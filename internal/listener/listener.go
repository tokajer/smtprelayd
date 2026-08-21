// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package listener implements the inbound SMTP servers and client matching.
package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/rewrite"
	"github.com/tokajer/smtprelayd/internal/router"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// Server is one configured inbound listener.
type Server struct {
	cfg   *config.Config
	lc    config.Listener
	log   *slog.Logger
	spool *spool.Spool
	store *store.Store

	tlsConf *tls.Config
	match   *Matcher
	router  *router.Router
	rules   map[string]*rewrite.Rules
	rate    *rateLimiter
	conns   *connCounter
	sem     chan struct{}

	ln net.Listener
	wg sync.WaitGroup

	// closeMu serialises wg.Add in accept against wg.Wait in close: closing
	// the socket alone does not stop a connection Accept had already
	// returned from also reaching Add, and sync.WaitGroup requires every Add
	// with a positive delta on a counter that could be zero to happen before
	// the matching Wait. Setting closed under this lock before Wait, and
	// checking it under the same lock before every Add, gives that ordering.
	closeMu sync.Mutex
	closed  bool
}

// Set owns every listener of a running instance.
type Set struct {
	servers []*Server
}

// New builds all listeners from the configuration. The TLS material and the
// client matcher are shared, so a certificate problem fails before any socket
// is bound.
func New(cfg *config.Config, sp *spool.Spool, log *slog.Logger, st *store.Store) (*Set, error) {
	match, err := NewMatcher(cfg.Clients)
	if err != nil {
		return nil, err
	}
	rt, err := router.New(cfg.Routes)
	if err != nil {
		return nil, err
	}
	// Compiling every client's policy up front turns a rewrite mistake into a
	// startup failure instead of a message rejected at three in the morning.
	rules := make(map[string]*rewrite.Rules, len(cfg.Clients))
	for _, cl := range cfg.Clients {
		r, err := rewrite.Compile(cl.Rewrite)
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", cl.Name, err)
		}
		rules[cl.Name] = r
	}
	rate := newRateLimiter()
	conns := newConnCounter()
	sem := make(chan struct{}, cfg.Limits.MaxConnections)

	var cert *tls.Certificate
	if cfg.TLS.CertFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("listener: tls: %w", err)
		}
		cert = &c
	}

	set := &Set{}
	for _, lc := range cfg.Listeners {
		s := &Server{
			cfg: cfg, lc: lc, spool: sp, store: st,
			log:   log.With("listener", lc.Name),
			match: match, router: rt, rules: rules,
			rate: rate, conns: conns, sem: sem,
		}
		if lc.TLS != "none" {
			if cert == nil {
				return nil, fmt.Errorf("listener %s: tls %s requires a certificate", lc.Name, lc.TLS)
			}
			min, err := config.ParseTLSVersion(orDefault(lc.MinTLS, "1.2"))
			if err != nil {
				return nil, err
			}
			s.tlsConf = &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: min}
			if min < tls.VersionTLS12 {
				// A deliberate weakening for legacy devices. It is reported so
				// that it shows up in a review rather than only in the file.
				s.log.Warn("inbound TLS minimum below 1.2", "min_tls", lc.MinTLS)
			}
		}
		set.servers = append(set.servers, s)
	}
	return set, nil
}

// Bind opens every listener's socket. Split from Run so a caller learns
// about a bind failure (e.g. an address already in use) synchronously,
// before doing anything that could be mistaken for "started successfully" —
// on Windows in particular, see winProgram.Start in cmd/smtprelayd.
func (s *Set) Bind() error {
	for _, srv := range s.servers {
		if err := srv.listen(); err != nil {
			s.Close()
			return err
		}
	}
	return nil
}

// Run accepts connections on every already-bound listener and blocks until
// ctx is cancelled. Call Bind first.
func (s *Set) Run(ctx context.Context) {
	for _, srv := range s.servers {
		go srv.accept(ctx)
	}
	<-ctx.Done()
	s.Close()
}

// Close stops every server accepting, then waits for open sessions to
// finish. Every socket is closed before any Wait, same as before this was
// split across two loops for the race fix in stopAccepting's doc comment:
// otherwise one slow listener's sessions would delay the others from even
// being told to stop.
func (s *Set) Close() {
	for _, srv := range s.servers {
		srv.stopAccepting()
	}
	for _, srv := range s.servers {
		srv.wg.Wait()
	}
}

func (s *Server) stopAccepting() {
	s.closeMu.Lock()
	s.closed = true
	s.closeMu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

func (s *Server) listen() error {
	ln, err := net.Listen("tcp", s.lc.Address)
	if err != nil {
		return fmt.Errorf("listener %s: %w", s.lc.Name, err)
	}
	if s.lc.TLS == "implicit" {
		ln = tls.NewListener(ln, s.tlsConf)
	}
	s.ln = ln
	s.log.Info("listening", "address", s.lc.Address, "tls", s.lc.TLS)
	return nil
}

func (s *Server) accept(ctx context.Context) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("accept failed", "error", err)
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			// Global connection cap reached. Answering 421 rather than
			// dropping the socket keeps well-behaved clients retrying.
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte("421 4.3.2 too many connections\r\n"))
			_ = conn.Close()
			continue
		}
		s.closeMu.Lock()
		if s.closed {
			// stopAccepting already closed the listener; this connection was
			// accepted in the narrow window before that took effect. Refusing
			// it here, rather than calling wg.Add, is what keeps Add from
			// ever racing the Wait in Set.Close — see closeMu's doc comment.
			s.closeMu.Unlock()
			<-s.sem
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		s.closeMu.Unlock()
		go func() {
			defer func() {
				<-s.sem
				s.wg.Done()
				// One malformed session must not take the process down.
				if r := recover(); r != nil {
					s.log.Error("session panic", "panic", fmt.Sprint(r),
						"remote", conn.RemoteAddr().String())
				}
			}()
			s.handle(ctx, conn)
		}()
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
