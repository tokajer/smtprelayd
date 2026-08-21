// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package logging configures structured JSON logging with central redaction.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/tokajer/smtprelayd/internal/fsmode"
)

// Redacted replaces the value of any attribute whose key looks like a
// credential. Redaction lives here rather than at each call site so that a
// new call site cannot forget it.
const Redacted = "[redacted]"

var secretKeys = []string{"secret", "password", "token", "authorization", "credential", "bearer", "client_secret"}

// Options configures the logger.
type Options struct {
	Level      slog.Level
	File       string         // absolute path, empty disables file output
	Console    bool           // also write to stderr
	MaxSizeMB  int            // max log file size in MB before rotation (0 disables)
	MaxBackups int            // number of old log files to keep
	MaxAgeDays int            // max age of log files in days
	Location   *time.Location // nil keeps each record's own (process-local) time
}

// New builds the process logger. The returned closer must be called on
// shutdown to flush and release the log file.
func New(o Options) (*slog.Logger, io.Closer, error) {
	writers := []io.Writer{}
	var closer io.Closer = nopCloser{}

	if o.Console || o.File == "" {
		writers = append(writers, os.Stderr)
	}
	if o.File != "" {
		if err := os.MkdirAll(filepath.Dir(o.File), 0o700); err != nil {
			return nil, nil, err
		}
		// lumberjack creates a new log file 0644 and copies the mode of the
		// existing file when it rotates, so creating it here with 0600 is
		// what makes every generation 0600 — including one left behind at
		// 0644 by an earlier version, which is why an existing file is
		// restricted too rather than only a new one.
		if err := createRestricted(o.File); err != nil {
			return nil, nil, err
		}

		var ljack io.WriteCloser
		if o.MaxSizeMB > 0 {
			ljack = &lumberjack.Logger{
				Filename:   o.File,
				MaxSize:    o.MaxSizeMB,
				MaxBackups: o.MaxBackups,
				MaxAge:     o.MaxAgeDays,
				Compress:   true,
			}
			closer = ljack
		} else {
			f, err := os.OpenFile(o.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, nil, err
			}
			ljack = f
			closer = f
		}
		writers = append(writers, ljack)
	}

	h := slog.NewJSONHandler(io.MultiWriter(writers...), &slog.HandlerOptions{
		Level:       o.Level,
		ReplaceAttr: newReplaceAttr(o.Location),
	})
	return slog.New(h), closer, nil
}

// newReplaceAttr applies the configured display timezone to the record's
// timestamp, then redacts secrets. Both go through one ReplaceAttr because
// slog only accepts a single hook.
func newReplaceAttr(loc *time.Location) func([]string, slog.Attr) slog.Attr {
	return func(_ []string, a slog.Attr) slog.Attr {
		if loc != nil && a.Key == slog.TimeKey {
			return slog.Time(slog.TimeKey, a.Value.Time().In(loc))
		}
		return redact(a)
	}
}

func redact(a slog.Attr) slog.Attr {
	k := strings.ToLower(a.Key)
	for _, s := range secretKeys {
		if strings.Contains(k, s) {
			return slog.String(a.Key, Redacted)
		}
	}
	return a
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// createRestricted makes sure the log file exists and is 0600 before anything
// else opens it. The log carries every queue ID, sender and recipient the
// relay handled, so it is not a file other local accounts may read.
func createRestricted(path string) error {
	//#nosec G304 -- path comes from config.LogPath, which proves lexically that log.file cannot name a location outside service.data_dir
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fsmode.RestrictFile(path)
}

// FromContext returns the logger stored in ctx, or the default logger.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// WithLogger stores a logger in ctx, used to carry the queue ID through the
// delivery path so that every line of one message shares a correlation key.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

type loggerKey struct{}
