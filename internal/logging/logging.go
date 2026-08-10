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

	"github.com/natefinch/lumberjack"
)

// Redacted replaces the value of any attribute whose key looks like a
// credential. Redaction lives here rather than at each call site so that a
// new call site cannot forget it.
const Redacted = "[redacted]"

var secretKeys = []string{"secret", "password", "token", "authorization", "credential", "bearer", "client_secret"}

// Options configures the logger.
type Options struct {
	Level      slog.Level
	File       string // absolute path, empty disables file output
	Console    bool   // also write to stderr
	MaxSizeMB  int    // max log file size in MB before rotation (0 disables)
	MaxBackups int    // number of old log files to keep
	MaxAgeDays int    // max age of log files in days
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
		ReplaceAttr: redact,
	})
	return slog.New(h), closer, nil
}

func redact(_ []string, a slog.Attr) slog.Attr {
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
