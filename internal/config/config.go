// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package config loads, validates and reloads the TOML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the complete on-disk configuration. Field names mirror
// configs/smtprelayd.example.toml one to one; decoding is strict, so an
// unknown or misspelled key is a startup error rather than a silent default.
type Config struct {
	Service   Service    `toml:"service"`
	Log       Log        `toml:"log"`
	Listeners []Listener `toml:"listener"`
	TLS       TLS        `toml:"tls"`
	Clients   []Client   `toml:"client"`
	Routes    []Route    `toml:"route"`
	Queue     Queue      `toml:"queue"`
	Bounce    Bounce     `toml:"bounce"`
	Web       Web        `toml:"web"`
	Metrics   Metrics    `toml:"metrics"`
	History   History    `toml:"history"`
	Limits    Limits     `toml:"limits"`

	// Path is the file this configuration was loaded from.
	Path string `toml:"-"`
}

type Service struct {
	DataDir  string `toml:"data_dir"`
	LogLevel string `toml:"log_level"`
	Hostname string `toml:"hostname"`
}

type Log struct {
	File       string `toml:"file"`
	MaxSizeMB  int    `toml:"max_size_mb"`
	MaxBackups int    `toml:"max_backups"`
	MaxAgeDays int    `toml:"max_age_days"`
}

type Listener struct {
	Name       string `toml:"name"`
	Address    string `toml:"address"`
	TLS        string `toml:"tls"`
	MinTLS     string `toml:"min_tls"`
	RequireTLS bool   `toml:"require_tls"`
}

type TLS struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type Client struct {
	Name            string   `toml:"name"`
	CIDR            []string `toml:"cidr"`
	Route           string   `toml:"route"`
	MaxMessageMB    int      `toml:"max_message_mb"`
	MaxRecipients   int      `toml:"max_recipients"`
	RateLimitPerMin int      `toml:"rate_limit_per_min"`
	MaxConnections  int      `toml:"max_connections"`
	Rewrite         Rewrite  `toml:"rewrite"`
	Bounce          Bounce   `toml:"bounce"`
}

type Rewrite struct {
	Mode           string   `toml:"mode"`
	AllowedSenders []string `toml:"allowed_senders"`
	EnvelopeFrom   string   `toml:"envelope_from"`
	HeaderFrom     string   `toml:"header_from"`
	ReplyTo        string   `toml:"reply_to"`
}

type Route struct {
	Name            string      `toml:"name"`
	Default         bool        `toml:"default"`
	Host            string      `toml:"host"`
	Port            int         `toml:"port"`
	TLS             string      `toml:"tls"`
	MinTLS          string      `toml:"min_tls"`
	Auth            string      `toml:"auth"`
	Domains         []string    `toml:"domains"`
	Sources         []string    `toml:"sources"`
	MaxConcurrent   int         `toml:"max_concurrent"`
	RateLimitPerMin int         `toml:"rate_limit_per_min"`
	CAPin           string      `toml:"ca_pin"`
	OAuth2          OAuth2      `toml:"oauth2"`
	Credentials     Credentials `toml:"credentials"`
}

type OAuth2 struct {
	TenantID      string `toml:"tenant_id"`
	ClientID      string `toml:"client_id"`
	ClientSecret  Secret `toml:"client_secret"`
	SecretExpires string `toml:"secret_expires"`
	Scope         string `toml:"scope"`
	Mailbox       string `toml:"mailbox"`
}

// SecretExpiry returns the configured client secret expiry date. The format
// has already been validated, so a parse failure here means the field was
// never set.
func (o OAuth2) SecretExpiry() (time.Time, bool) {
	t, err := time.Parse(secretExpiresLayout, o.SecretExpires)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

type Credentials struct {
	Username string `toml:"username"`
	Password Secret `toml:"password"`
}

type Queue struct {
	RetryScheduleMin []int `toml:"retry_schedule_min"`
	MaxLifetimeHours int   `toml:"max_lifetime_hours"`
}

type Bounce struct {
	Sender        string   `toml:"sender"`
	Notify        []string `toml:"notify"`
	NotifyRoute   string   `toml:"notify_route"`
	DigestMinutes int      `toml:"digest_minutes"`
	MaxPerHour    int      `toml:"max_per_hour"`
}

type Web struct {
	Address string  `toml:"address"`
	Enabled bool    `toml:"enabled"`
	Theme   Theme   `toml:"theme"`
	Tokens  []Token `toml:"token"`
}

// Theme carries the dashboard's appearance overrides. Every colour is a
// literal hex value validated at load time and again where the stylesheet is
// generated: the values end up inside a CSS custom property declaration, so an
// unvalidated string would be a stylesheet injection. An empty field keeps the
// built-in value; an override applies to the light and the dark scheme alike,
// which is why Mode exists to pin the scheme an operator is theming for.
type Theme struct {
	Mode       string `toml:"mode"`
	Accent     string `toml:"accent"`
	AccentText string `toml:"accent_text"`
	Background string `toml:"background"`
	Surface    string `toml:"surface"`
	Border     string `toml:"border"`
	Text       string `toml:"text"`
	Muted      string `toml:"muted"`
	OK         string `toml:"ok"`
	Warn       string `toml:"warn"`
	Danger     string `toml:"danger"`
}

// Colors returns the configured overrides keyed by the CSS custom property
// they set, skipping the empty ones. The key set is fixed here, so no
// caller-supplied string can ever become a property name.
func (t Theme) Colors() map[string]string {
	out := make(map[string]string, 10)
	for name, v := range map[string]string{
		"--accent":      t.Accent,
		"--accent-text": t.AccentText,
		"--bg":          t.Background,
		"--surface":     t.Surface,
		"--border":      t.Border,
		"--text":        t.Text,
		"--muted":       t.Muted,
		"--ok":          t.OK,
		"--warn":        t.Warn,
		"--danger":      t.Danger,
	} {
		if v != "" {
			out[name] = v
		}
	}
	return out
}

// IsHexColor reports whether s is a literal #rgb or #rrggbb colour. It is
// deliberately the narrowest syntax that covers the use case: named colours,
// rgb(), var() and anything carrying a semicolon, a brace or a comment marker
// are all rejected, so a theme value cannot close the declaration it sits in
// and start a rule of its own.
func IsHexColor(s string) bool {
	if len(s) != 4 && len(s) != 7 {
		return false
	}
	if s[0] != '#' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

type Token struct {
	Name   string `toml:"name"`
	Scope  string `toml:"scope"`
	SHA256 string `toml:"sha256"`
}

type Metrics struct {
	Address string `toml:"address"`
	Path    string `toml:"path"`
	Enabled bool   `toml:"enabled"`
}

type History struct {
	RetentionDays  int  `toml:"retention_days"`
	RetainSubjects bool `toml:"retain_subjects"`
}

type Limits struct {
	MaxMessageMB     int `toml:"max_message_mb"`
	MaxHops          int `toml:"max_hops"`
	MaxHeaders       int `toml:"max_headers"`
	MaxHeaderBytes   int `toml:"max_header_bytes"`
	MaxConnections   int `toml:"max_connections"`
	ReadTimeoutSec   int `toml:"read_timeout_sec"`
	WriteTimeoutSec  int `toml:"write_timeout_sec"`
	DataTimeoutSec   int `toml:"data_timeout_sec"`
	SpoolMaxGB       int `toml:"spool_max_gb"`
	SpoolWarnPercent int `toml:"spool_warn_percent"`
}

// Secret holds a reference to a credential, never the credential itself as it
// appears in the file. Its String method is deliberately lossy so that a
// secret cannot leak through a log line, an error string or %v formatting.
type Secret struct {
	ref   string
	value string
}

var envRef = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)

func (s *Secret) UnmarshalText(b []byte) error {
	s.ref = string(b)
	return nil
}

func (s Secret) String() string   { return "[redacted]" }
func (s Secret) GoString() string { return "[redacted]" }

// Value returns the resolved secret. It is only populated after resolve.
func (s Secret) Value() string { return s.value }

// Empty reports whether no secret was configured at all.
func (s Secret) Empty() bool { return s.ref == "" }

// resolve dereferences the configured reference. A literal value is rejected:
// a secret must never be readable from the configuration file itself.
func (s *Secret) resolve(field string) error {
	switch {
	case s.ref == "":
		return nil
	case envRef.MatchString(s.ref):
		name := strings.TrimSuffix(strings.TrimPrefix(s.ref, "${"), "}")
		v := os.Getenv(name)
		if v == "" {
			return fmt.Errorf("%s: environment variable %s is unset or empty", field, name)
		}
		s.value = v
		return nil
	case strings.HasPrefix(s.ref, "file:"):
		path := strings.TrimPrefix(s.ref, "file:")
		if err := checkSecretFile(path); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		s.value = strings.TrimRight(string(b), "\r\n")
		if s.value == "" {
			return fmt.Errorf("%s: secret file %s is empty", field, path)
		}
		return nil
	default:
		return fmt.Errorf("%s: secrets must be ${ENV_VAR} or file:<path>, never a literal value", field)
	}
}

// Defaults returns a configuration with every optional value populated, so a
// missing section can never silently mean "no limit".
func Defaults() *Config {
	return &Config{
		Service: Service{LogLevel: "info"},
		Log:     Log{File: "smtprelayd.log", MaxSizeMB: 50, MaxBackups: 10, MaxAgeDays: 90},
		Queue:   Queue{RetryScheduleMin: []int{1, 5, 15, 30, 60, 120}, MaxLifetimeHours: 96},
		Bounce:  Bounce{DigestMinutes: 15, MaxPerHour: 12},
		Web:     Web{Address: "127.0.0.1:8025", Theme: Theme{Mode: "auto"}},
		Metrics: Metrics{Address: "127.0.0.1:9025", Path: "/metrics"},
		History: History{RetentionDays: 90, RetainSubjects: true},
		Limits: Limits{
			MaxMessageMB: 50,
			MaxHops:      25, MaxHeaders: 200, MaxHeaderBytes: 262144,
			MaxConnections: 200, ReadTimeoutSec: 60, WriteTimeoutSec: 60,
			DataTimeoutSec: 300, SpoolMaxGB: 10, SpoolWarnPercent: 80,
		},
	}
}

// Load reads, resolves and validates a configuration file. It fails closed:
// any error returned here must abort startup.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config: no configuration file given")
	}
	if err := CheckConfigFile(path); err != nil {
		return nil, err
	}

	c := Defaults()
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, 0, len(un))
		for _, k := range un {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("config: unknown key(s): %s", strings.Join(keys, ", "))
	}
	c.Path = path

	for i := range c.Routes {
		r := &c.Routes[i]
		if err := r.OAuth2.ClientSecret.resolve("route " + r.Name + " oauth2.client_secret"); err != nil {
			return nil, err
		}
		if err := r.Credentials.Password.resolve("route " + r.Name + " credentials.password"); err != nil {
			return nil, err
		}
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
