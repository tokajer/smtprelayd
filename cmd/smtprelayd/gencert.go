// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/certgen"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/fsmode"
)

// maxValidityDays bounds -days. Twenty years is already far beyond any
// sensible rotation period; the ceiling exists so the duration arithmetic
// cannot overflow.
const maxValidityDays = 7300

// genCert writes a self-signed certificate and key to the paths [tls] already
// names, for an internal listener that has no CA behind it.
//
// It deliberately tolerates a configuration that does not validate. Validate
// refuses to load when a listener uses TLS and the certificate it names is
// absent -- which is exactly the state this command exists to resolve, so
// requiring a valid configuration first would make it unusable for its own
// purpose. Nothing here binds a port, opens the spool or reads a secret: it
// writes two files and exits, so running it against a configuration with
// other faults costs nothing beyond those faults still being there.
func genCert(configPath string, force bool, days int, out io.Writer) error {
	// Bounded rather than merely positive: days*24h is computed in
	// time.Duration nanoseconds, which overflows int64 somewhere past 292
	// years, and a certificate valid for longer than the machine will exist
	// is not a thing to let through by accident.
	if days < 0 || days > maxValidityDays {
		return fmt.Errorf("gen-cert: -days must be between 1 and %d (0 uses the default)", maxValidityDays)
	}

	cfg, loadErr := config.Load(configPath)
	if cfg == nil {
		// The file could not be read or decoded at all, so there is no
		// [tls] block to act on.
		return loadErr
	}
	if loadErr != nil {
		fmt.Fprintf(out, "warning: the configuration does not validate yet:\n%v\n\n", loadErr)
	}

	certFile, keyFile := cfg.TLS.CertFile, cfg.TLS.KeyFile
	if certFile == "" || keyFile == "" {
		return errors.New("gen-cert: set [tls] cert_file and key_file first; " +
			"gen-cert writes to the paths they name rather than inventing its own")
	}
	if !force {
		for _, p := range []string{certFile, keyFile} {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("gen-cert: %s already exists, refusing to overwrite it; "+
					"pass -force if you are sure, and note that a key issued by a real CA "+
					"would be destroyed by that", p)
			}
		}
	}

	hosts := certHosts(cfg)
	certPEM, keyPEM, err := certgen.Generate(certgen.Options{
		Hosts: hosts,
		// Zero leaves certgen on its own default.
		Validity: time.Duration(days) * 24 * time.Hour,
	})
	if err != nil {
		return err
	}

	// 0700 rather than 0755: the directory holds a private key, and on a
	// fresh install it usually does not exist yet.
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return fmt.Errorf("gen-cert: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return fmt.Errorf("gen-cert: %w", err)
	}

	// The key first: a certificate on disk without its key is a
	// configuration that fails to load, which is louder than the reverse and
	// so the safer half to leave behind if the second write fails.
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("gen-cert: writing the key: %w", err)
	}
	// WriteFile applies its mode only when it creates the file, so a -force
	// run over a key that was already 0644 would leave it that way. This runs
	// before the group is widened below, so a failure there leaves the key
	// too restrictive rather than too open.
	if err := fsmode.RestrictFile(keyFile); err != nil {
		return fmt.Errorf("gen-cert: restricting the key: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("gen-cert: writing the certificate: %w", err)
	}

	// On a server this command runs as root while the service runs as its own
	// account, so a 0600 root:root key inside a 0700 root:root directory is
	// one the service cannot read -- and it reports that as a service which
	// will not start, saying nothing about permissions. The configuration
	// file is the reference because the package already gave it the service's
	// group.
	group, shareErr := shareWithService(configPath, filepath.Dir(keyFile), keyFile)

	fmt.Fprintf(out, "wrote a self-signed certificate to %s\n", certFile)
	fmt.Fprintf(out, "wrote its private key to %s\n", keyFile)
	// Naming the group is the point: it is whatever the configuration file
	// carries, and on a hand-made install that can be a group every local
	// account is in. Saying nothing made a key readable machine-wide look
	// exactly like a key readable by the service.
	if group != "" {
		fmt.Fprintf(out, "the key is readable by group %s, which owns %s\n", group, configPath)
	}
	fmt.Fprintf(out, "subject alternative names: %s\n", strings.Join(hosts, ", "))
	if shareErr != nil {
		fmt.Fprintf(out, "\nWARNING: could not give the key the configuration's group (%v).\n"+
			"The service account may be unable to read it, which shows up as a service\n"+
			"that will not start. Fix it with, adjusting the group to the one running it:\n"+
			"  chown -R root:smtprelayd %s\n"+
			"  chmod 0750 %s && chmod 0640 %s\n",
			shareErr, filepath.Dir(keyFile), filepath.Dir(keyFile), keyFile)
	}
	fmt.Fprintf(out, "\nThis certificate is not signed by any CA. Devices that verify it must be\n"+
		"given this certificate explicitly, or be configured not to verify.\n"+
		"Outbound delivery to the smarthost is unaffected and still verifies against\n"+
		"the system roots.\n")
	return nil
}

// certHosts collects the names a device might address this relay by: the
// hostname the banner and Received header already use, whatever each
// listener binds, and loopback.
//
// A wildcard bind contributes nothing -- it means "every interface", which is
// not a name a certificate can carry -- so those addresses are skipped rather
// than turned into a SAN for 0.0.0.0 that no client will ever ask for.
func certHosts(cfg *config.Config) []string {
	var hosts []string
	add := func(s string) {
		if s == "" {
			return
		}
		for _, existing := range hosts {
			if existing == s {
				return
			}
		}
		hosts = append(hosts, s)
	}
	addAddress := func(addr string) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
			return
		}
		add(host)
	}

	add(cfg.Service.Hostname)
	for _, l := range cfg.Listeners {
		addAddress(l.Address)
	}
	// The metrics endpoint serves this same certificate when it binds beyond
	// loopback (internal/metrics.Serve), and a monitoring system addresses it
	// by that name -- so leaving it out produced a certificate that was valid
	// for the mail listeners and failed hostname verification for Checkmk.
	// The dashboard needs no entry: config.Validate pins it to loopback,
	// which the three constants below already cover.
	if cfg.Metrics.Enabled {
		addAddress(cfg.Metrics.Address)
	}
	add("localhost")
	add("127.0.0.1")
	add("::1")
	return hosts
}

// shareWithService widens each path to the configuration file's group and
// reports which group that was, for the caller to print. The first failure is
// returned; the remaining paths are still attempted, so a directory that
// could not be changed does not also leave the key untouched.
func shareWithService(configPath string, paths ...string) (string, error) {
	var firstErr error
	var group string
	for _, p := range paths {
		name, err := fsmode.ShareWithGroupOf(p, configPath)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		group = name
	}
	return group, firstErr
}
