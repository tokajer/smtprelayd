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

	"github.com/tokajer/smtprelayd/internal/certgen"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/fsmode"
)

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
func genCert(configPath string, force bool, out io.Writer) error {
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
	certPEM, keyPEM, err := certgen.Generate(certgen.Options{Hosts: hosts})
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
	// run over a key that was already 0644 would leave it that way.
	if err := fsmode.RestrictFile(keyFile); err != nil {
		return fmt.Errorf("gen-cert: restricting the key: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("gen-cert: writing the certificate: %w", err)
	}

	fmt.Fprintf(out, "wrote a self-signed certificate to %s\n", certFile)
	fmt.Fprintf(out, "wrote its private key to %s\n", keyFile)
	fmt.Fprintf(out, "subject alternative names: %v\n", hosts)
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
	hosts := []string{}
	if cfg.Service.Hostname != "" {
		hosts = append(hosts, cfg.Service.Hostname)
	}
	for _, l := range cfg.Listeners {
		host, _, err := net.SplitHostPort(l.Address)
		if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
			continue
		}
		hosts = append(hosts, host)
	}
	hosts = append(hosts, "localhost", "127.0.0.1", "::1")
	return hosts
}
