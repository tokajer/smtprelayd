// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package config

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dataBlob mirrors Win32's DATA_BLOB (a.k.a. CRYPTOAPI_BLOB), the parameter
// and return type both CryptProtectData and CryptUnprotectData use.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

var modcrypt32 = windows.NewLazySystemDLL("crypt32.dll")
var modkernel32DPAPI = windows.NewLazySystemDLL("kernel32.dll")

var procCryptProtectData = modcrypt32.NewProc("CryptProtectData")
var procCryptUnprotectData = modcrypt32.NewProc("CryptUnprotectData")
var procLocalFreeDPAPI = modkernel32DPAPI.NewProc("LocalFree")

// CRYPTPROTECT_UI_FORBIDDEN keeps a service context from ever popping a
// credential prompt, which would otherwise just hang forever with no console
// to show it on. CRYPTPROTECT_LOCAL_MACHINE ties the key to this machine
// rather than to the calling user's profile: the virtual service account
// NT SERVICE\smtprelayd has no ordinary user profile to hold a per-user DPAPI
// master key, and machine scope is also what lets an elevated operator
// (a different account, running "protect-secret" by hand) produce a file the
// service account can later decrypt.
const (
	cryptprotectUIForbidden  = 0x1
	cryptprotectLocalMachine = 0x4
)

func blobBytes(b dataBlob) []byte {
	if b.cbData == 0 {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func newBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

// ProtectMachineSecret encrypts plaintext with this machine's DPAPI key, so
// the result is decryptable only by a process running on this machine. It is
// called once, by an elevated operator via "smtprelayd protect-secret", never
// by the running service.
func ProtectMachineSecret(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("dpapi: refusing to protect an empty secret")
	}
	in := newBlob(plaintext)
	var out dataBlob
	r, _, callErr := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		uintptr(cryptprotectUIForbidden|cryptprotectLocalMachine),
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(in)
	if r == 0 {
		return nil, fmt.Errorf("dpapi: CryptProtectData: %w", callErr)
	}
	defer procLocalFreeDPAPI.Call(uintptr(unsafe.Pointer(out.pbData))) //nolint:errcheck // best-effort free of a Win32-owned buffer, nothing meaningful to do with a failure
	return blobBytes(out), nil
}

// unprotectMachineSecret reverses ProtectMachineSecret. It fails on a blob
// protected on a different machine, by design: that is what makes the file
// useless if it is copied off this host.
func unprotectMachineSecret(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("dpapi: empty ciphertext")
	}
	in := newBlob(ciphertext)
	var out dataBlob
	r, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		uintptr(cryptprotectUIForbidden|cryptprotectLocalMachine),
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(in)
	if r == 0 {
		return nil, fmt.Errorf("dpapi: CryptUnprotectData: %w", callErr)
	}
	defer procLocalFreeDPAPI.Call(uintptr(unsafe.Pointer(out.pbData))) //nolint:errcheck // best-effort free of a Win32-owned buffer, nothing meaningful to do with a failure
	return blobBytes(out), nil
}

// resolveDPAPISecret reads and decrypts a DPAPI-protected secret file. It
// runs the same symlink/reparse-point and containing-directory checks
// checkSecretFile already runs for file:, since a secret file is a secret
// file whether or not it happens to be encrypted at rest.
func resolveDPAPISecret(path string) (string, error) {
	if err := checkSecretFile(path); err != nil {
		return "", err
	}
	//#nosec G304 -- an operator-written dpapi: reference, and checkSecretFile above has already verified its containing directory and that it is not a symlink or reparse point
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	plaintext, err := unprotectMachineSecret(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return string(plaintext), nil
}
