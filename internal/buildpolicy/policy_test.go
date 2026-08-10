// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package buildpolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// bannedImports removes categories of vulnerability rather than defending
// against them, which is why each is a build failure and not a review note.
// The reason travels with the entry so that a future reader who hits this test
// is told why, not merely that.
var bannedImports = map[string]string{
	"unsafe":  "memory safety is the reason this service is written in Go",
	"os/exec": "command injection is made structurally impossible; the Windows service backend is the reason kardianos/service is imported only from a _windows.go file",
	"plugin":  "loadable code defeats the single-binary and no-dynamic-behaviour rules",
	"C":       "cgo would end trivial Windows cross-compilation and pull in a toolchain this project does not want",
}

// allowedBannedImports lists files that are permitted to import banned packages
// for platform-specific reasons. Each is a relative path from the repo root.
var allowedBannedImports = map[string]map[string]bool{
	"internal/config/trust_windows.go": {"unsafe": true}, // Windows ACL API requires unsafe.Pointer for LocalFree
}

// bannedConversions are the html/template escape hatches. Every one of them
// tells the template engine that attacker-influenced data is already safe.
var bannedConversions = map[string]bool{"HTML": true, "JS": true, "URL": true, "CSS": true, "HTMLAttr": true, "Srcset": true}

// skipDirs are build outputs and version control, never source.
var skipDirs = map[string]bool{".git": true, "bin": true, "dist": true, "obj": true, "vendor": true}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("go.mod not found at %s: %v", root, err)
	}
	return root
}

func goFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no Go files found; the walk root is wrong")
	}
	return out
}

func TestBannedImports(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	for _, path := range goFiles(t, root) {
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("%s: %v", rel(root, path), err)
			continue
		}
		relPath := rel(root, path)
		allowed := allowedBannedImports[relPath]
		for _, spec := range f.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Errorf("%s: unparsable import %s", relPath, spec.Path.Value)
				continue
			}
			if why, banned := bannedImports[p]; banned && !allowed[p] {
				t.Errorf("%s imports %q, which is banned: %s", relPath, p, why)
			}
		}
	}
}

// TestNoTemplateEscapeHatches rejects the html/template conversions that mark
// a value as pre-sanitised. The check is syntactic and keyed on the package
// name "template", which is how this module would import it; it is a floor,
// not a proof.
func TestNoTemplateEscapeHatches(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	for _, path := range goFiles(t, root) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Errorf("%s: %v", rel(root, path), err)
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "template" || !bannedConversions[sel.Sel.Name] {
				return true
			}
			t.Errorf("%s:%d: template.%s conversion is banned; it declares attacker-influenced data pre-sanitised",
				rel(root, path), fset.Position(call.Pos()).Line, sel.Sel.Name)
			return true
		})
	}
}

// TestNoCgo is separate from the import check because cgo announces itself
// with a directive comment as well as with the pseudo-import.
func TestNoCgo(t *testing.T) {
	root := repoRoot(t)
	for _, path := range goFiles(t, root) {
		// This file has to name the directive in order to look for it.
		if filepath.Base(path) == "policy_test.go" {
			continue
		}
		b, err := os.ReadFile(path) //nolint:gosec // paths come from the walk above
		if err != nil {
			t.Errorf("%s: %v", rel(root, path), err)
			continue
		}
		if strings.Contains(string(b), "#cgo ") {
			t.Errorf("%s carries a #cgo directive", rel(root, path))
		}
	}
}

func rel(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return r
	}
	return path
}
