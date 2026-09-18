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
	"internal/config/dpapi_windows.go": {"unsafe": true}, // DPAPI (CryptProtectData/CryptUnprotectData) has no non-unsafe wrapper in golang.org/x/sys/windows
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

// rel returns the repo-relative path in forward-slash form. ToSlash is not
// cosmetic: allowedBannedImports is keyed by forward-slash paths, and on
// Windows filepath.Rel returns backslashes, so without it every exception
// misses and the test reports a banned import in a file that is explicitly
// permitted one -- which reads exactly like a real violation.
func rel(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(r)
	}
	return filepath.ToSlash(path)
}

// TestDocCommentsNameTheirSymbol enforces the Go convention that a doc
// comment begins with the name of what it documents.
//
// It is here rather than delegated to a third-party linter because the
// obvious candidate, revive's "exported" rule, cannot separate the two halves
// it checks: alongside this it demands a doc comment on every exported
// symbol, which for the twenty config structs that mirror TOML sections would
// mean twenty "Service is the [service] section" lines -- exactly the what-
// not-why commenting CLAUDE.md forbids. This half is the one that catches a
// real defect, and it caught three when it was first run: two comments that
// had been orphaned onto a neighbouring symbol by an edit, and one naming a
// method rather than the type it sat on.
//
// Test files are excluded; see the loop below for why.
//
// Why it matters more here than in most projects: the comments in this tree
// carry the rationale, and three documentation claims that had drifted away
// from the code were each found by hand after they had already misled
// somebody. A comment naming a symbol that moved is how that starts.
func TestDocCommentsNameTheirSymbol(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	for _, path := range goFiles(t, root) {
		// Test files are exempt on purpose. A test's doc comment here states
		// the behaviour under test ("A page the operator visits can rebind a
		// name...") rather than repeating the function name, which says far
		// more than "TestFoo tests Foo" ever would. The convention this
		// enforces is for the API surface, not for prose about a scenario.
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		rel, _ := filepath.Rel(root, path)

		check := func(doc *ast.CommentGroup, name string, pos token.Pos) {
			if doc == nil || name == "" || name == "_" {
				return
			}
			first := strings.TrimSpace(strings.TrimPrefix(doc.List[0].Text, "//"))
			// Build tags and directives are not prose about the symbol.
			if strings.HasPrefix(first, "go:") || strings.HasPrefix(first, "+build") {
				return
			}
			if first == "" || strings.HasPrefix(first, name) {
				return
			}
			t.Errorf("%s:%d: doc comment on %s starts with %q; a doc comment must begin with the name of what it documents, or it is describing something else",
				rel, fset.Position(pos).Line, name, firstWords(first))
		}

		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				check(d.Doc, d.Name.Name, d.Pos())
			case *ast.GenDecl:
				// A parenthesised block documents the group, not one symbol,
				// so only a lone declaration is checked against its name.
				if d.Lparen.IsValid() || len(d.Specs) != 1 {
					continue
				}
				switch spec := d.Specs[0].(type) {
				case *ast.TypeSpec:
					check(d.Doc, spec.Name.Name, d.Pos())
				case *ast.ValueSpec:
					if len(spec.Names) == 1 {
						check(d.Doc, spec.Names[0].Name, d.Pos())
					}
				}
			}
		}
	}
}

// firstWords shortens a comment for the failure message, so the report names
// what was found without reprinting a paragraph.
func firstWords(s string) string {
	if fields := strings.Fields(s); len(fields) > 4 {
		return strings.Join(fields[:4], " ") + " ..."
	}
	return s
}
