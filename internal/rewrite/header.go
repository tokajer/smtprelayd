// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package rewrite

import (
	"errors"
	"strings"
)

// errTrailingData means the caller passed something other than a header
// block: text followed the terminating empty line. It cannot happen with the
// listener's scanner and exists so that a future caller fails loudly.
var errTrailingData = errors.New("rewrite: data after the end of the header block")

// field is one header, kept as its verbatim lines so that an untouched header
// is re-emitted byte for byte, folding included.
type field struct {
	name  string // lower case, empty for a line that is not a header at all
	lines []string
}

// block is a parsed header block. Fields keep their original order; a field
// that is replaced keeps its position, a new field is appended.
type block struct {
	fields []field
	blank  bool // the block was terminated by an empty line
}

func parseBlock(s string) (*block, error) {
	b := &block{}
	rest := s
	for rest != "" {
		var line string
		if i := strings.Index(rest, "\r\n"); i < 0 {
			line, rest = rest, ""
		} else {
			line, rest = rest[:i], rest[i+2:]
		}
		if line == "" {
			b.blank = true
			if rest != "" {
				return nil, errTrailingData
			}
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(b.fields) == 0 {
				// A continuation with nothing to continue. Keep it opaque
				// rather than reject: it is not a value this package reuses.
				b.fields = append(b.fields, field{lines: []string{line}})
				continue
			}
			f := &b.fields[len(b.fields)-1]
			f.lines = append(f.lines, line)
			continue
		}
		c := strings.IndexByte(line, ':')
		if c <= 0 {
			b.fields = append(b.fields, field{lines: []string{line}})
			continue
		}
		b.fields = append(b.fields, field{
			name:  strings.ToLower(strings.TrimSpace(line[:c])),
			lines: []string{line},
		})
	}
	return b, nil
}

// HeaderValue returns the unfolded value of the first occurrence of name in a
// raw header block. Unlike Apply, this is best-effort metadata extraction for
// the history store, not the rewriting path: a block that fails to parse or
// a header that is absent both yield "" rather than an error.
func HeaderValue(headers, name string) string {
	blk, err := parseBlock(headers)
	if err != nil {
		return ""
	}
	return blk.value(strings.ToLower(name))
}

func (b *block) count(name string) int {
	n := 0
	for _, f := range b.fields {
		if f.name == name {
			n++
		}
	}
	return n
}

func (b *block) has(name string) bool { return b.count(name) > 0 }

// value returns the unfolded value of the first occurrence of name.
func (b *block) value(name string) string {
	for _, f := range b.fields {
		if f.name == name {
			return unfold(f.lines)
		}
	}
	return ""
}

func unfold(lines []string) string {
	c := strings.IndexByte(lines[0], ':')
	if c < 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(strings.TrimSpace(lines[0][c+1:]))
	for _, l := range lines[1:] {
		sb.WriteByte(' ')
		sb.WriteString(strings.TrimSpace(l))
	}
	return strings.TrimSpace(sb.String())
}

// set replaces the first occurrence of name with a single unfolded line and
// removes any further occurrences, so a duplicate header cannot survive a
// rewrite and be interpreted instead of the value written here.
func (b *block) set(name, value string) {
	lower := strings.ToLower(name)
	line := name + ": " + value
	replaced := false
	out := b.fields[:0]
	for _, f := range b.fields {
		if f.name == lower {
			if replaced {
				continue
			}
			replaced = true
			out = append(out, field{name: lower, lines: []string{line}})
			continue
		}
		out = append(out, f)
	}
	b.fields = out
	if !replaced {
		b.fields = append(b.fields, field{name: lower, lines: []string{line}})
	}
}

func (b *block) remove(name string) {
	out := b.fields[:0]
	for _, f := range b.fields {
		if f.name == name {
			continue
		}
		out = append(out, f)
	}
	b.fields = out
}

func (b *block) String() string {
	var sb strings.Builder
	for _, f := range b.fields {
		for _, l := range f.lines {
			sb.WriteString(l)
			sb.WriteString("\r\n")
		}
	}
	if b.blank {
		sb.WriteString("\r\n")
	}
	return sb.String()
}
