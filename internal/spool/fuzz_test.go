// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func FuzzDecodeMeta(f *testing.F) {
	seed := func(mutate func(m *Meta)) {
		m := validMeta()
		mutate(m)
		b, err := json.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	seed(func(*Meta) {})
	seed(func(m *Meta) { m.Envelope = selfmailEnvelope() })
	seed(func(m *Meta) { m.Envelope.To = []string{"ops@example.net\r\nDATA"} })
	seed(func(m *Meta) { m.Envelope.From = "a\x00@example.at" })
	seed(func(m *Meta) { m.Envelope.Route = `m"365` })
	seed(func(m *Meta) { m.Envelope.Kind = "bounce" })
	seed(func(m *Meta) { m.Envelope.To = strings.Split(strings.Repeat("r@example.net,", 500), ",")[:500] })
	seed(func(m *Meta) { m.Attempts = -1 })
	for _, s := range []string{
		`{"id":"ABCDEFGHIJKLMNOP","envelope":{"from":"","to":["a@b.example"],"route":"r","notification":true}}`,
		`{"id":"ABCDEFGHIJKLMNOP","envelope":{"to":["a@b.example"],"route":"r","client":"c"},"future":{"x":[1]}}`,
		`{"id":"ABCDEFGHIJKLMNOP","envelope":{"to":["a@b.example"],"route":"r","received":"2026-11-11T08:00:00+01:00"}}`,
		`{"id":"ABCDEFGHIJKLMNOQ","envelope":{"to":["a@b.example"],"route":"r"}}`,
		`{"id":"ABCDEFGHIJKLMNOP","envelope":{"to":"a@b.example","route":"r"}}`,
		`{"id":"ABCDEFGHIJKLMNOP","envelope":{"to":["a\u0000@b.example"],"route":"r"}}`,
		"{\"id\":\"ABCDEFGHIJKLMNOP\",\"envelope\":{\"to\":[\"\xff@b.example\"],\"route\":\"r\"}}",
		`{"id":`,
		`null`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := decodeMeta(b, fixedID)
		if err != nil {
			return
		}
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("accepted metadata does not encode: %v", err)
		}
		again, err := decodeMeta(out, fixedID)
		if err != nil {
			t.Fatalf("accepted metadata, encoded again, is refused: %v\n%s", err, out)
		}
		if !reflect.DeepEqual(m, again) {
			t.Fatalf("metadata changed across an encode and decode:\n got %+v\nwant %+v", again, m)
		}
	})
}
