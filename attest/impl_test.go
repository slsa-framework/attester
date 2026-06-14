// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestReadSubjects(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.txt")
	pathB := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(pathA, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte("bravo"), 0o600); err != nil {
		t.Fatal(err)
	}
	sumA := sha256.Sum256([]byte("alpha"))
	wantA := hex.EncodeToString(sumA[:])

	impl := &defaultImpl{}
	opts := defaultOptions()

	t.Run("hashes-in-order-and-dedupes", func(t *testing.T) {
		// pathA repeated should only appear once and order must be preserved.
		subs, err := impl.ReadSubjects(&opts, []string{pathA, pathB, pathA})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(subs) != 2 {
			t.Fatalf("expected 2 subjects, got %d", len(subs))
		}
		if subs[0].GetName() != "a.txt" || subs[1].GetName() != "b.txt" {
			t.Fatalf("unexpected names/order: %q, %q", subs[0].GetName(), subs[1].GetName())
		}
		if got := subs[0].GetDigest()["sha256"]; got != wantA {
			t.Fatalf("digest mismatch for a.txt: got %q want %q", got, wantA)
		}
	})

	t.Run("empty", func(t *testing.T) {
		subs, err := impl.ReadSubjects(&opts, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if subs != nil {
			t.Fatalf("expected nil subjects, got %v", subs)
		}
	})

	t.Run("missing-file", func(t *testing.T) {
		if _, err := impl.ReadSubjects(&opts, []string{filepath.Join(dir, "nope")}); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("unknown-algorithm", func(t *testing.T) {
		o := defaultOptions()
		o.HashAlgorithms = []string{"not-an-algo"}
		if _, err := impl.ReadSubjects(&o, []string{pathA}); err == nil {
			t.Fatal("expected error for unknown algorithm")
		}
	})
}

func TestSerialize(t *testing.T) {
	t.Parallel()
	pred, err := structpb.NewStruct(map[string]any{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	stmt := &intoto.Statement{
		Type:          intoto.StatementTypeUri,
		PredicateType: "https://example.com/pred/v1",
		Subject: []*intoto.ResourceDescriptor{
			{Name: "a.txt", Digest: map[string]string{"sha256": "deadbeef"}},
		},
		Predicate: pred,
	}

	data, err := (&defaultImpl{}).Serialize(defaultOptionsPtr(), stmt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Contains(data, []byte("\n")) {
		t.Fatalf("serialized output must be single line, got: %s", data)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("output is not valid json: %v", err)
	}
	if decoded["predicateType"] != "https://example.com/pred/v1" {
		t.Fatalf("unexpected predicateType: %v", decoded["predicateType"])
	}
	if decoded["_type"] != intoto.StatementTypeUri {
		t.Fatalf("unexpected _type: %v", decoded["_type"])
	}
}

func TestWrite(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	o := defaultOptions()
	o.Writer = &buf
	if err := (&defaultImpl{}).Write(&o, []byte("payload")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != "payload\n" {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}

func TestBuildStatement(t *testing.T) {
	t.Parallel()
	subjects := []*intoto.ResourceDescriptor{{Name: "x"}}

	t.Run("nil-predicate-yields-empty-struct", func(t *testing.T) {
		stmt, err := buildStatement("https://example.com/p", subjects, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stmt.GetType() != intoto.StatementTypeUri {
			t.Fatalf("unexpected type: %q", stmt.GetType())
		}
		if stmt.GetPredicate() == nil || len(stmt.GetPredicate().GetFields()) != 0 {
			t.Fatalf("expected empty predicate struct, got %v", stmt.GetPredicate())
		}
		if len(stmt.GetSubject()) != 1 {
			t.Fatalf("expected subjects to be carried through")
		}
	})

	t.Run("predicate-converted", func(t *testing.T) {
		pred, err := structpb.NewStruct(map[string]any{"k": "v"})
		if err != nil {
			t.Fatal(err)
		}
		stmt, err := buildStatement("https://example.com/p", subjects, pred)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stmt.GetPredicate().GetFields()["k"].GetStringValue() != "v" {
			t.Fatalf("predicate not converted: %v", stmt.GetPredicate())
		}
	})
}

func defaultOptionsPtr() *Options {
	o := defaultOptions()
	return &o
}
