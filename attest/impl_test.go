// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/signer"
	signeroptions "github.com/carabiner-dev/signer/options"
	intoto "github.com/in-toto/attestation/go/v1"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
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

	t.Run("appends-declared-subjects", func(t *testing.T) {
		declared := &intoto.ResourceDescriptor{Digest: map[string]string{"sha256": wantA}}
		o := defaultOptions()
		o.Subjects = []*intoto.ResourceDescriptor{declared}

		subs, err := impl.ReadSubjects(&o, []string{pathA})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(subs) != 2 {
			t.Fatalf("expected hashed + declared subjects, got %d", len(subs))
		}
		if subs[0].GetName() != "a.txt" || subs[1] != declared {
			t.Fatalf("unexpected subjects/order: %v", subs)
		}

		// Declared subjects alone, with no files to hash.
		subs, err = impl.ReadSubjects(&o, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(subs) != 1 || subs[0] != declared {
			t.Fatalf("expected only the declared subject, got %v", subs)
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

// fakeSigner is a test double for the Signer interface. It records the payload
// it was asked to sign and returns a canned artifact or error.
type fakeSigner struct {
	artifact signer.SignedArtifact
	err      error
	got      []byte
}

func (f *fakeSigner) SignStatement(data []byte, _ ...signeroptions.SignOptFn) (signer.SignedArtifact, error) {
	f.got = data
	return f.artifact, f.err
}

func TestSign(t *testing.T) {
	t.Parallel()
	impl := &defaultImpl{}
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)

	t.Run("no-signer-passes-through", func(t *testing.T) {
		t.Parallel()
		o := defaultOptions()
		data, err := impl.Sign(&o, statement)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(data, statement) {
			t.Fatalf("expected passthrough, got: %s", data)
		}
	})

	t.Run("emits-signed-artifact", func(t *testing.T) {
		t.Parallel()
		fs := &fakeSigner{
			artifact: &signer.EnvelopeArtifact{
				Envelope: &sdsse.Envelope{
					PayloadType: "https://in-toto.io/Statement/v1",
					Payload:     statement,
					Signatures:  []*sdsse.Signature{{Keyid: "test", Sig: []byte("sig")}},
				},
			},
		}
		o := defaultOptions()
		o.Signer = fs
		data, err := impl.Sign(&o, statement)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(fs.got, statement) {
			t.Fatalf("signer got %s, want the serialized statement", fs.got)
		}
		var env map[string]any
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("signed output is not valid json: %v", err)
		}
		if env["payloadType"] != "https://in-toto.io/Statement/v1" {
			t.Fatalf("unexpected payloadType: %v", env["payloadType"])
		}
	})

	t.Run("signer-error-propagates", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		o := defaultOptions()
		o.Signer = &fakeSigner{err: boom}
		if _, err := impl.Sign(&o, statement); !errors.Is(err, boom) {
			t.Fatalf("expected signer error to propagate, got %v", err)
		}
	})
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

func defaultOptionsPtr() *Options {
	o := defaultOptions()
	return &o
}
