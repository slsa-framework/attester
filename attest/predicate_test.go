// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"testing"

	buildv02 "github.com/slsa-framework/protos/build/v02"
	buildv1 "github.com/slsa-framework/protos/build/v1"
	vsav1 "github.com/slsa-framework/protos/vsa/v1"
)

func TestParsePredicate(t *testing.T) {
	t.Parallel()

	t.Run("build-v1", func(t *testing.T) {
		t.Parallel()
		p, err := ParsePredicate(SlsaProvenanceV1, []byte(`{"buildDefinition":{"buildType":"https://ex/bt"}}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		prov, ok := p.(*buildv1.Provenance)
		if !ok {
			t.Fatalf("expected *buildv1.Provenance, got %T", p)
		}
		if prov.GetBuildDefinition().GetBuildType() != "https://ex/bt" {
			t.Fatalf("unexpected buildType: %v", prov)
		}
	})

	t.Run("build-v02", func(t *testing.T) {
		t.Parallel()
		p, err := ParsePredicate(SlsaProvenanceV02, []byte(`{"builder":{"id":"https://ex/builder"}}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := p.(*buildv02.Provenance); !ok {
			t.Fatalf("expected *buildv02.Provenance, got %T", p)
		}
	})

	t.Run("vsa-v1", func(t *testing.T) {
		t.Parallel()
		p, err := ParsePredicate(VsaV1, []byte(`{"verifier":{"id":"https://ex/verifier"}}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := p.(*vsav1.VerificationSummary); !ok {
			t.Fatalf("expected *vsav1.VerificationSummary, got %T", p)
		}
	})

	t.Run("rejects-unknown-fields", func(t *testing.T) {
		t.Parallel()
		if _, err := ParsePredicate(SlsaProvenanceV1, []byte(`{"bogusField":true}`)); err == nil {
			t.Fatal("expected error for a field the proto does not define")
		}
		// A v0.2 predicate is not a valid v1 predicate.
		if _, err := ParsePredicate(SlsaProvenanceV1, []byte(`{"builder":{"id":"x"}}`)); err == nil {
			t.Fatal("expected error parsing a v0.2 predicate as v1")
		}
	})

	t.Run("rejects-bad-json", func(t *testing.T) {
		t.Parallel()
		if _, err := ParsePredicate(SlsaProvenanceV1, []byte(`{not json`)); err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("unknown-version", func(t *testing.T) {
		t.Parallel()
		if _, err := ParsePredicate(AttestationVersion("nope"), []byte(`{}`)); !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("expected ErrUnknownVersion, got %v", err)
		}
	})
}
