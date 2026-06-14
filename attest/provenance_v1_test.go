// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"strings"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	buildv1 "github.com/slsa-framework/slsa-core/predicates/build/v1"
)

func TestGenerateSlsaProvenanceV1Statement(t *testing.T) {
	t.Parallel()
	impl := &defaultImpl{}
	subjects := []*intoto.ResourceDescriptor{{Name: "artifact"}}

	t.Run("nil-predicate-uses-empty", func(t *testing.T) {
		o := defaultOptions()
		stmt, err := impl.GenerateSlsaProvenanceV1Statement(&o, subjects)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stmt.GetPredicateType() != PredicateTypeSlsaProvenanceV1 {
			t.Fatalf("unexpected predicate type: %q", stmt.GetPredicateType())
		}
		if len(stmt.GetSubject()) != 1 {
			t.Fatalf("subjects not carried through")
		}
		if stmt.GetPredicate() == nil {
			t.Fatalf("expected non-nil predicate struct")
		}
	})

	t.Run("supplied-predicate-is-embedded", func(t *testing.T) {
		o := defaultOptions()
		o.Predicate = &buildv1.Provenance{
			BuildDefinition: &buildv1.BuildDefinition{
				BuildType: "https://example.com/build@v1",
			},
		}
		stmt, err := impl.GenerateSlsaProvenanceV1Statement(&o, subjects)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		bd := stmt.GetPredicate().GetFields()["buildDefinition"].GetStructValue()
		if bd == nil {
			t.Fatalf("buildDefinition missing from predicate: %v", stmt.GetPredicate())
		}
		if got := bd.GetFields()["buildType"].GetStringValue(); got != "https://example.com/build@v1" {
			t.Fatalf("unexpected buildType: %q", got)
		}
	})

	t.Run("wrong-predicate-type-errors", func(t *testing.T) {
		o := defaultOptions()
		o.Predicate = &intoto.ResourceDescriptor{Name: "not a provenance"}
		if _, err := impl.GenerateSlsaProvenanceV1Statement(&o, subjects); err == nil {
			t.Fatal("expected error for incompatible predicate type")
		}
	})
}

// TestAttestSlsaProvenanceV1EndToEnd exercises the full public path with the
// real implementation, asserting a valid single-line statement is written.
func TestAttestSlsaProvenanceV1EndToEnd(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := &Writer{}
	err := w.AttestSlsaProvenanceV1(nil,
		WithWriter(&buf),
		WithPredicate(&buildv1.Provenance{
			BuildDefinition: &buildv1.BuildDefinition{BuildType: "https://example.com/b"},
		}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected single trailing newline, got: %q", out)
	}
	if want := PredicateTypeSlsaProvenanceV1; !strings.Contains(out, want) {
		t.Fatalf("output missing predicate type %q: %s", want, out)
	}
}
