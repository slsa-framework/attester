// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"strings"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	buildv02 "github.com/slsa-framework/slsa-core/predicates/build/v02"
)

func TestGenerateSlsaProvenanceV02Statement(t *testing.T) {
	t.Parallel()
	impl := &defaultImpl{}
	subjects := []*intoto.ResourceDescriptor{{Name: "artifact"}}

	t.Run("nil-predicate-uses-empty", func(t *testing.T) {
		o := defaultOptions()
		stmt, err := impl.GenerateSlsaProvenanceV02Statement(&o, subjects)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stmt.GetPredicateType() != PredicateTypeSlsaProvenanceV02 {
			t.Fatalf("unexpected predicate type: %q", stmt.GetPredicateType())
		}
		if stmt.GetPredicate() == nil {
			t.Fatalf("expected non-nil predicate struct")
		}
	})

	t.Run("supplied-predicate-is-embedded", func(t *testing.T) {
		o := defaultOptions()
		o.Predicate = &buildv02.Provenance{
			BuildType: "https://example.com/build@v0.2",
			Builder:   &buildv02.Builder{Id: "https://example.com/builder"},
		}
		stmt, err := impl.GenerateSlsaProvenanceV02Statement(&o, subjects)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		fields := stmt.GetPredicate().GetFields()
		if got := fields["buildType"].GetStringValue(); got != "https://example.com/build@v0.2" {
			t.Fatalf("unexpected buildType: %q", got)
		}
		if got := fields["builder"].GetStructValue().GetFields()["id"].GetStringValue(); got != "https://example.com/builder" {
			t.Fatalf("unexpected builder id: %q", got)
		}
	})

	t.Run("wrong-predicate-type-errors", func(t *testing.T) {
		o := defaultOptions()
		o.Predicate = &intoto.ResourceDescriptor{Name: "not a provenance"}
		if _, err := impl.GenerateSlsaProvenanceV02Statement(&o, subjects); err == nil {
			t.Fatal("expected error for incompatible predicate type")
		}
	})
}

func TestAttestSlsaProvenanceV02EndToEnd(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := &Writer{}
	err := w.AttestSlsaProvenanceV02(nil,
		WithWriter(&buf),
		WithPredicate(&buildv02.Provenance{BuildType: "https://example.com/b"}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected single trailing newline, got: %q", out)
	}
	if !strings.Contains(out, PredicateTypeSlsaProvenanceV02) {
		t.Fatalf("output missing predicate type: %s", out)
	}
}
