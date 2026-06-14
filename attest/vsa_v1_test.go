// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"strings"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	vsav1 "github.com/slsa-framework/slsa-core/predicates/vsa/v1"
)

func TestGenerateVsaV1Statement(t *testing.T) {
	t.Parallel()
	impl := &defaultImpl{}
	subjects := []*intoto.ResourceDescriptor{{Name: "artifact"}}

	t.Run("nil-predicate-uses-empty", func(t *testing.T) {
		o := defaultOptions()
		stmt, err := impl.GenerateVsaV1Statement(&o, subjects)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stmt.GetPredicateType() != PredicateTypeVsaV1 {
			t.Fatalf("unexpected predicate type: %q", stmt.GetPredicateType())
		}
		if stmt.GetPredicate() == nil {
			t.Fatalf("expected non-nil predicate struct")
		}
	})

	t.Run("supplied-predicate-is-embedded", func(t *testing.T) {
		o := defaultOptions()
		o.Predicate = &vsav1.VerificationSummary{
			Verifier:           &vsav1.VerificationSummary_Verifier{Id: "https://example.com/verifier"},
			ResourceUri:        "pkg:example/thing@1.0.0",
			VerificationResult: "PASSED",
			VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_3"},
		}
		stmt, err := impl.GenerateVsaV1Statement(&o, subjects)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		fields := stmt.GetPredicate().GetFields()
		if got := fields["resourceUri"].GetStringValue(); got != "pkg:example/thing@1.0.0" {
			t.Fatalf("unexpected resourceUri: %q", got)
		}
		if got := fields["verificationResult"].GetStringValue(); got != "PASSED" {
			t.Fatalf("unexpected verificationResult: %q", got)
		}
		if got := fields["verifier"].GetStructValue().GetFields()["id"].GetStringValue(); got != "https://example.com/verifier" {
			t.Fatalf("unexpected verifier id: %q", got)
		}
	})

	t.Run("wrong-predicate-type-errors", func(t *testing.T) {
		o := defaultOptions()
		o.Predicate = &intoto.ResourceDescriptor{Name: "not a vsa"}
		if _, err := impl.GenerateVsaV1Statement(&o, subjects); err == nil {
			t.Fatal("expected error for incompatible predicate type")
		}
	})
}

func TestAttestVSAV1EndToEnd(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := &Writer{}
	err := w.AttestVSAV1(nil,
		WithWriter(&buf),
		WithPredicate(&vsav1.VerificationSummary{VerificationResult: "PASSED"}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected single trailing newline, got: %q", out)
	}
	if !strings.Contains(out, PredicateTypeVsaV1) {
		t.Fatalf("output missing predicate type: %s", out)
	}
}
