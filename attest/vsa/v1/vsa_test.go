// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	vsav1 "github.com/slsa-framework/slsa-core/predicates/vsa/v1"
)

func TestStatement(t *testing.T) {
	t.Parallel()
	w := New(Options{
		VerifierID:         "https://ex/v",
		ResourceURI:        "pkg:x@1",
		PolicyURI:          "https://ex/p",
		PolicyDigest:       map[string]string{"sha256": "p0"},
		VerificationResult: "PASSED",
		VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_3"},
		DependencyLevels:   map[string]uint64{"SLSA_BUILD_LEVEL_3": 5},
		InputAttestations: []*intoto.ResourceDescriptor{
			{Name: "dropped", Uri: "https://ex/att", Digest: map[string]string{"sha256": "a7"}},
		},
	})
	stmt, err := w.Statement(nil)
	if err != nil {
		t.Fatal(err)
	}
	if stmt.GetPredicateType() != PredicateTypeURI {
		t.Fatalf("predicate type: %q", stmt.GetPredicateType())
	}
	pred := stmt.GetPredicate().GetFields()
	if pred["verifier"].GetStructValue().GetFields()["id"].GetStringValue() != "https://ex/v" {
		t.Fatalf("verifier id missing")
	}
	if pred["verificationResult"].GetStringValue() != "PASSED" {
		t.Fatalf("verificationResult missing")
	}
	// uint64 map values render as JSON strings.
	if pred["dependencyLevels"].GetStructValue().GetFields()["SLSA_BUILD_LEVEL_3"].GetStringValue() != "5" {
		t.Fatalf("dependencyLevels: %v", pred["dependencyLevels"])
	}
	in := pred["inputAttestations"].GetListValue().GetValues()[0].GetStructValue().GetFields()
	if in["uri"].GetStringValue() != "https://ex/att" {
		t.Fatalf("input uri: %v", in["uri"])
	}
	if _, hasName := in["name"]; hasName {
		t.Fatalf("inputAttestation must not carry name")
	}
}

func TestEmptyOptions(t *testing.T) {
	t.Parallel()
	stmt, err := New(Options{}).Statement(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(stmt.GetPredicate().GetFields()); n != 0 {
		t.Fatalf("expected empty predicate, got %d", n)
	}
}

func TestWrongBaseType(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{Base: &vsav1.VerificationSummary_Policy{}}).Statement(nil); err == nil {
		t.Fatal("expected error for wrong base type")
	}
}
