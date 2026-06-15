// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"testing"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	vsav1 "github.com/slsa-framework/slsa-core/predicates/vsa/v1"
)

func TestVsaV1OptionsMerge(t *testing.T) {
	t.Parallel()
	impl := &defaultImpl{}
	verified := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

	o := applyOpts(t,
		WithVerifierID("https://example.com/verifier"),
		WithTimeVerified(verified),
		WithResourceURI("pkg:generic/thing@1.0.0"),
		WithPolicyURI("https://example.com/policy"),
		WithPolicyDigest(map[string]string{"sha256": "p0l1cy"}),
		WithInputAttestations(&intoto.ResourceDescriptor{
			Name:   "dropped",
			Uri:    "https://example.com/att",
			Digest: map[string]string{"sha256": "a77"},
		}),
		WithVerificationResult("PASSED"),
		WithVerifiedLevels("SLSA_BUILD_LEVEL_2"),
		WithVerifiedLevels("SLSA_BUILD_LEVEL_3"),
		WithDependencyLevels(map[string]uint64{"SLSA_BUILD_LEVEL_3": 5}),
		WithSlsaVersion("1.0"),
	)

	stmt, err := impl.GenerateVsaV1Statement(o, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pred := stmt.GetPredicate().GetFields()

	if got := pred["verifier"].GetStructValue().GetFields()["id"].GetStringValue(); got != "https://example.com/verifier" {
		t.Fatalf("verifier id: %q", got)
	}
	if pred["timeVerified"].GetStringValue() == "" {
		t.Fatalf("expected timeVerified set")
	}
	if got := pred["resourceUri"].GetStringValue(); got != "pkg:generic/thing@1.0.0" {
		t.Fatalf("resourceUri: %q", got)
	}
	policy := pred["policy"].GetStructValue().GetFields()
	if got := policy["uri"].GetStringValue(); got != "https://example.com/policy" {
		t.Fatalf("policy uri: %q", got)
	}
	if got := policy["digest"].GetStructValue().GetFields()["sha256"].GetStringValue(); got != "p0l1cy" {
		t.Fatalf("policy digest: %q", got)
	}
	if got := pred["verificationResult"].GetStringValue(); got != "PASSED" {
		t.Fatalf("verificationResult: %q", got)
	}
	if levels := pred["verifiedLevels"].GetListValue().GetValues(); len(levels) != 2 {
		t.Fatalf("expected 2 verifiedLevels (append), got %d", len(levels))
	}
	// proto JSON encodes uint64 map values as strings.
	if got := pred["dependencyLevels"].GetStructValue().GetFields()["SLSA_BUILD_LEVEL_3"].GetStringValue(); got != "5" {
		t.Fatalf("dependencyLevels: %q", got)
	}
	if got := pred["slsaVersion"].GetStringValue(); got != "1.0" {
		t.Fatalf("slsaVersion: %q", got)
	}

	inputs := pred["inputAttestations"].GetListValue().GetValues()
	if len(inputs) != 1 {
		t.Fatalf("expected 1 inputAttestation, got %d", len(inputs))
	}
	in := inputs[0].GetStructValue().GetFields()
	if got := in["uri"].GetStringValue(); got != "https://example.com/att" {
		t.Fatalf("input uri: %q", got)
	}
	if _, hasName := in["name"]; hasName {
		t.Fatalf("inputAttestation must not carry a name field")
	}
}

func TestVsaV1NoOptionsLeavesPredicateEmpty(t *testing.T) {
	t.Parallel()
	stmt, err := (&defaultImpl{}).GenerateVsaV1Statement(applyOpts(t), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := len(stmt.GetPredicate().GetFields()); n != 0 {
		t.Fatalf("expected empty predicate, got %d fields", n)
	}
}

func TestVsaV1DoesNotMutateBase(t *testing.T) {
	t.Parallel()
	base := &vsav1.VerificationSummary{ResourceUri: "base"}
	o := applyOpts(t, WithPredicate(base), WithVerifierID("v"))
	if _, err := (&defaultImpl{}).GenerateVsaV1Statement(o, nil); err != nil {
		t.Fatal(err)
	}
	if base.GetVerifier() != nil {
		t.Fatalf("base predicate was mutated")
	}
}
