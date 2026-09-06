// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"
)

func TestVSAFlagMapping(t *testing.T) {
	t.Parallel()
	stmt, err := runVSA(t,
		"--verifier-id", "https://ex/v",
		"--resource-uri", "pkg:x@1",
		"--verification-result", "PASSED",
		"--verified-level", "SLSA_BUILD_LEVEL_3",
		"--policy-digest", "sha256=p0",
		"--input-attestation", "uri=https://ex/att,sha256=a7",
		"--dependency-level", "SLSA_BUILD_LEVEL_3=5",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stmt["predicateType"] != "https://slsa.dev/verification_summary/v1" {
		t.Fatalf("unexpected predicateType: %v", stmt["predicateType"])
	}
	pred := predicateOf(t, stmt)
	if pred["resourceUri"] != "pkg:x@1" {
		t.Fatalf("unexpected resourceUri: %v", pred["resourceUri"])
	}
	if pred["verificationResult"] != "PASSED" {
		t.Fatalf("unexpected verificationResult: %v", pred["verificationResult"])
	}
	if v := asMap(t, pred["verifier"]); v["id"] != "https://ex/v" {
		t.Fatalf("unexpected verifier: %v", v)
	}
	if levels, ok := pred["verifiedLevels"].([]any); !ok || len(levels) != 1 {
		t.Fatalf("expected 1 verified level, got %v", levels)
	}
	// proto JSON encodes uint64 map values as strings.
	if dl := asMap(t, pred["dependencyLevels"]); dl["SLSA_BUILD_LEVEL_3"] != "5" {
		t.Fatalf("unexpected dependencyLevels: %v", dl)
	}
	if _, ok := pred["inputAttestations"].([]any); !ok {
		t.Fatalf("expected inputAttestations: %v", pred)
	}
}

func TestVSABadVersionErrors(t *testing.T) {
	t.Parallel()
	if _, err := runVSA(t, "--predicate-version", "v2"); err == nil {
		t.Fatal("expected error for unsupported version")
	}
}
