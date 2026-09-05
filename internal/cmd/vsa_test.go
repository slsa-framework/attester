// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// runVSA executes the vsa subcommand with args and returns the decoded statement.
func runVSA(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	dir := t.TempDir()
	subject := filepath.Join(dir, "subject.txt")
	if err := os.WriteFile(subject, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "att.json")

	root := New()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs(append(append([]string{"vsa", "--sign=false", "-o", out}, args...), subject))

	if err := root.Execute(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	var stmt map[string]any
	if err := json.Unmarshal(data, &stmt); err != nil {
		t.Fatalf("decoding output: %v", err)
	}
	return stmt, nil
}

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
	if v := pred["verifier"].(map[string]any); v["id"] != "https://ex/v" {
		t.Fatalf("unexpected verifier: %v", v)
	}
	if levels := pred["verifiedLevels"].([]any); len(levels) != 1 {
		t.Fatalf("expected 1 verified level, got %v", levels)
	}
	// proto JSON encodes uint64 map values as strings.
	if dl := pred["dependencyLevels"].(map[string]any); dl["SLSA_BUILD_LEVEL_3"] != "5" {
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
