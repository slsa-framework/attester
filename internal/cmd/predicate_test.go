// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPredicateBaseMergesWithFlags(t *testing.T) {
	t.Parallel()
	stmt, err := runBuild(t,
		"--predicate", `{"buildDefinition":{"buildType":"https://ex/bt"}}`,
		"--builder-id", "https://example.com/builder",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pred := predicateOf(t, stmt)
	bd, ok := pred["buildDefinition"].(map[string]any)
	if !ok || bd["buildType"] != "https://ex/bt" {
		t.Fatalf("expected buildType from the base predicate, got: %v", pred)
	}
	rd, ok := pred["runDetails"].(map[string]any)
	if !ok {
		t.Fatalf("expected runDetails from the flags, got: %v", pred)
	}
	if asMap(t, rd["builder"])["id"] != "https://example.com/builder" {
		t.Fatalf("expected builder id from the flags, got: %v", rd)
	}
}

func TestPredicateFromFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pred.json")
	if err := os.WriteFile(path, []byte(`{"verifier":{"id":"https://ex/verifier"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stmt, err := runVSA(t, "--predicate", "@"+path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pred := predicateOf(t, stmt)
	verifier, ok := pred["verifier"].(map[string]any)
	if !ok || verifier["id"] != "https://ex/verifier" {
		t.Fatalf("expected verifier from the base predicate file, got: %v", pred)
	}
}

func TestPredicateMismatchRejected(t *testing.T) {
	t.Parallel()
	// A v0.2-shaped predicate must not parse as the default v1.
	if _, err := runBuild(t, "--predicate", `{"builder":{"id":"x"}}`); err == nil {
		t.Fatal("expected error for a predicate that does not match the proto")
	}
	// Invalid JSON is rejected at flag-parse time.
	if _, err := runBuild(t, "--predicate", `{not json`); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
