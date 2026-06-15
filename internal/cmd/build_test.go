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

// runBuild executes the build subcommand with args, writing the attestation to a
// temp file, and returns the decoded statement.
func runBuild(t *testing.T, args ...string) (map[string]any, error) {
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
	root.SetArgs(append(append([]string{"build", "-o", out}, args...), subject))

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

func predicateOf(t *testing.T, stmt map[string]any) map[string]any {
	t.Helper()
	pred, ok := stmt["predicate"].(map[string]any)
	if !ok {
		t.Fatalf("predicate missing or wrong type: %v", stmt["predicate"])
	}
	return pred
}

func TestBuildV1FlagMapping(t *testing.T) {
	t.Parallel()
	stmt, err := runBuild(t,
		"--build-type", "https://ex/bt",
		"--resolved-dependency", "name=dep,sha256=ab",
		"--invocation-id", "run-1",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stmt["predicateType"] != "https://slsa.dev/provenance/v1" {
		t.Fatalf("unexpected predicateType: %v", stmt["predicateType"])
	}
	bd := predicateOf(t, stmt)["buildDefinition"].(map[string]any)
	if _, ok := bd["resolvedDependencies"]; !ok {
		t.Fatalf("expected resolvedDependencies in v1: %v", bd)
	}
}

func TestBuildV02FlagMappingToLegacyNames(t *testing.T) {
	t.Parallel()
	stmt, err := runBuild(t,
		"--predicate-version", "v0.2",
		"--resolved-dependency", "uri=pkg:x,sha256=ab",
		"--invocation-id", "run-1",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pred := predicateOf(t, stmt)
	if _, ok := pred["resolvedDependencies"]; ok {
		t.Fatalf("v0.2 must not emit resolvedDependencies: %v", pred)
	}
	if _, ok := pred["materials"]; !ok {
		t.Fatalf("expected materials in v0.2: %v", pred)
	}
	meta := pred["metadata"].(map[string]any)
	if _, ok := meta["buildInvocationId"]; !ok {
		t.Fatalf("expected buildInvocationId in v0.2 metadata: %v", meta)
	}
}

func TestBuildHiddenMaterialsAlias(t *testing.T) {
	t.Parallel()
	stmt, err := runBuild(t, "--predicate-version", "v0.2", "--materials", "uri=pkg:y,sha256=cd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := predicateOf(t, stmt)["materials"]; !ok {
		t.Fatalf("expected materials from --materials alias")
	}
}

func TestBuildVersionMismatchErrors(t *testing.T) {
	t.Parallel()
	if _, err := runBuild(t, "--predicate-version", "v0.2", "--byproduct", "name=x"); err == nil {
		t.Fatal("expected error using v1-only flag with v0.2")
	}
	if _, err := runBuild(t, "--reproducible"); err == nil {
		t.Fatal("expected error using v0.2-only flag with v1")
	}
}
