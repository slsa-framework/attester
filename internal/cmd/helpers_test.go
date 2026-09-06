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

// runAttestCmd executes an attestation subcommand with args (unsigned), adding
// a temp subject file, and returns the decoded statement.
func runAttestCmd(t *testing.T, subcommand string, args ...string) (map[string]any, error) {
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
	root.SetArgs(append(append([]string{subcommand, "--sign=false", "-o", out}, args...), subject))

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

// runBuild executes the build subcommand with args and returns the decoded
// statement.
func runBuild(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	return runAttestCmd(t, "build", args...)
}

// runVSA executes the vsa subcommand with args and returns the decoded
// statement.
func runVSA(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	return runAttestCmd(t, "vsa", args...)
}

// asMap asserts that v is a JSON object and returns it.
func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected a JSON object, got %T", v)
	}
	return m
}
