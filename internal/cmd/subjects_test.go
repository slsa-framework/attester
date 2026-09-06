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

const testDigest = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"

// runBuildRaw executes the build subcommand with exactly the given args (no
// implicit subject file) and returns the decoded output on success.
func runBuildRaw(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "att.json")

	root := New()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs(append([]string{"build", "--sign=false", "-o", out}, args...))

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

func TestSubjectDigestOnly(t *testing.T) {
	t.Parallel()
	stmt, err := runBuildRaw(t, "-s", "sha256:"+testDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	subjects, ok := stmt["subject"].([]any)
	if !ok || len(subjects) != 1 {
		t.Fatalf("expected one subject, got: %v", stmt["subject"])
	}
	digest := asMap(t, asMap(t, subjects[0])["digest"])
	if digest["sha256"] != testDigest {
		t.Fatalf("unexpected digest: %v", digest)
	}
}

func TestSubjectDigestAfterHashedFiles(t *testing.T) {
	t.Parallel()
	// The helper appends a subject file, so the declared digest must come second.
	stmt, err := runBuild(t, "-s", "sha256:"+testDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	subjects, ok := stmt["subject"].([]any)
	if !ok || len(subjects) != 2 {
		t.Fatalf("expected two subjects, got: %v", stmt["subject"])
	}
	first := asMap(t, subjects[0])
	if first["name"] != "subject.txt" {
		t.Fatalf("expected the hashed file first, got: %v", first)
	}
	second := asMap(t, asMap(t, subjects[1])["digest"])
	if second["sha256"] != testDigest {
		t.Fatalf("unexpected declared digest: %v", second)
	}
}

func TestSubjectHashAlgorithms(t *testing.T) {
	t.Parallel()
	stmt, err := runBuild(t, "--hash-algorithms", "sha256,sha512")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	subjects, ok := stmt["subject"].([]any)
	if !ok || len(subjects) != 1 {
		t.Fatalf("expected one subject, got: %v", stmt["subject"])
	}
	digest := asMap(t, asMap(t, subjects[0])["digest"])
	if digest["sha256"] == nil || digest["sha512"] == nil {
		t.Fatalf("expected sha256 and sha512 digests, got: %v", digest)
	}

	if _, err := runBuild(t, "--hash-algorithms", "not-an-algo"); err == nil {
		t.Fatal("expected error for an unknown hash algorithm")
	}
}

func TestSubjectErrors(t *testing.T) {
	t.Parallel()
	if _, err := runBuildRaw(t); err == nil {
		t.Fatal("expected error with no subjects at all")
	}
	if _, err := runBuildRaw(t, "-s", "sha256:tooshort"); err == nil {
		t.Fatal("expected error for an invalid subject spec")
	}
}
