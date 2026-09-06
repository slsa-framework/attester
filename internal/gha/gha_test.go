// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"testing"
)

func TestParseSpec(t *testing.T) {
	t.Parallel()
	owner, repo, runID, err := ParseSpec("github://slsa-framework/actions/12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "slsa-framework" || repo != "actions" || runID != 12345 {
		t.Fatalf("unexpected parse: %s %s %d", owner, repo, runID)
	}

	for _, spec := range []string{
		"",
		"github://",
		"github://owner/repo",
		"github://owner/repo/notanumber",
		"github://owner/repo/-3",
		"gitlab://owner/repo/1",
		"github://owner/repo/1/extra",
	} {
		if _, _, _, err := ParseSpec(spec); err == nil {
			t.Errorf("expected error for %q", spec)
		}
	}
}

func TestSpecFromEnvironment(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "org/proj")
	t.Setenv("GITHUB_RUN_ID", "99")
	if spec := SpecFromEnvironment(); spec != "github://org/proj/99" {
		t.Fatalf("unexpected spec: %q", spec)
	}
	t.Setenv("GITHUB_RUN_ID", "")
	if spec := SpecFromEnvironment(); spec != "" {
		t.Fatalf("expected empty spec, got %q", spec)
	}
}

func TestMatchJobName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		apiName, key string
		want         bool
	}{
		{"build", "build", true},
		{"build / inner", "build", true},
		{"builder", "build", false},
		{"build/inner", "build", false}, // needs " / " separator
		{"other", "build", false},
	} {
		if got := matchJobName(tc.apiName, tc.key); got != tc.want {
			t.Errorf("matchJobName(%q, %q) = %v, want %v", tc.apiName, tc.key, got, tc.want)
		}
	}
}

func TestMatchesAnyGlob(t *testing.T) {
	t.Parallel()
	if ok, err := matchesAnyGlob(nil, "anything"); err != nil || !ok {
		t.Fatalf("empty filter must match everything: %v %v", ok, err)
	}
	if ok, err := matchesAnyGlob([]string{"bin-*"}, "bin-linux"); err != nil || !ok {
		t.Fatalf("expected match: %v %v", ok, err)
	}
	if ok, err := matchesAnyGlob([]string{"bin-*"}, "docs"); err != nil || ok {
		t.Fatalf("expected no match: %v %v", ok, err)
	}
	if _, err := matchesAnyGlob([]string{"[bad"}, "x"); err == nil {
		t.Fatal("expected error for invalid glob")
	}
}
