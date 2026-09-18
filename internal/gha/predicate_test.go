// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"net/http"
	"testing"
	"time"

	gogithub "github.com/google/go-github/v90/github"
)

func TestPredicate(t *testing.T) {
	t.Parallel()
	c := &Client{Owner: "org", Repo: "proj", RunID: 7}
	run := &gogithub.WorkflowRun{
		ID:           gogithub.Ptr(int64(7)),
		RunAttempt:   gogithub.Ptr(2),
		Path:         gogithub.Ptr(".github/workflows/ci.yml"),
		Event:        gogithub.Ptr("push"),
		HeadBranch:   gogithub.Ptr("main"),
		HeadSHA:      gogithub.Ptr("abc123"),
		RunStartedAt: &gogithub.Timestamp{Time: time.Unix(1750000000, 0).UTC()},
		UpdatedAt:    &gogithub.Timestamp{Time: time.Unix(1750000600, 0).UTC()},
	}

	pred, err := c.Predicate(run, "refs/heads/main", map[string]any{"environment": "prod", "skip-tests": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := pred.GetBuildDefinition().GetBuildType(); got != BuildType {
		t.Fatalf("unexpected buildType: %q", got)
	}
	wantBuilder := "https://github.com/org/proj/.github/workflows/ci.yml@refs/heads/main"
	if got := pred.GetRunDetails().GetBuilder().GetId(); got != wantBuilder {
		t.Fatalf("unexpected builder id: %q", got)
	}
	deps := pred.GetBuildDefinition().GetResolvedDependencies()
	if len(deps) != 1 || deps[0].GetDigest()["gitCommit"] != "abc123" {
		t.Fatalf("unexpected resolved dependencies: %v", deps)
	}
	if deps[0].GetUri() != "git+https://github.com/org/proj@refs/heads/main" {
		t.Fatalf("unexpected source uri: %q", deps[0].GetUri())
	}
	meta := pred.GetRunDetails().GetMetadata()
	if meta.GetInvocationId() != "https://github.com/org/proj/actions/runs/7/attempts/2" {
		t.Fatalf("unexpected invocation id: %q", meta.GetInvocationId())
	}
	if meta.GetStartedOn().AsTime().Unix() != 1750000000 || meta.GetFinishedOn().AsTime().Unix() != 1750000600 {
		t.Fatalf("unexpected times: %v %v", meta.GetStartedOn(), meta.GetFinishedOn())
	}
	ext := pred.GetBuildDefinition().GetExternalParameters().AsMap()
	if ext["workflow"] != ".github/workflows/ci.yml" || ext["event"] != "push" || ext["ref"] != "refs/heads/main" {
		t.Fatalf("unexpected external parameters: %v", ext)
	}
	inputs, ok := ext["inputs"].(map[string]any)
	if !ok || inputs["environment"] != "prod" || inputs["skip-tests"] != true {
		t.Fatalf("unexpected inputs in external parameters: %v", ext["inputs"])
	}

	// Without inputs the key must not appear at all.
	pred, err = c.Predicate(run, "refs/heads/main", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := pred.GetBuildDefinition().GetExternalParameters().AsMap()["inputs"]; ok {
		t.Fatal("empty inputs must not be recorded")
	}
}

func TestRunRef(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/org/proj/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `{"ref": "refs/heads/main", "object": {"sha": "abc123"}}`)
	})
	mux.HandleFunc("/repos/org/proj/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `{"ref": "refs/tags/v1.0.0", "object": {"sha": "tagobj"}}`)
	})
	c := testClient(t, mux)
	t.Setenv("GITHUB_ACTIONS", "")

	// A name matching a branch at the run's commit resolves as a branch.
	run := &gogithub.WorkflowRun{HeadBranch: gogithub.Ptr("main"), HeadSHA: gogithub.Ptr("abc123")}
	if got := c.RunRef(t.Context(), run); got != "refs/heads/main" {
		t.Fatalf("unexpected branch ref: %q", got)
	}

	// A tag name lands in head_branch too; it must resolve as a tag.
	run = &gogithub.WorkflowRun{HeadBranch: gogithub.Ptr("v1.0.0"), HeadSHA: gogithub.Ptr("abc123")}
	if got := c.RunRef(t.Context(), run); got != "refs/tags/v1.0.0" {
		t.Fatalf("unexpected tag ref: %q", got)
	}

	// Unresolvable names fall back to a branch guess; no name falls back to
	// the commit; qualified refs pass through.
	run = &gogithub.WorkflowRun{HeadBranch: gogithub.Ptr("gone"), HeadSHA: gogithub.Ptr("abc123")}
	if got := c.RunRef(t.Context(), run); got != "refs/heads/gone" {
		t.Fatalf("unexpected fallback ref: %q", got)
	}
	run = &gogithub.WorkflowRun{HeadSHA: gogithub.Ptr("deadbeef")}
	if got := c.RunRef(t.Context(), run); got != "deadbeef" {
		t.Fatalf("unexpected sha fallback: %q", got)
	}
	run = &gogithub.WorkflowRun{HeadBranch: gogithub.Ptr("refs/tags/v2.0.0")}
	if got := c.RunRef(t.Context(), run); got != "refs/tags/v2.0.0" {
		t.Fatalf("already-qualified ref must pass through: %q", got)
	}
}

func TestRunRefSameRun(t *testing.T) {
	// Inside the attested run the runner's GITHUB_REF wins, with no API call.
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "org/proj")
	t.Setenv("GITHUB_RUN_ID", "7")
	t.Setenv("GITHUB_REF", "refs/tags/v0.1.0-rc.2")

	c := testClient(t, http.NewServeMux())
	run := &gogithub.WorkflowRun{HeadBranch: gogithub.Ptr("v0.1.0-rc.2")}
	if got := c.RunRef(t.Context(), run); got != "refs/tags/v0.1.0-rc.2" {
		t.Fatalf("unexpected ref: %q", got)
	}
}
