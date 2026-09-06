// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package gha

import (
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

	pred, err := c.Predicate(run)
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
}

func TestHeadRefFallsBackToSHA(t *testing.T) {
	t.Parallel()
	run := &gogithub.WorkflowRun{HeadSHA: gogithub.Ptr("deadbeef")}
	if got := headRef(run); got != "deadbeef" {
		t.Fatalf("unexpected ref: %q", got)
	}
	run.HeadBranch = gogithub.Ptr("refs/tags/v1.0.0")
	if got := headRef(run); got != "refs/tags/v1.0.0" {
		t.Fatalf("already-qualified ref must pass through: %q", got)
	}
}
