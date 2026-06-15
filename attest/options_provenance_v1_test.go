// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"testing"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	buildv1 "github.com/slsa-framework/slsa-core/predicates/build/v1"
)

// applyOpts builds an Options from the given functional options for testing.
func applyOpts(t *testing.T, fns ...OptFn) *Options {
	t.Helper()
	o := defaultOptions()
	for _, fn := range fns {
		if err := fn(&o); err != nil {
			t.Fatalf("applying option: %v", err)
		}
	}
	return &o
}

func TestProvenanceV1OptionsMerge(t *testing.T) {
	t.Parallel()
	impl := &defaultImpl{}
	started := time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC)

	o := applyOpts(t,
		WithBuildType("https://example.com/build@v1"),
		WithBuilderID("https://example.com/builder"),
		WithBuilderVersion(map[string]string{"host": "ci-1"}),
		WithResolvedDependencies(&intoto.ResourceDescriptor{Name: "dep-a"}),
		WithResolvedDependencies(&intoto.ResourceDescriptor{Name: "dep-b"}),
		WithBuilderDependencies(&intoto.ResourceDescriptor{Name: "bdep"}),
		WithByproducts(&intoto.ResourceDescriptor{Name: "log"}),
		WithInvocationID("run-42"),
		WithStartedOn(started),
	)

	stmt, err := impl.GenerateSlsaProvenanceV1Statement(o, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pred := stmt.GetPredicate().GetFields()

	bd := pred["buildDefinition"].GetStructValue().GetFields()
	if got := bd["buildType"].GetStringValue(); got != "https://example.com/build@v1" {
		t.Fatalf("buildType: %q", got)
	}
	if deps := bd["resolvedDependencies"].GetListValue().GetValues(); len(deps) != 2 {
		t.Fatalf("expected 2 resolvedDependencies (append), got %d", len(deps))
	}

	rd := pred["runDetails"].GetStructValue().GetFields()
	builder := rd["builder"].GetStructValue().GetFields()
	if got := builder["id"].GetStringValue(); got != "https://example.com/builder" {
		t.Fatalf("builder id: %q", got)
	}
	if got := builder["version"].GetStructValue().GetFields()["host"].GetStringValue(); got != "ci-1" {
		t.Fatalf("builder version: %q", got)
	}
	if len(builder["builderDependencies"].GetListValue().GetValues()) != 1 {
		t.Fatalf("expected 1 builderDependency")
	}
	meta := rd["metadata"].GetStructValue().GetFields()
	if got := meta["invocationId"].GetStringValue(); got != "run-42" {
		t.Fatalf("invocationId: %q", got)
	}
	if meta["startedOn"].GetStringValue() == "" {
		t.Fatalf("expected startedOn to be set")
	}
	if len(rd["byproducts"].GetListValue().GetValues()) != 1 {
		t.Fatalf("expected 1 byproduct")
	}
}

func TestProvenanceV1NoOptionsLeavesPredicateEmpty(t *testing.T) {
	t.Parallel()
	stmt, err := (&defaultImpl{}).GenerateSlsaProvenanceV1Statement(applyOpts(t), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := len(stmt.GetPredicate().GetFields()); n != 0 {
		t.Fatalf("expected empty predicate with no options, got %d fields", n)
	}
}

func TestProvenanceV1MergesOntoBaseWithoutMutating(t *testing.T) {
	t.Parallel()
	base := &buildv1.Provenance{
		BuildDefinition: &buildv1.BuildDefinition{
			ResolvedDependencies: []*intoto.ResourceDescriptor{{Name: "base-dep"}},
		},
	}
	o := applyOpts(t,
		WithPredicate(base),
		WithResolvedDependencies(&intoto.ResourceDescriptor{Name: "added-dep"}),
	)

	stmt, err := (&defaultImpl{}).GenerateSlsaProvenanceV1Statement(o, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	deps := stmt.GetPredicate().GetFields()["buildDefinition"].GetStructValue().
		GetFields()["resolvedDependencies"].GetListValue().GetValues()
	if len(deps) != 2 {
		t.Fatalf("expected base+added = 2 deps, got %d", len(deps))
	}
	// The caller's base predicate must remain untouched.
	if got := len(base.GetBuildDefinition().GetResolvedDependencies()); got != 1 {
		t.Fatalf("base predicate was mutated: now has %d deps", got)
	}
}
