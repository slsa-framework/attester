// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"testing"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	buildv02 "github.com/slsa-framework/slsa-core/predicates/build/v02"
)

func TestProvenanceV02OptionsMerge(t *testing.T) {
	t.Parallel()
	impl := &defaultImpl{}
	started := time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC)

	o := applyOpts(t,
		WithBuildType("https://example.com/build@v0.2"),
		WithBuilderID("https://example.com/builder"),
		WithConfigSourceURI("git+https://example.com/repo"),
		WithConfigSourceDigest(map[string]string{"sha1": "abc"}),
		WithConfigSourceEntryPoint("ci.yaml"),
		WithBuildInvocationID("run-7"),
		WithBuildStartedOn(started),
		WithCompleteness(true, false, true),
		WithReproducible(true),
		WithMaterials(&intoto.ResourceDescriptor{
			Name:   "ignored-in-v02",
			Uri:    "pkg:generic/dep",
			Digest: map[string]string{"sha256": "deadbeef"},
		}),
	)

	stmt, err := impl.GenerateSlsaProvenanceV02Statement(o, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pred := stmt.GetPredicate().GetFields()

	if got := pred["buildType"].GetStringValue(); got != "https://example.com/build@v0.2" {
		t.Fatalf("buildType: %q", got)
	}
	if got := pred["builder"].GetStructValue().GetFields()["id"].GetStringValue(); got != "https://example.com/builder" {
		t.Fatalf("builder id: %q", got)
	}

	cs := pred["invocation"].GetStructValue().GetFields()["configSource"].GetStructValue().GetFields()
	if got := cs["uri"].GetStringValue(); got != "git+https://example.com/repo" {
		t.Fatalf("configSource uri: %q", got)
	}
	if got := cs["entryPoint"].GetStringValue(); got != "ci.yaml" {
		t.Fatalf("configSource entryPoint: %q", got)
	}

	meta := pred["metadata"].GetStructValue().GetFields()
	if got := meta["buildInvocationId"].GetStringValue(); got != "run-7" {
		t.Fatalf("buildInvocationId: %q", got)
	}
	if !meta["reproducible"].GetBoolValue() {
		t.Fatalf("expected reproducible true")
	}
	comp := meta["completeness"].GetStructValue().GetFields()
	if !comp["parameters"].GetBoolValue() || !comp["materials"].GetBoolValue() {
		t.Fatalf("unexpected completeness: %v", comp)
	}

	// Materials carries uri + digest (RD name is dropped).
	mats := pred["materials"].GetListValue().GetValues()
	if len(mats) != 1 {
		t.Fatalf("expected 1 material, got %d", len(mats))
	}
	mat := mats[0].GetStructValue().GetFields()
	if got := mat["uri"].GetStringValue(); got != "pkg:generic/dep" {
		t.Fatalf("material uri: %q", got)
	}
	if got := mat["digest"].GetStructValue().GetFields()["sha256"].GetStringValue(); got != "deadbeef" {
		t.Fatalf("material digest: %q", got)
	}
	if _, hasName := mat["name"]; hasName {
		t.Fatalf("v0.2 material must not carry a name field")
	}
}

// TestResolvedDependenciesVsMaterialsMapping is the marquee cross-version check:
// the same dependency surfaces as resolvedDependencies in v1 and materials in v0.2.
func TestResolvedDependenciesVsMaterialsMapping(t *testing.T) {
	t.Parallel()
	dep := &intoto.ResourceDescriptor{Uri: "pkg:generic/x", Digest: map[string]string{"sha256": "ab"}}
	impl := &defaultImpl{}

	v1Stmt, err := impl.GenerateSlsaProvenanceV1Statement(applyOpts(t, WithResolvedDependencies(dep)), nil)
	if err != nil {
		t.Fatal(err)
	}
	v1Deps := v1Stmt.GetPredicate().GetFields()["buildDefinition"].GetStructValue().
		GetFields()["resolvedDependencies"].GetListValue().GetValues()
	if len(v1Deps) != 1 {
		t.Fatalf("v1: expected resolvedDependencies, got %v", v1Stmt.GetPredicate())
	}

	v02Stmt, err := impl.GenerateSlsaProvenanceV02Statement(applyOpts(t, WithMaterials(dep)), nil)
	if err != nil {
		t.Fatal(err)
	}
	pred := v02Stmt.GetPredicate().GetFields()
	if _, hasRD := pred["resolvedDependencies"]; hasRD {
		t.Fatalf("v0.2 must not emit resolvedDependencies")
	}
	if len(pred["materials"].GetListValue().GetValues()) != 1 {
		t.Fatalf("v0.2: expected materials, got %v", pred)
	}
}

func TestProvenanceV02NoOptionsLeavesPredicateEmpty(t *testing.T) {
	t.Parallel()
	stmt, err := (&defaultImpl{}).GenerateSlsaProvenanceV02Statement(applyOpts(t), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := len(stmt.GetPredicate().GetFields()); n != 0 {
		t.Fatalf("expected empty predicate, got %d fields", n)
	}
}

func TestProvenanceV02DoesNotMutateBase(t *testing.T) {
	t.Parallel()
	base := &buildv02.Provenance{BuildType: "base"}
	o := applyOpts(t, WithPredicate(base), WithBuilderID("b"))
	if _, err := (&defaultImpl{}).GenerateSlsaProvenanceV02Statement(o, nil); err != nil {
		t.Fatal(err)
	}
	if base.GetBuilder() != nil {
		t.Fatalf("base predicate was mutated")
	}
}
