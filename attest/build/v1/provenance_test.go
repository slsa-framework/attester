// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	buildv1 "github.com/slsa-framework/slsa-core/predicates/build/v1"
)

func TestStatement(t *testing.T) {
	t.Parallel()
	w := New(Options{
		BuildType:            "https://ex/bt",
		BuilderID:            "https://ex/b",
		ResolvedDependencies: []*intoto.ResourceDescriptor{{Name: "dep"}},
		InvocationID:         "run-1",
	})
	stmt, err := w.Statement([]*intoto.ResourceDescriptor{{Name: "subj"}})
	if err != nil {
		t.Fatal(err)
	}
	if stmt.GetPredicateType() != PredicateTypeURI {
		t.Fatalf("predicate type: %q", stmt.GetPredicateType())
	}
	bd := stmt.GetPredicate().GetFields()["buildDefinition"].GetStructValue().GetFields()
	if bd["buildType"].GetStringValue() != "https://ex/bt" {
		t.Fatalf("buildType: %v", bd["buildType"])
	}
	if len(bd["resolvedDependencies"].GetListValue().GetValues()) != 1 {
		t.Fatalf("expected resolvedDependencies")
	}
	rd := stmt.GetPredicate().GetFields()["runDetails"].GetStructValue().GetFields()
	if rd["builder"].GetStructValue().GetFields()["id"].GetStringValue() != "https://ex/b" {
		t.Fatalf("builder id missing")
	}
}

func TestEmptyOptions(t *testing.T) {
	t.Parallel()
	stmt, err := New(Options{}).Statement(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(stmt.GetPredicate().GetFields()); n != 0 {
		t.Fatalf("expected empty predicate, got %d fields", n)
	}
}

func TestBaseNotMutated(t *testing.T) {
	t.Parallel()
	base := &buildv1.Provenance{
		BuildDefinition: &buildv1.BuildDefinition{
			ResolvedDependencies: []*intoto.ResourceDescriptor{{Name: "base"}},
		},
	}
	w := New(Options{Base: base, ResolvedDependencies: []*intoto.ResourceDescriptor{{Name: "added"}}})
	stmt, err := w.Statement(nil)
	if err != nil {
		t.Fatal(err)
	}
	deps := stmt.GetPredicate().GetFields()["buildDefinition"].GetStructValue().
		GetFields()["resolvedDependencies"].GetListValue().GetValues()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if len(base.GetBuildDefinition().GetResolvedDependencies()) != 1 {
		t.Fatalf("base mutated")
	}
}

func TestWrongBaseType(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{Base: &intoto.ResourceDescriptor{}}).Statement(nil); err == nil {
		t.Fatal("expected error for wrong base type")
	}
}
