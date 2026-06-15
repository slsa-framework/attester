// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package v02

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	buildv02 "github.com/slsa-framework/slsa-core/predicates/build/v02"
)

func TestStatementMaterialsAndLegacyNames(t *testing.T) {
	t.Parallel()
	repro := true
	w := New(Options{
		BuildType:         "https://ex/bt",
		BuilderID:         "https://ex/b",
		Parameters:        nil,
		BuildInvocationID: "run-7",
		ConfigSourceURI:   "git+https://r",
		Reproducible:      &repro,
		Materials: []*intoto.ResourceDescriptor{
			{Name: "dropped", Uri: "pkg:x", Digest: map[string]string{"sha256": "ab"}},
		},
	})
	stmt, err := w.Statement(nil)
	if err != nil {
		t.Fatal(err)
	}
	pred := stmt.GetPredicate().GetFields()
	if _, ok := pred["resolvedDependencies"]; ok {
		t.Fatalf("v0.2 must not emit resolvedDependencies")
	}
	mats := pred["materials"].GetListValue().GetValues()
	if len(mats) != 1 {
		t.Fatalf("expected 1 material")
	}
	mat := mats[0].GetStructValue().GetFields()
	if mat["uri"].GetStringValue() != "pkg:x" {
		t.Fatalf("material uri: %v", mat["uri"])
	}
	if _, hasName := mat["name"]; hasName {
		t.Fatalf("material must not carry name")
	}
	meta := pred["metadata"].GetStructValue().GetFields()
	if meta["buildInvocationId"].GetStringValue() != "run-7" {
		t.Fatalf("buildInvocationId: %v", meta["buildInvocationId"])
	}
	if !meta["reproducible"].GetBoolValue() {
		t.Fatalf("expected reproducible")
	}
	cs := pred["invocation"].GetStructValue().GetFields()["configSource"].GetStructValue().GetFields()
	if cs["uri"].GetStringValue() != "git+https://r" {
		t.Fatalf("configSource uri: %v", cs["uri"])
	}
}

func TestEmptyOptions(t *testing.T) {
	t.Parallel()
	stmt, err := New(Options{}).Statement(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(stmt.GetPredicate().GetFields()); n != 0 {
		t.Fatalf("expected empty predicate, got %d", n)
	}
}

func TestWrongBaseType(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{Base: &buildv02.Material{}}).Statement(nil); err == nil {
		t.Fatal("expected error for wrong base type")
	}
}
