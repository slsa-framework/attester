// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	buildv1 "github.com/slsa-framework/slsa-core/predicates/build/v1"
)

// attestTo runs Attest with a buffer writer and returns the decoded statement.
func attestTo(t *testing.T, version AttestationVersion, fn ...OptFn) (map[string]any, error) {
	t.Helper()
	var buf bytes.Buffer
	w := &Writer{}
	if err := w.Attest(version, nil, append(fn, WithWriter(&buf))...); err != nil {
		return nil, err
	}
	var stmt map[string]any
	if err := json.Unmarshal(buf.Bytes(), &stmt); err != nil {
		t.Fatalf("decoding output: %v", err)
	}
	return stmt, nil
}

func TestAttestDispatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		version AttestationVersion
		want    string
	}{
		{"build v1", SlsaProvenanceV1, PredicateTypeSlsaProvenanceV1},
		{"build v0.2", SlsaProvenanceV02, PredicateTypeSlsaProvenanceV02},
		{"vsa v1", VsaV1, PredicateTypeVsaV1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stmt, err := attestTo(t, tc.version)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if stmt["predicateType"] != tc.want {
				t.Fatalf("predicateType = %v, want %v", stmt["predicateType"], tc.want)
			}
		})
	}
}

func TestAttestUnknownVersion(t *testing.T) {
	t.Parallel()
	w := &Writer{}
	err := w.Attest(AttestationVersion("nope"), nil)
	if !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("expected ErrUnknownVersion, got %v", err)
	}
}

func TestAttestOrchestrationOrder(t *testing.T) {
	t.Parallel()
	fake := &fakeImpl{}
	w := &Writer{}
	w.SetImplementation(fake)
	if err := w.AttestSlsaProvenanceV1(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCalls(t, fake.calls, []string{"ValidateOptions", "ReadSubjects", "Serialize", "Write"})
}

func TestAttestShortCircuitsOnError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		fake      *fakeImpl
		wantCalls []string
	}{
		{"validate fails", &fakeImpl{validateErr: errors.New("x")}, []string{"ValidateOptions"}},
		{"read subjects fails", &fakeImpl{subjectsErr: errors.New("x")}, []string{"ValidateOptions", "ReadSubjects"}},
		{"serialize fails", &fakeImpl{serializeErr: errors.New("x")}, []string{"ValidateOptions", "ReadSubjects", "Serialize"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := &Writer{}
			w.SetImplementation(tc.fake)
			if err := w.AttestVSAV1(nil); err == nil {
				t.Fatal("expected error")
			}
			assertCalls(t, tc.fake.calls, tc.wantCalls)
		})
	}
}

func TestAttestStatementErrorPropagates(t *testing.T) {
	t.Parallel()
	// A base predicate of the wrong concrete type makes the version writer's
	// Statement fail, after ReadSubjects and before Serialize.
	fake := &fakeImpl{}
	w := &Writer{}
	w.SetImplementation(fake)
	err := w.AttestVSAV1(nil, WithPredicate(&buildv1.Provenance{}))
	if err == nil {
		t.Fatal("expected error from statement generation")
	}
	assertCalls(t, fake.calls, []string{"ValidateOptions", "ReadSubjects"})
}

func TestOptionFnError(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	w := &Writer{}
	w.SetImplementation(&fakeImpl{})
	err := w.AttestVSAV1(nil, func(*Options) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("expected option error to propagate, got %v", err)
	}
}

func assertCalls(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("call sequence mismatch:\n got: %v\nwant: %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d: got %q want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}
