// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"testing"
)

func TestAttestDispatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		version  AttestationVersion
		wantGen  string
		wantErr  bool
		errIsUnk bool
	}{
		{name: "build v1", version: SlsaProvenanceV1, wantGen: "GenerateSlsaProvenanceV1Statement"},
		{name: "build v0.2", version: SlsaProvenanceV02, wantGen: "GenerateSlsaProvenanceV02Statement"},
		{name: "vsa v1", version: VsaV1, wantGen: "GenerateVsaV1Statement"},
		{name: "unknown", version: AttestationVersion("nope"), wantErr: true, errIsUnk: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeImpl{}
			w := &Writer{}
			w.SetImplementation(fake)

			err := w.Attest(tc.version, []string{"a"})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errIsUnk && !errors.Is(err, ErrUnknownVersion) {
					t.Fatalf("expected ErrUnknownVersion, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertCalls(t, fake.calls, []string{
				"ValidateOptions", "ReadSubjects", tc.wantGen, "Serialize", "Write",
			})
		})
	}
}

func TestAttestShortCircuitsOnError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		fake      *fakeImpl
		wantCalls []string
	}{
		{
			name:      "validate fails",
			fake:      &fakeImpl{validateErr: errors.New("bad opts")},
			wantCalls: []string{"ValidateOptions"},
		},
		{
			name:      "read subjects fails",
			fake:      &fakeImpl{subjectsErr: errors.New("hash error")},
			wantCalls: []string{"ValidateOptions", "ReadSubjects"},
		},
		{
			name:      "generate fails",
			fake:      &fakeImpl{genErr: errors.New("gen error")},
			wantCalls: []string{"ValidateOptions", "ReadSubjects", "GenerateVsaV1Statement"},
		},
		{
			name:      "serialize fails",
			fake:      &fakeImpl{serializeErr: errors.New("ser error")},
			wantCalls: []string{"ValidateOptions", "ReadSubjects", "GenerateVsaV1Statement", "Serialize"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := &Writer{}
			w.SetImplementation(tc.fake)
			if err := w.AttestVSAV1([]string{"a"}); err == nil {
				t.Fatal("expected error, got nil")
			}
			assertCalls(t, tc.fake.calls, tc.wantCalls)
		})
	}
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
			t.Fatalf("call %d mismatch: got %q want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}
