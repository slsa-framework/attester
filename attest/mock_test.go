// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import intoto "github.com/in-toto/attestation/go/v1"

// fakeImpl is a hand-written test double for attesterImpl. It records the order
// in which its methods are invoked and returns programmable canned values, so
// tests can assert orchestration without touching the filesystem.
type fakeImpl struct {
	calls []string

	validateErr error

	subjects    []*intoto.ResourceDescriptor
	subjectsErr error

	data         []byte
	serializeErr error

	writeErr error
}

func (f *fakeImpl) ValidateOptions(*Options) error {
	f.calls = append(f.calls, "ValidateOptions")
	return f.validateErr
}

func (f *fakeImpl) ReadSubjects(*Options, []string) ([]*intoto.ResourceDescriptor, error) {
	f.calls = append(f.calls, "ReadSubjects")
	return f.subjects, f.subjectsErr
}

func (f *fakeImpl) Serialize(*Options, *intoto.Statement) ([]byte, error) {
	f.calls = append(f.calls, "Serialize")
	return f.data, f.serializeErr
}

func (f *fakeImpl) Write(*Options, []byte) error {
	f.calls = append(f.calls, "Write")
	return f.writeErr
}
