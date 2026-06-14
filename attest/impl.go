// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	intoto "github.com/in-toto/attestation/go/v1"
)

// attesterImpl is the internal implementation seam for the Writer. The public
// Attest* methods orchestrate calls to these atomic operations, which lets us
// mock the implementation in tests.
type attesterImpl interface {
	// ValidateOptions checks that the resolved Options are coherent.
	ValidateOptions(*Options) error

	// ReadSubjects hashes the given subject paths into resource descriptors.
	ReadSubjects(*Options, []string) ([]*intoto.ResourceDescriptor, error)

	// GenerateSlsaProvenanceV1Statement builds an in-toto statement carrying a
	// SLSA Build provenance v1 predicate.
	GenerateSlsaProvenanceV1Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error)

	// GenerateSlsaProvenanceV02Statement builds an in-toto statement carrying a
	// SLSA Build provenance v0.2 predicate.
	GenerateSlsaProvenanceV02Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error)

	// GenerateVsaV1Statement builds an in-toto statement carrying a SLSA
	// Verification Summary Attestation v1 predicate.
	GenerateVsaV1Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error)

	// Serialize renders a statement to its wire representation.
	Serialize(*Options, *intoto.Statement) ([]byte, error)

	// Write emits the serialized attestation to the configured destination.
	Write(*Options, []byte) error
}

// defaultImpl is the production implementation of attesterImpl. Its methods are
// filled in by subsequent chunks; for now they report that the operation is not
// yet implemented.
type defaultImpl struct{}

func (*defaultImpl) ValidateOptions(*Options) error {
	return nil
}

func (*defaultImpl) ReadSubjects(*Options, []string) ([]*intoto.ResourceDescriptor, error) {
	return nil, errNotImplemented("ReadSubjects")
}

func (*defaultImpl) GenerateSlsaProvenanceV1Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	return nil, errNotImplemented("GenerateSlsaProvenanceV1Statement")
}

func (*defaultImpl) GenerateSlsaProvenanceV02Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	return nil, errNotImplemented("GenerateSlsaProvenanceV02Statement")
}

func (*defaultImpl) GenerateVsaV1Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	return nil, errNotImplemented("GenerateVsaV1Statement")
}

func (*defaultImpl) Serialize(*Options, *intoto.Statement) ([]byte, error) {
	return nil, errNotImplemented("Serialize")
}

func (*defaultImpl) Write(*Options, []byte) error {
	return errNotImplemented("Write")
}
