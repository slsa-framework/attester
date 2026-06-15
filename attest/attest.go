// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package attest generates in-toto attestations for the SLSA predicate types.
//
// The entry point is the Writer. It owns a single, canonical option set and maps
// it onto the per-version generator packages (attest/build/v1, attest/build/v02,
// attest/vsa/v1). Callers can dispatch on a format with Writer.Attest, or call a
// format-specific method directly to pin the output to a known version.
package attest

import (
	"errors"
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"

	buildgenv1 "github.com/slsa-framework/slsa-attester/attest/build/v1"
	buildgenv02 "github.com/slsa-framework/slsa-attester/attest/build/v02"
	vsagenv1 "github.com/slsa-framework/slsa-attester/attest/vsa/v1"
)

// ErrUnknownVersion is returned by Attest when handed a format it cannot produce.
var ErrUnknownVersion = errors.New("unknown attestation version")

// AttestationWriter is implemented by each per-version generator. Given a set of
// subjects it produces the in-toto statement carrying that version's predicate.
type AttestationWriter interface {
	PredicateType() string
	Statement(subjects []*intoto.ResourceDescriptor) (*intoto.Statement, error)
}

// Writer generates attestations. The zero value is usable; it lazily wires in
// the default implementation on first use.
type Writer struct {
	impl attesterImpl
}

// implementation returns the configured impl, defaulting to defaultImpl.
func (w *Writer) implementation() attesterImpl {
	if w.impl == nil {
		w.impl = &defaultImpl{}
	}
	return w.impl
}

// SetImplementation overrides the internal implementation (for tests).
func (w *Writer) SetImplementation(impl attesterImpl) {
	w.impl = impl
}

// Attest generates an attestation in the requested format over the given subject
// paths, dispatching to the matching format-specific method.
func (w *Writer) Attest(version AttestationVersion, subjects []string, fn ...OptFn) error {
	switch version {
	case SlsaProvenanceV1:
		return w.AttestSlsaProvenanceV1(subjects, fn...)
	case SlsaProvenanceV02:
		return w.AttestSlsaProvenanceV02(subjects, fn...)
	case VsaV1:
		return w.AttestVSAV1(subjects, fn...)
	default:
		return fmt.Errorf("%w: %q", ErrUnknownVersion, version)
	}
}

// resolveOptions applies the functional options on top of the defaults.
func resolveOptions(fn ...OptFn) (*Options, error) {
	opts := defaultOptions()
	for _, f := range fn {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}
	return &opts, nil
}

// AttestSlsaProvenanceV1 generates a SLSA build provenance v1 attestation.
func (w *Writer) AttestSlsaProvenanceV1(subjects []string, fn ...OptFn) error {
	opts, err := resolveOptions(fn...)
	if err != nil {
		return err
	}
	genOpts, err := mapToBuildV1(opts)
	if err != nil {
		return err
	}
	return w.write(opts, subjects, buildgenv1.New(genOpts))
}

// AttestSlsaProvenanceV02 generates a SLSA build provenance v0.2 attestation.
func (w *Writer) AttestSlsaProvenanceV02(subjects []string, fn ...OptFn) error {
	opts, err := resolveOptions(fn...)
	if err != nil {
		return err
	}
	genOpts, err := mapToBuildV02(opts)
	if err != nil {
		return err
	}
	return w.write(opts, subjects, buildgenv02.New(genOpts))
}

// AttestVSAV1 generates a SLSA verification summary attestation v1.
func (w *Writer) AttestVSAV1(subjects []string, fn ...OptFn) error {
	opts, err := resolveOptions(fn...)
	if err != nil {
		return err
	}
	return w.write(opts, subjects, vsagenv1.New(mapToVsaV1(opts)))
}

// write runs the version-independent pipeline: validate, hash subjects, generate
// the statement with the supplied version writer, serialize, and emit.
func (w *Writer) write(opts *Options, subjects []string, gen AttestationWriter) error {
	impl := w.implementation()
	if err := impl.ValidateOptions(opts); err != nil {
		return err
	}
	subs, err := impl.ReadSubjects(opts, subjects)
	if err != nil {
		return err
	}
	stmt, err := gen.Statement(subs)
	if err != nil {
		return err
	}
	data, err := impl.Serialize(opts, stmt)
	if err != nil {
		return err
	}
	return impl.Write(opts, data)
}
