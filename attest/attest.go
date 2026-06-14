// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package attest generates in-toto attestations for the SLSA predicate types.
//
// The entry point is the Writer. Callers can dispatch on a format with
// Writer.Attest, or call a format-specific method directly (for example
// Writer.AttestSlsaProvenanceV1) to pin the output to a known version.
package attest

import (
	"errors"
	"fmt"
)

// ErrUnknownVersion is returned by Attest when handed a format it cannot
// produce.
var ErrUnknownVersion = errors.New("unknown attestation version")

// errNotImplemented builds a placeholder error for unimplemented impl methods.
func errNotImplemented(op string) error {
	return fmt.Errorf("%s: not implemented yet", op)
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

// SetImplementation overrides the internal implementation. It is intended for
// tests that supply a mock.
func (w *Writer) SetImplementation(impl attesterImpl) {
	w.impl = impl
}

// Attest generates an attestation in the requested format over the given
// subject paths, dispatching to the matching format-specific method.
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

// AttestSlsaProvenanceV1 generates a SLSA Build provenance v1 attestation.
func (w *Writer) AttestSlsaProvenanceV1(subjects []string, fn ...OptFn) error {
	opts, err := resolveOptions(fn...)
	if err != nil {
		return err
	}
	impl := w.implementation()
	if err := impl.ValidateOptions(opts); err != nil {
		return err
	}
	subs, err := impl.ReadSubjects(opts, subjects)
	if err != nil {
		return err
	}
	stmt, err := impl.GenerateSlsaProvenanceV1Statement(opts, subs)
	if err != nil {
		return err
	}
	data, err := impl.Serialize(opts, stmt)
	if err != nil {
		return err
	}
	return impl.Write(opts, data)
}

// AttestSlsaProvenanceV02 generates a SLSA Build provenance v0.2 attestation.
func (w *Writer) AttestSlsaProvenanceV02(subjects []string, fn ...OptFn) error {
	opts, err := resolveOptions(fn...)
	if err != nil {
		return err
	}
	impl := w.implementation()
	if err := impl.ValidateOptions(opts); err != nil {
		return err
	}
	subs, err := impl.ReadSubjects(opts, subjects)
	if err != nil {
		return err
	}
	stmt, err := impl.GenerateSlsaProvenanceV02Statement(opts, subs)
	if err != nil {
		return err
	}
	data, err := impl.Serialize(opts, stmt)
	if err != nil {
		return err
	}
	return impl.Write(opts, data)
}

// AttestVSAV1 generates a SLSA Verification Summary Attestation v1.
func (w *Writer) AttestVSAV1(subjects []string, fn ...OptFn) error {
	opts, err := resolveOptions(fn...)
	if err != nil {
		return err
	}
	impl := w.implementation()
	if err := impl.ValidateOptions(opts); err != nil {
		return err
	}
	subs, err := impl.ReadSubjects(opts, subjects)
	if err != nil {
		return err
	}
	stmt, err := impl.GenerateVsaV1Statement(opts, subs)
	if err != nil {
		return err
	}
	data, err := impl.Serialize(opts, stmt)
	if err != nil {
		return err
	}
	return impl.Write(opts, data)
}
