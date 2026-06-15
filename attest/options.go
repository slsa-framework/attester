// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"io"
	"os"

	"google.golang.org/protobuf/proto"
)

// Signer abstracts envelope signing. It is a placeholder for now: the Writer
// produces bare statements and does not sign them yet. The seam lets us add
// DSSE/envelope signing later without changing the format methods.
type Signer any

// Options holds the configuration applied to a single attestation operation.
// It is populated by the functional OptFn options passed to the Attest methods.
type Options struct {
	// Writer is where the serialized attestation is written. Defaults to
	// os.Stdout.
	Writer io.Writer

	// HashAlgorithms are the digest algorithms used when hashing subject files.
	// Defaults to sha256.
	HashAlgorithms []string

	// Predicate is the predicate message to embed in the statement. Each format
	// method type-asserts it to the concrete predicate type it expects. When
	// nil, the format methods generate an empty predicate of the right type.
	Predicate proto.Message

	// Signer, when set, is used to sign the generated attestation. Unused for
	// now (see Signer).
	Signer Signer

	// BuildType and BuilderID are build provenance content fields whose name
	// and semantics are identical across provenance versions, so they are
	// shared rather than version-specific.
	BuildType string
	BuilderID string

	// ProvenanceV1 holds content specific to SLSA build provenance v1.
	ProvenanceV1 ProvenanceV1Options

	// ProvenanceV02 holds content specific to SLSA build provenance v0.2.
	ProvenanceV02 ProvenanceV02Options

	// VSAV1 holds content specific to the verification summary attestation v1.
	VSAV1 VSAV1Options
}

// defaultOptions returns the baseline Options before any OptFn is applied.
func defaultOptions() Options {
	return Options{
		Writer:         os.Stdout,
		HashAlgorithms: []string{"sha256"},
	}
}

// OptFn is a functional option mutating an Options value.
type OptFn func(*Options) error

// WithWriter sets the destination for the serialized attestation.
func WithWriter(w io.Writer) OptFn {
	return func(o *Options) error {
		o.Writer = w
		return nil
	}
}

// WithHashAlgorithms sets the digest algorithms used to hash subject files.
func WithHashAlgorithms(algos ...string) OptFn {
	return func(o *Options) error {
		o.HashAlgorithms = algos
		return nil
	}
}

// WithPredicate sets the predicate message embedded in the statement.
func WithPredicate(p proto.Message) OptFn {
	return func(o *Options) error {
		o.Predicate = p
		return nil
	}
}

// WithSigner sets the signer used to sign the attestation.
func WithSigner(s Signer) OptFn {
	return func(o *Options) error {
		o.Signer = s
		return nil
	}
}

// WithBuildType sets the build type URI. It is shared by build provenance v1
// (buildDefinition.buildType) and v0.2 (buildType).
func WithBuildType(buildType string) OptFn {
	return func(o *Options) error {
		o.BuildType = buildType
		return nil
	}
}

// WithBuilderID sets the builder id. It is shared by build provenance v1
// (runDetails.builder.id) and v0.2 (builder.id).
func WithBuilderID(id string) OptFn {
	return func(o *Options) error {
		o.BuilderID = id
		return nil
	}
}
