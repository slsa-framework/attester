// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	buildgenv02 "github.com/slsa-framework/slsa-attester/attest/build/v02"
	buildgenv1 "github.com/slsa-framework/slsa-attester/attest/build/v1"
	vsagenv1 "github.com/slsa-framework/slsa-attester/attest/vsa/v1"
)

// AttestationVersion is a typed identifier for one of the attestation formats
// (predicate type + version) the Writer knows how to generate. It is passed to
// Writer.Attest to select the format to produce.
type AttestationVersion string

const (
	// SlsaProvenanceV1 selects the SLSA Build provenance predicate, v1.
	SlsaProvenanceV1 AttestationVersion = "slsa-provenance-v1"
	// SlsaProvenanceV02 selects the SLSA Build provenance predicate, v0.2.
	SlsaProvenanceV02 AttestationVersion = "slsa-provenance-v0.2"
	// VsaV1 selects the SLSA Verification Summary Attestation predicate, v1.
	VsaV1 AttestationVersion = "vsa-v1"
)

// Predicate type URIs for the supported formats, sourced from the per-version
// generator packages so there is a single definition of each.
const (
	PredicateTypeSlsaProvenanceV1  = buildgenv1.PredicateTypeURI
	PredicateTypeSlsaProvenanceV02 = buildgenv02.PredicateTypeURI
	PredicateTypeVsaV1             = vsagenv1.PredicateTypeURI
)

// predicateTypeURI maps a known AttestationVersion to its predicate type URI.
var predicateTypeURI = map[AttestationVersion]string{
	SlsaProvenanceV1:  PredicateTypeSlsaProvenanceV1,
	SlsaProvenanceV02: PredicateTypeSlsaProvenanceV02,
	VsaV1:             PredicateTypeVsaV1,
}

// Valid returns true if v is a version the Writer can generate.
func (v AttestationVersion) Valid() bool {
	_, ok := predicateTypeURI[v]
	return ok
}

// PredicateType returns the predicate type URI for the version, or the empty
// string if the version is unknown.
func (v AttestationVersion) PredicateType() string {
	return predicateTypeURI[v]
}
