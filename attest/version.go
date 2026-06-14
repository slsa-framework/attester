// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

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

// Predicate type URIs for the supported formats. These live here for now and
// are expected to be upstreamed into slsa-core.
const (
	PredicateTypeSlsaProvenanceV1  = "https://slsa.dev/provenance/v1"
	PredicateTypeSlsaProvenanceV02 = "https://slsa.dev/provenance/v0.2"
	PredicateTypeVsaV1             = "https://slsa.dev/verification_summary/v1"
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
