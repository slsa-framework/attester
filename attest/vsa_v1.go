// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	intoto "github.com/in-toto/attestation/go/v1"
	vsav1 "github.com/slsa-framework/slsa-core/predicates/vsa/v1"
	"google.golang.org/protobuf/proto"
)

// GenerateVsaV1Statement builds an in-toto statement carrying a SLSA
// Verification Summary Attestation v1 predicate over the given subjects. It
// starts from the base predicate in Options.Predicate (when set) and merges the
// granular content options on top.
func (*defaultImpl) GenerateVsaV1Statement(o *Options, subjects []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	base, err := predicateAs[*vsav1.VerificationSummary](o)
	if err != nil {
		return nil, err
	}

	// Clone the base so a caller-supplied predicate is never mutated.
	predicate := &vsav1.VerificationSummary{}
	if base != nil {
		predicate = proto.Clone(base).(*vsav1.VerificationSummary)
	}

	mergeVsaV1Options(o, predicate)

	return buildStatement(PredicateTypeVsaV1, subjects, predicate)
}

// mergeVsaV1Options applies the configured VSA content options onto the
// predicate, creating nested messages lazily so empty options leave the
// predicate untouched.
func mergeVsaV1Options(o *Options, p *vsav1.VerificationSummary) {
	v := o.VSAV1

	if v.VerifierID != "" {
		if p.Verifier == nil {
			p.Verifier = &vsav1.VerificationSummary_Verifier{}
		}
		p.Verifier.Id = v.VerifierID
	}
	if v.TimeVerified != nil {
		p.TimeVerified = v.TimeVerified
	}
	if v.ResourceURI != "" {
		p.ResourceUri = v.ResourceURI
	}
	if v.PolicyURI != "" || len(v.PolicyDigest) > 0 {
		if p.Policy == nil {
			p.Policy = &vsav1.VerificationSummary_Policy{}
		}
		if v.PolicyURI != "" {
			p.Policy.Uri = v.PolicyURI
		}
		if len(v.PolicyDigest) > 0 {
			p.Policy.Digest = mergeStringMap(p.Policy.Digest, v.PolicyDigest)
		}
	}
	for _, rd := range v.InputAttestations {
		p.InputAttestations = append(p.InputAttestations, resourceDescriptorToInputAttestation(rd))
	}
	if v.VerificationResult != "" {
		p.VerificationResult = v.VerificationResult
	}
	if len(v.VerifiedLevels) > 0 {
		p.VerifiedLevels = append(p.VerifiedLevels, v.VerifiedLevels...)
	}
	if len(v.DependencyLevels) > 0 {
		p.DependencyLevels = mergeUint64Map(p.DependencyLevels, v.DependencyLevels)
	}
	if v.SlsaVersion != "" {
		p.SlsaVersion = v.SlsaVersion
	}
}

// resourceDescriptorToInputAttestation converts a ResourceDescriptor into the
// VSA InputAttestation shape, keeping only uri and digest.
func resourceDescriptorToInputAttestation(rd *intoto.ResourceDescriptor) *vsav1.VerificationSummary_InputAttestation {
	return &vsav1.VerificationSummary_InputAttestation{
		Uri:    rd.GetUri(),
		Digest: rd.GetDigest(),
	}
}
