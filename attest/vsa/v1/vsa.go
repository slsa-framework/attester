// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package v1 generates SLSA verification summary attestations (VSA) v1. Its
// Options struct mirrors the VSA v1 predicate; the main attest.Writer maps its
// canonical options onto these.
package v1

import (
	"fmt"
	"maps"

	intoto "github.com/in-toto/attestation/go/v1"
	vsav1 "github.com/slsa-framework/protos/vsa/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/attester/attest/internal/statement"
)

// PredicateTypeURI is the SLSA verification summary attestation v1 predicate type.
const PredicateTypeURI = "https://slsa.dev/verification_summary/v1"

// Options holds the content fields for a VSA v1 predicate. InputAttestations
// accepts ResourceDescriptors (uri + digest) and is converted to the VSA
// InputAttestation shape when generating.
type Options struct {
	// Base, when set, is an existing *vsav1.VerificationSummary the options are
	// merged onto. It is never mutated.
	Base proto.Message

	VerifierID         string
	TimeVerified       *timestamppb.Timestamp
	ResourceURI        string
	PolicyURI          string
	PolicyDigest       map[string]string
	InputAttestations  []*intoto.ResourceDescriptor
	VerificationResult string
	VerifiedLevels     []string
	DependencyLevels   map[string]uint64
	SlsaVersion        string
}

// Writer generates VSA v1 statements.
type Writer struct {
	opts Options
}

// New returns a Writer configured with opts. A nil opts is treated as empty.
func New(opts *Options) *Writer {
	if opts == nil {
		opts = &Options{}
	}
	return &Writer{opts: *opts}
}

// PredicateType returns the predicate type URI.
func (*Writer) PredicateType() string { return PredicateTypeURI }

// Statement builds the in-toto statement over the given subjects.
func (w *Writer) Statement(subjects []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	predicate, err := w.predicate()
	if err != nil {
		return nil, err
	}
	return statement.Build(PredicateTypeURI, subjects, predicate)
}

// predicate clones any base and merges the options onto it.
func (w *Writer) predicate() (*vsav1.VerificationSummary, error) {
	p := &vsav1.VerificationSummary{}
	if w.opts.Base != nil {
		base, ok := w.opts.Base.(*vsav1.VerificationSummary)
		if !ok {
			return nil, fmt.Errorf("base predicate is %T, want *vsa.v1.VerificationSummary", w.opts.Base)
		}
		cloned, ok := proto.Clone(base).(*vsav1.VerificationSummary)
		if !ok {
			return nil, fmt.Errorf("cloning base predicate")
		}
		p = cloned
	}

	o := w.opts
	if o.VerifierID != "" {
		if p.GetVerifier() == nil {
			p.Verifier = &vsav1.VerificationSummary_Verifier{}
		}
		p.Verifier.Id = o.VerifierID
	}
	if o.TimeVerified != nil {
		p.TimeVerified = o.TimeVerified
	}
	if o.ResourceURI != "" {
		p.ResourceUri = o.ResourceURI
	}
	if o.PolicyURI != "" || len(o.PolicyDigest) > 0 {
		if p.GetPolicy() == nil {
			p.Policy = &vsav1.VerificationSummary_Policy{}
		}
		if o.PolicyURI != "" {
			p.Policy.Uri = o.PolicyURI
		}
		if len(o.PolicyDigest) > 0 {
			if p.Policy.Digest == nil {
				p.Policy.Digest = map[string]string{}
			}
			maps.Copy(p.GetPolicy().GetDigest(), o.PolicyDigest)
		}
	}
	for _, rd := range o.InputAttestations {
		p.InputAttestations = append(p.InputAttestations, &vsav1.VerificationSummary_InputAttestation{
			Uri:    rd.GetUri(),
			Digest: rd.GetDigest(),
		})
	}
	if o.VerificationResult != "" {
		p.VerificationResult = o.VerificationResult
	}
	if len(o.VerifiedLevels) > 0 {
		p.VerifiedLevels = append(p.VerifiedLevels, o.VerifiedLevels...)
	}
	if len(o.DependencyLevels) > 0 {
		if p.DependencyLevels == nil {
			p.DependencyLevels = map[string]uint64{}
		}
		maps.Copy(p.GetDependencyLevels(), o.DependencyLevels)
	}
	if o.SlsaVersion != "" {
		p.SlsaVersion = o.SlsaVersion
	}

	return p, nil
}
