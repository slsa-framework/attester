// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"maps"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// VSAV1Options holds the content fields for a SLSA verification summary
// attestation v1.
//
// InputAttestations accepts ResourceDescriptors (uri + digest) and is converted
// to the VSA InputAttestation shape when the predicate is generated.
type VSAV1Options struct {
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

// WithVerifierID sets verifier.id (VSA v1).
func WithVerifierID(id string) OptFn {
	return func(o *Options) error {
		o.VSAV1.VerifierID = id
		return nil
	}
}

// WithTimeVerified sets timeVerified (VSA v1).
func WithTimeVerified(t time.Time) OptFn {
	return func(o *Options) error {
		o.VSAV1.TimeVerified = timestamppb.New(t)
		return nil
	}
}

// WithResourceURI sets resourceUri (VSA v1).
func WithResourceURI(uri string) OptFn {
	return func(o *Options) error {
		o.VSAV1.ResourceURI = uri
		return nil
	}
}

// WithPolicyURI sets policy.uri (VSA v1).
func WithPolicyURI(uri string) OptFn {
	return func(o *Options) error {
		o.VSAV1.PolicyURI = uri
		return nil
	}
}

// WithPolicyDigest merges entries into policy.digest (VSA v1).
func WithPolicyDigest(digest map[string]string) OptFn {
	return func(o *Options) error {
		o.VSAV1.PolicyDigest = mergeStringMap(o.VSAV1.PolicyDigest, digest)
		return nil
	}
}

// WithInputAttestations appends to inputAttestations (VSA v1). It accepts
// ResourceDescriptors; only the uri and digest are carried into the VSA
// InputAttestation.
func WithInputAttestations(inputs ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.VSAV1.InputAttestations = append(o.VSAV1.InputAttestations, inputs...)
		return nil
	}
}

// WithVerificationResult sets verificationResult (VSA v1), e.g. "PASSED".
func WithVerificationResult(result string) OptFn {
	return func(o *Options) error {
		o.VSAV1.VerificationResult = result
		return nil
	}
}

// WithVerifiedLevels appends to verifiedLevels (VSA v1).
func WithVerifiedLevels(levels ...string) OptFn {
	return func(o *Options) error {
		o.VSAV1.VerifiedLevels = append(o.VSAV1.VerifiedLevels, levels...)
		return nil
	}
}

// WithDependencyLevels merges entries into dependencyLevels (VSA v1).
func WithDependencyLevels(levels map[string]uint64) OptFn {
	return func(o *Options) error {
		o.VSAV1.DependencyLevels = mergeUint64Map(o.VSAV1.DependencyLevels, levels)
		return nil
	}
}

// WithSlsaVersion sets slsaVersion (VSA v1).
func WithSlsaVersion(version string) OptFn {
	return func(o *Options) error {
		o.VSAV1.SlsaVersion = version
		return nil
	}
}

// mergeUint64Map returns dst with all entries from src merged in, allocating dst
// if needed. Existing keys are overwritten.
func mergeUint64Map(dst, src map[string]uint64) map[string]uint64 {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]uint64, len(src))
	}
	maps.Copy(dst, src)
	return dst
}
