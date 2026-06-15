// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"maps"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProvenanceV1Options holds the SLSA build provenance v1 content fields that do
// not have an identically named counterpart in v0.2. Fields shared verbatim
// with v0.2 (build type, builder id) live on Options directly.
type ProvenanceV1Options struct {
	ExternalParameters   *structpb.Struct
	InternalParameters   *structpb.Struct
	ResolvedDependencies []*intoto.ResourceDescriptor
	BuilderVersion       map[string]string
	BuilderDependencies  []*intoto.ResourceDescriptor
	InvocationID         string
	StartedOn            *timestamppb.Timestamp
	FinishedOn           *timestamppb.Timestamp
	Byproducts           []*intoto.ResourceDescriptor
}

// WithExternalParameters sets buildDefinition.externalParameters (v1).
func WithExternalParameters(s *structpb.Struct) OptFn {
	return func(o *Options) error {
		o.ProvenanceV1.ExternalParameters = s
		return nil
	}
}

// WithInternalParameters sets buildDefinition.internalParameters (v1).
func WithInternalParameters(s *structpb.Struct) OptFn {
	return func(o *Options) error {
		o.ProvenanceV1.InternalParameters = s
		return nil
	}
}

// WithResolvedDependencies appends to buildDefinition.resolvedDependencies (v1).
func WithResolvedDependencies(deps ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.ProvenanceV1.ResolvedDependencies = append(o.ProvenanceV1.ResolvedDependencies, deps...)
		return nil
	}
}

// WithBuilderVersion merges entries into runDetails.builder.version (v1).
func WithBuilderVersion(version map[string]string) OptFn {
	return func(o *Options) error {
		o.ProvenanceV1.BuilderVersion = mergeStringMap(o.ProvenanceV1.BuilderVersion, version)
		return nil
	}
}

// WithBuilderDependencies appends to runDetails.builder.builderDependencies (v1).
func WithBuilderDependencies(deps ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.ProvenanceV1.BuilderDependencies = append(o.ProvenanceV1.BuilderDependencies, deps...)
		return nil
	}
}

// WithInvocationID sets runDetails.metadata.invocationId (v1).
func WithInvocationID(id string) OptFn {
	return func(o *Options) error {
		o.ProvenanceV1.InvocationID = id
		return nil
	}
}

// WithStartedOn sets runDetails.metadata.startedOn (v1).
func WithStartedOn(t time.Time) OptFn {
	return func(o *Options) error {
		o.ProvenanceV1.StartedOn = timestamppb.New(t)
		return nil
	}
}

// WithFinishedOn sets runDetails.metadata.finishedOn (v1).
func WithFinishedOn(t time.Time) OptFn {
	return func(o *Options) error {
		o.ProvenanceV1.FinishedOn = timestamppb.New(t)
		return nil
	}
}

// WithByproducts appends to runDetails.byproducts (v1).
func WithByproducts(deps ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.ProvenanceV1.Byproducts = append(o.ProvenanceV1.Byproducts, deps...)
		return nil
	}
}

// mergeStringMap returns dst with all entries from src merged in, allocating dst
// if needed. Existing keys are overwritten.
func mergeStringMap(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	maps.Copy(dst, src)
	return dst
}
