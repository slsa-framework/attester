// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	buildv02 "github.com/slsa-framework/slsa-core/predicates/build/v02"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProvenanceV02Options holds the SLSA build provenance v0.2 content fields that
// do not have an identically named counterpart in v1. Fields shared verbatim
// with v1 (build type, builder id) live on Options directly.
//
// Materials is the v0.2 analog of v1's resolvedDependencies: it accepts the same
// ResourceDescriptor input and is converted to the v0.2 Material shape (uri +
// digest) when the predicate is generated.
type ProvenanceV02Options struct {
	ConfigSourceURI        string
	ConfigSourceDigest     map[string]string
	ConfigSourceEntryPoint string
	Parameters             *structpb.Struct
	Environment            *structpb.Struct
	BuildConfig            *structpb.Struct
	BuildInvocationID      string
	BuildStartedOn         *timestamppb.Timestamp
	BuildFinishedOn        *timestamppb.Timestamp
	Completeness           *buildv02.Completeness
	Reproducible           *bool
	Materials              []*intoto.ResourceDescriptor
}

// WithConfigSourceURI sets invocation.configSource.uri (v0.2).
func WithConfigSourceURI(uri string) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.ConfigSourceURI = uri
		return nil
	}
}

// WithConfigSourceDigest merges entries into invocation.configSource.digest (v0.2).
func WithConfigSourceDigest(digest map[string]string) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.ConfigSourceDigest = mergeStringMap(o.ProvenanceV02.ConfigSourceDigest, digest)
		return nil
	}
}

// WithConfigSourceEntryPoint sets invocation.configSource.entryPoint (v0.2).
func WithConfigSourceEntryPoint(entryPoint string) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.ConfigSourceEntryPoint = entryPoint
		return nil
	}
}

// WithParameters sets invocation.parameters (v0.2).
func WithParameters(s *structpb.Struct) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.Parameters = s
		return nil
	}
}

// WithEnvironment sets invocation.environment (v0.2).
func WithEnvironment(s *structpb.Struct) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.Environment = s
		return nil
	}
}

// WithBuildConfig sets buildConfig (v0.2).
func WithBuildConfig(s *structpb.Struct) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.BuildConfig = s
		return nil
	}
}

// WithBuildInvocationID sets metadata.buildInvocationId (v0.2).
func WithBuildInvocationID(id string) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.BuildInvocationID = id
		return nil
	}
}

// WithBuildStartedOn sets metadata.buildStartedOn (v0.2).
func WithBuildStartedOn(t time.Time) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.BuildStartedOn = timestamppb.New(t)
		return nil
	}
}

// WithBuildFinishedOn sets metadata.buildFinishedOn (v0.2).
func WithBuildFinishedOn(t time.Time) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.BuildFinishedOn = timestamppb.New(t)
		return nil
	}
}

// WithCompleteness sets metadata.completeness (v0.2).
func WithCompleteness(parameters, environment, materials bool) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.Completeness = &buildv02.Completeness{
			Parameters:  parameters,
			Environment: environment,
			Materials:   materials,
		}
		return nil
	}
}

// WithReproducible sets metadata.reproducible (v0.2).
func WithReproducible(reproducible bool) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.Reproducible = &reproducible
		return nil
	}
}

// WithMaterials appends to materials (v0.2). It accepts ResourceDescriptors (the
// v1 resolvedDependencies shape); only the uri and digest are carried into the
// v0.2 Material.
func WithMaterials(materials ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.ProvenanceV02.Materials = append(o.ProvenanceV02.Materials, materials...)
		return nil
	}
}
