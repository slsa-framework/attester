// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	intoto "github.com/in-toto/attestation/go/v1"
	buildv02 "github.com/slsa-framework/slsa-core/predicates/build/v02"
	"google.golang.org/protobuf/proto"
)

// GenerateSlsaProvenanceV02Statement builds an in-toto statement carrying a SLSA
// Build provenance v0.2 predicate over the given subjects. It starts from the
// base predicate in Options.Predicate (when set) and merges the granular content
// options on top, translating shared concepts to their v0.2 field names.
func (*defaultImpl) GenerateSlsaProvenanceV02Statement(o *Options, subjects []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	base, err := predicateAs[*buildv02.Provenance](o)
	if err != nil {
		return nil, err
	}

	// Clone the base so a caller-supplied predicate is never mutated.
	predicate := &buildv02.Provenance{}
	if base != nil {
		predicate = proto.Clone(base).(*buildv02.Provenance)
	}

	mergeProvenanceV02Options(o, predicate)

	return buildStatement(PredicateTypeSlsaProvenanceV02, subjects, predicate)
}

// mergeProvenanceV02Options applies the configured v0.2 content options onto the
// predicate, creating nested messages lazily so empty options leave the
// predicate untouched.
func mergeProvenanceV02Options(o *Options, p *buildv02.Provenance) {
	v := o.ProvenanceV02

	if o.BuildType != "" {
		p.BuildType = o.BuildType
	}
	if o.BuilderID != "" {
		if p.Builder == nil {
			p.Builder = &buildv02.Builder{}
		}
		p.Builder.Id = o.BuilderID
	}

	needConfigSource := v.ConfigSourceURI != "" || len(v.ConfigSourceDigest) > 0 || v.ConfigSourceEntryPoint != ""
	if needConfigSource || v.Parameters != nil || v.Environment != nil {
		inv := p.GetInvocation()
		if inv == nil {
			inv = &buildv02.Invocation{}
			p.Invocation = inv
		}
		if needConfigSource {
			cs := inv.GetConfigSource()
			if cs == nil {
				cs = &buildv02.ConfigSource{}
				inv.ConfigSource = cs
			}
			if v.ConfigSourceURI != "" {
				cs.Uri = v.ConfigSourceURI
			}
			if len(v.ConfigSourceDigest) > 0 {
				cs.Digest = mergeStringMap(cs.Digest, v.ConfigSourceDigest)
			}
			if v.ConfigSourceEntryPoint != "" {
				cs.EntryPoint = v.ConfigSourceEntryPoint
			}
		}
		if v.Parameters != nil {
			inv.Parameters = v.Parameters
		}
		if v.Environment != nil {
			inv.Environment = v.Environment
		}
	}

	if v.BuildConfig != nil {
		p.BuildConfig = v.BuildConfig
	}

	if v.BuildInvocationID != "" || v.BuildStartedOn != nil || v.BuildFinishedOn != nil ||
		v.Completeness != nil || v.Reproducible != nil {
		m := p.GetMetadata()
		if m == nil {
			m = &buildv02.Metadata{}
			p.Metadata = m
		}
		if v.BuildInvocationID != "" {
			m.BuildInvocationId = v.BuildInvocationID
		}
		if v.BuildStartedOn != nil {
			m.BuildStartedOn = v.BuildStartedOn
		}
		if v.BuildFinishedOn != nil {
			m.BuildFinishedOn = v.BuildFinishedOn
		}
		if v.Completeness != nil {
			m.Completeness = v.Completeness
		}
		if v.Reproducible != nil {
			m.Reproducible = *v.Reproducible
		}
	}

	for _, rd := range v.Materials {
		p.Materials = append(p.Materials, resourceDescriptorToMaterial(rd))
	}
}

// resourceDescriptorToMaterial converts a ResourceDescriptor (the canonical
// resolvedDependencies shape) into the v0.2 Material shape, keeping only the
// fields a Material has.
func resourceDescriptorToMaterial(rd *intoto.ResourceDescriptor) *buildv02.Material {
	return &buildv02.Material{
		Uri:    rd.GetUri(),
		Digest: rd.GetDigest(),
	}
}
