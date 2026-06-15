// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	intoto "github.com/in-toto/attestation/go/v1"
	buildv1 "github.com/slsa-framework/slsa-core/predicates/build/v1"
	"google.golang.org/protobuf/proto"
)

// GenerateSlsaProvenanceV1Statement builds an in-toto statement carrying a SLSA
// Build provenance v1 predicate over the given subjects. It starts from the base
// predicate in Options.Predicate (when set) and merges the granular content
// options on top.
func (*defaultImpl) GenerateSlsaProvenanceV1Statement(o *Options, subjects []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	base, err := predicateAs[*buildv1.Provenance](o)
	if err != nil {
		return nil, err
	}

	// Clone the base so a caller-supplied predicate is never mutated.
	predicate := &buildv1.Provenance{}
	if base != nil {
		predicate = proto.Clone(base).(*buildv1.Provenance)
	}

	mergeProvenanceV1Options(o, predicate)

	return buildStatement(PredicateTypeSlsaProvenanceV1, subjects, predicate)
}

// mergeProvenanceV1Options applies the configured v1 content options onto the
// predicate, creating nested messages lazily so empty options leave the
// predicate untouched.
func mergeProvenanceV1Options(o *Options, p *buildv1.Provenance) {
	v1 := o.ProvenanceV1

	if o.BuildType != "" || v1.ExternalParameters != nil || v1.InternalParameters != nil || len(v1.ResolvedDependencies) > 0 {
		bd := p.GetBuildDefinition()
		if bd == nil {
			bd = &buildv1.BuildDefinition{}
			p.BuildDefinition = bd
		}
		if o.BuildType != "" {
			bd.BuildType = o.BuildType
		}
		if v1.ExternalParameters != nil {
			bd.ExternalParameters = v1.ExternalParameters
		}
		if v1.InternalParameters != nil {
			bd.InternalParameters = v1.InternalParameters
		}
		if len(v1.ResolvedDependencies) > 0 {
			bd.ResolvedDependencies = append(bd.ResolvedDependencies, v1.ResolvedDependencies...)
		}
	}

	needBuilder := o.BuilderID != "" || len(v1.BuilderVersion) > 0 || len(v1.BuilderDependencies) > 0
	needMetadata := v1.InvocationID != "" || v1.StartedOn != nil || v1.FinishedOn != nil
	if !needBuilder && !needMetadata && len(v1.Byproducts) == 0 {
		return
	}

	rd := p.GetRunDetails()
	if rd == nil {
		rd = &buildv1.RunDetails{}
		p.RunDetails = rd
	}

	if needBuilder {
		b := rd.GetBuilder()
		if b == nil {
			b = &buildv1.Builder{}
			rd.Builder = b
		}
		if o.BuilderID != "" {
			b.Id = o.BuilderID
		}
		if len(v1.BuilderVersion) > 0 {
			b.Version = mergeStringMap(b.Version, v1.BuilderVersion)
		}
		if len(v1.BuilderDependencies) > 0 {
			b.BuilderDependencies = append(b.BuilderDependencies, v1.BuilderDependencies...)
		}
	}

	if needMetadata {
		m := rd.GetMetadata()
		if m == nil {
			m = &buildv1.BuildMetadata{}
			rd.Metadata = m
		}
		if v1.InvocationID != "" {
			m.InvocationId = v1.InvocationID
		}
		if v1.StartedOn != nil {
			m.StartedOn = v1.StartedOn
		}
		if v1.FinishedOn != nil {
			m.FinishedOn = v1.FinishedOn
		}
	}

	if len(v1.Byproducts) > 0 {
		rd.Byproducts = append(rd.Byproducts, v1.Byproducts...)
	}
}
