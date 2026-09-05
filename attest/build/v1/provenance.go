// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package v1 generates SLSA build provenance v1 attestations. Its Options struct
// mirrors the v1 predicate; the main attest.Writer maps its canonical options
// onto these.
package v1

import (
	"fmt"
	"maps"

	intoto "github.com/in-toto/attestation/go/v1"
	buildv1 "github.com/slsa-framework/protos/build/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/slsa-attester/attest/internal/statement"
)

// PredicateTypeURI is the SLSA build provenance v1 predicate type.
const PredicateTypeURI = "https://slsa.dev/provenance/v1"

// Options holds the content fields for a SLSA build provenance v1 predicate.
type Options struct {
	// Base, when set, is an existing *buildv1.Provenance the options are merged
	// onto. It is never mutated.
	Base proto.Message

	BuildType            string
	BuilderID            string
	ExternalParameters   *structpb.Struct
	InternalParameters   *structpb.Struct
	ResolvedDependencies []*intoto.ResourceDescriptor
	BuilderVersion       map[string]string
	BuilderDependencies  []*intoto.ResourceDescriptor
	Byproducts           []*intoto.ResourceDescriptor
	InvocationID         string
	StartedOn            *timestamppb.Timestamp
	FinishedOn           *timestamppb.Timestamp
}

// Writer generates build provenance v1 statements.
type Writer struct {
	opts Options
}

// New returns a Writer configured with opts.
func New(opts Options) *Writer {
	return &Writer{opts: opts}
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

// predicate clones any base and merges the options onto it, creating nested
// messages lazily so empty options leave the predicate untouched.
func (w *Writer) predicate() (*buildv1.Provenance, error) {
	p := &buildv1.Provenance{}
	if w.opts.Base != nil {
		base, ok := w.opts.Base.(*buildv1.Provenance)
		if !ok {
			return nil, fmt.Errorf("base predicate is %T, want *build.v1.Provenance", w.opts.Base)
		}
		p = proto.Clone(base).(*buildv1.Provenance)
	}

	o := w.opts
	if o.BuildType != "" || o.ExternalParameters != nil || o.InternalParameters != nil || len(o.ResolvedDependencies) > 0 {
		bd := p.GetBuildDefinition()
		if bd == nil {
			bd = &buildv1.BuildDefinition{}
			p.BuildDefinition = bd
		}
		if o.BuildType != "" {
			bd.BuildType = o.BuildType
		}
		if o.ExternalParameters != nil {
			bd.ExternalParameters = o.ExternalParameters
		}
		if o.InternalParameters != nil {
			bd.InternalParameters = o.InternalParameters
		}
		if len(o.ResolvedDependencies) > 0 {
			bd.ResolvedDependencies = append(bd.ResolvedDependencies, o.ResolvedDependencies...)
		}
	}

	needBuilder := o.BuilderID != "" || len(o.BuilderVersion) > 0 || len(o.BuilderDependencies) > 0
	needMetadata := o.InvocationID != "" || o.StartedOn != nil || o.FinishedOn != nil
	if !needBuilder && !needMetadata && len(o.Byproducts) == 0 {
		return p, nil
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
		if len(o.BuilderVersion) > 0 {
			if b.Version == nil {
				b.Version = map[string]string{}
			}
			maps.Copy(b.Version, o.BuilderVersion)
		}
		if len(o.BuilderDependencies) > 0 {
			b.BuilderDependencies = append(b.BuilderDependencies, o.BuilderDependencies...)
		}
	}

	if needMetadata {
		m := rd.GetMetadata()
		if m == nil {
			m = &buildv1.BuildMetadata{}
			rd.Metadata = m
		}
		if o.InvocationID != "" {
			m.InvocationId = o.InvocationID
		}
		if o.StartedOn != nil {
			m.StartedOn = o.StartedOn
		}
		if o.FinishedOn != nil {
			m.FinishedOn = o.FinishedOn
		}
	}

	if len(o.Byproducts) > 0 {
		rd.Byproducts = append(rd.Byproducts, o.Byproducts...)
	}

	return p, nil
}
