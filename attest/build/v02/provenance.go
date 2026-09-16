// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package v02 generates SLSA build provenance v0.2 attestations. Its Options
// struct mirrors the v0.2 predicate; the main attest.Writer maps its canonical
// options onto these (e.g. resolvedDependencies -> materials).
package v02

import (
	"fmt"
	"maps"

	intoto "github.com/in-toto/attestation/go/v1"
	buildv02 "github.com/slsa-framework/protos/build/v02"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/attester/attest/internal/statement"
)

// PredicateTypeURI is the SLSA build provenance v0.2 predicate type.
const PredicateTypeURI = "https://slsa.dev/provenance/v0.2"

// Options holds the content fields for a SLSA build provenance v0.2 predicate.
// Materials accepts ResourceDescriptors (the v1 resolvedDependencies shape) and
// is converted to the v0.2 Material shape (uri + digest) when generating.
type Options struct {
	// Base, when set, is an existing *buildv02.Provenance the options are merged
	// onto. It is never mutated.
	Base proto.Message

	BuildType              string
	BuilderID              string
	Parameters             *structpb.Struct
	Environment            *structpb.Struct
	BuildConfig            *structpb.Struct
	ConfigSourceURI        string
	ConfigSourceDigest     map[string]string
	ConfigSourceEntryPoint string
	BuildInvocationID      string
	BuildStartedOn         *timestamppb.Timestamp
	BuildFinishedOn        *timestamppb.Timestamp
	Completeness           *buildv02.Completeness
	Reproducible           *bool
	Materials              []*intoto.ResourceDescriptor
}

// Writer generates build provenance v0.2 statements.
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
func (w *Writer) predicate() (*buildv02.Provenance, error) {
	p := &buildv02.Provenance{}
	if w.opts.Base != nil {
		base, ok := w.opts.Base.(*buildv02.Provenance)
		if !ok {
			return nil, fmt.Errorf("base predicate is %T, want *build.v02.Provenance", w.opts.Base)
		}
		cloned, ok := proto.Clone(base).(*buildv02.Provenance)
		if !ok {
			return nil, fmt.Errorf("cloning base predicate")
		}
		p = cloned
	}

	o := w.opts
	if o.BuildType != "" {
		p.BuildType = o.BuildType
	}
	if o.BuilderID != "" {
		if p.GetBuilder() == nil {
			p.Builder = &buildv02.Builder{}
		}
		p.Builder.Id = o.BuilderID
	}

	needConfigSource := o.ConfigSourceURI != "" || len(o.ConfigSourceDigest) > 0 || o.ConfigSourceEntryPoint != ""
	if needConfigSource || o.Parameters != nil || o.Environment != nil {
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
			if o.ConfigSourceURI != "" {
				cs.Uri = o.ConfigSourceURI
			}
			if len(o.ConfigSourceDigest) > 0 {
				if cs.Digest == nil {
					cs.Digest = map[string]string{}
				}
				maps.Copy(cs.GetDigest(), o.ConfigSourceDigest)
			}
			if o.ConfigSourceEntryPoint != "" {
				cs.EntryPoint = o.ConfigSourceEntryPoint
			}
		}
		if o.Parameters != nil {
			inv.Parameters = o.Parameters
		}
		if o.Environment != nil {
			inv.Environment = o.Environment
		}
	}

	if o.BuildConfig != nil {
		p.BuildConfig = o.BuildConfig
	}

	if o.BuildInvocationID != "" || o.BuildStartedOn != nil || o.BuildFinishedOn != nil ||
		o.Completeness != nil || o.Reproducible != nil {
		m := p.GetMetadata()
		if m == nil {
			m = &buildv02.Metadata{}
			p.Metadata = m
		}
		if o.BuildInvocationID != "" {
			m.BuildInvocationId = o.BuildInvocationID
		}
		if o.BuildStartedOn != nil {
			m.BuildStartedOn = o.BuildStartedOn
		}
		if o.BuildFinishedOn != nil {
			m.BuildFinishedOn = o.BuildFinishedOn
		}
		if o.Completeness != nil {
			m.Completeness = o.Completeness
		}
		if o.Reproducible != nil {
			m.Reproducible = *o.Reproducible
		}
	}

	for _, rd := range o.Materials {
		p.Materials = append(p.Materials, &buildv02.Material{
			Uri:    rd.GetUri(),
			Digest: rd.GetDigest(),
		})
	}

	return p, nil
}
