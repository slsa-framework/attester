// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	intoto "github.com/in-toto/attestation/go/v1"
	buildv1 "github.com/slsa-framework/slsa-core/predicates/build/v1"
)

// GenerateSlsaProvenanceV1Statement builds an in-toto statement carrying a SLSA
// Build provenance v1 predicate over the given subjects. The predicate is taken
// from Options.Predicate; when unset an empty provenance is used.
func (*defaultImpl) GenerateSlsaProvenanceV1Statement(o *Options, subjects []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	predicate, err := predicateAs[*buildv1.Provenance](o)
	if err != nil {
		return nil, err
	}
	if predicate == nil {
		predicate = &buildv1.Provenance{}
	}
	return buildStatement(PredicateTypeSlsaProvenanceV1, subjects, predicate)
}
