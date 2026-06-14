// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	intoto "github.com/in-toto/attestation/go/v1"
	buildv02 "github.com/slsa-framework/slsa-core/predicates/build/v02"
)

// GenerateSlsaProvenanceV02Statement builds an in-toto statement carrying a SLSA
// Build provenance v0.2 predicate over the given subjects. The predicate is
// taken from Options.Predicate; when unset an empty provenance is used.
func (*defaultImpl) GenerateSlsaProvenanceV02Statement(o *Options, subjects []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	predicate, err := predicateAs[*buildv02.Provenance](o)
	if err != nil {
		return nil, err
	}
	if predicate == nil {
		predicate = &buildv02.Provenance{}
	}
	return buildStatement(PredicateTypeSlsaProvenanceV02, subjects, predicate)
}
