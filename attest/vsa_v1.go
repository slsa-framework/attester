// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	intoto "github.com/in-toto/attestation/go/v1"
	vsav1 "github.com/slsa-framework/slsa-core/predicates/vsa/v1"
)

// GenerateVsaV1Statement builds an in-toto statement carrying a SLSA
// Verification Summary Attestation v1 predicate over the given subjects. The
// predicate is taken from Options.Predicate; when unset an empty summary is used.
func (*defaultImpl) GenerateVsaV1Statement(o *Options, subjects []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	predicate, err := predicateAs[*vsav1.VerificationSummary](o)
	if err != nil {
		return nil, err
	}
	if predicate == nil {
		predicate = &vsav1.VerificationSummary{}
	}
	return buildStatement(PredicateTypeVsaV1, subjects, predicate)
}
