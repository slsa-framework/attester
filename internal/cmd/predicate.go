// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/slsa-framework/slsa-attester/attest"
	"github.com/slsa-framework/slsa-attester/internal/flagvalue"
)

// predicateOptions parses the --predicate base into the official SLSA
// predicate proto for the selected version and returns the option arming it.
// Parsing is strict, so a predicate that does not match the proto is rejected.
func predicateOptions(version attest.AttestationVersion, raw *flagvalue.RawJSON) ([]attest.OptFn, error) {
	if raw == nil || raw.Data == nil {
		return nil, nil
	}
	p, err := attest.ParsePredicate(version, raw.Data)
	if err != nil {
		return nil, err
	}
	return []attest.OptFn{attest.WithPredicate(p)}, nil
}
