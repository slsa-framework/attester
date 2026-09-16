// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/carabiner-dev/signer"
	signeroptions "github.com/carabiner-dev/signer/options"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/attester/attest"
)

// signFlags holds the signing surface shared by the attestation subcommands:
// the --sign switch plus the signer library's flag set (--signing-backend,
// --signing-key, the sigstore flags, etc).
type signFlags struct {
	sign bool
	set  *signeroptions.SignerSet
}

// addSignFlags registers the signing flags on cmd. Signing defaults to on with
// the sigstore backend: ambient credentials (CI OIDC tokens) are used when
// detected, falling back to the interactive browser flow. Passing --signing-key
// switches to the key backend, which emits a DSSE-wrapped attestation. SPIFFE
// is not exposed for now.
func addSignFlags(cmd *cobra.Command) *signFlags {
	f := &signFlags{sign: true, set: signeroptions.DefaultSignerSet()}
	f.set.Spiffe = nil
	cmd.Flags().BoolVar(&f.sign, "sign", true,
		"sign the attestation (sigstore by default, keys with --signing-key)")
	f.set.AddFlags(cmd)
	return f
}

// signerOptions validates the signing flags and returns the attest options
// arming the signer, plus a cleanup func to call after attesting. With
// --sign=false it returns no options and the attestation is emitted unsigned.
func (f *signFlags) signerOptions() ([]attest.OptFn, func(), error) {
	if !f.sign {
		return nil, func() {}, nil
	}
	if f.set.Backend == string(signeroptions.BackendSpiffe) {
		return nil, nil, errors.New("the spiffe signing backend is not supported yet")
	}
	if err := f.set.Validate(); err != nil {
		return nil, nil, err
	}
	s, err := signer.NewSignerFromSet(f.set)
	if err != nil {
		return nil, nil, err
	}
	return []attest.OptFn{attest.WithSigner(s)}, func() { s.Close() }, nil //nolint:errcheck,gosec // nothing to handle at cleanup
}
