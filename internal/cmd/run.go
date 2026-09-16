// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/carabiner-dev/command/output"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/attester/attest"
	"github.com/slsa-framework/attester/internal/flagvalue"
)

// attestRunE builds the RunE shared by the attestation subcommands: validate
// output, resolve the predicate version, assemble the subject, base-predicate,
// content, output and signing options, and run the attestation. The
// per-command pieces come in as callbacks.
func attestRunE(
	outOpts *output.Options,
	sf *signFlags,
	subjects *subjectFlags,
	predicate *flagvalue.RawJSON,
	predicateVersion *string,
	resolve func(string) (attest.AttestationVersion, error),
	contentOpts func(*cobra.Command) []attest.OptFn,
) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := outOpts.Validate(); err != nil {
			return err
		}
		version, err := resolve(*predicateVersion)
		if err != nil {
			return err
		}
		opts, err := subjects.attestOptions(cmd, args)
		if err != nil {
			return err
		}
		predOpts, err := predicateOptions(version, predicate)
		if err != nil {
			return err
		}
		opts = append(opts, predOpts...)
		opts = append(opts, contentOpts(cmd)...)
		w, err := outOpts.GetWriter()
		if err != nil {
			return err
		}
		opts = append(opts, attest.WithWriter(w))

		signOpts, done, err := sf.signerOptions()
		if err != nil {
			return err
		}
		defer done()
		opts = append(opts, signOpts...)

		writer := &attest.Writer{}
		return writer.Attest(version, args, opts...)
	}
}
