// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io"
	"os"

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
		err = writer.Attest(version, args, opts...)
		if cerr := closeWriter(w); cerr != nil && err == nil {
			err = cerr
		}
		return err
	}
}

// closeWriter closes the output writer when it owns a file handle. GetWriter
// hands out os.Stdout when no output path is set, and stdout is not ours to
// close. Leaving the handle open would leak it and, on Windows, keep the
// output file locked.
func closeWriter(w io.Writer) error {
	if w == os.Stdout {
		return nil
	}
	if c, ok := w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
