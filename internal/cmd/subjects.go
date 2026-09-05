// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-attester/attest"
	"github.com/slsa-framework/slsa-attester/internal/flagvalue"
)

// subjectFlags holds the subject surface shared by the attestation
// subcommands: digests declared with -s/--subject and the algorithms the
// subject files given as arguments are hashed with.
type subjectFlags struct {
	subjects       *flagvalue.SubjectSlice
	hashAlgorithms []string
}

// addSubjectFlags registers the subject flags on cmd. The -s/--subject flag
// takes subjects as algorithm:digest specs, mirroring the slsa verifier's
// -s/--subject so a digest stated at attest time can be restated verbatim at
// verify time.
func addSubjectFlags(cmd *cobra.Command) *subjectFlags {
	f := &subjectFlags{subjects: &flagvalue.SubjectSlice{}}
	cmd.Flags().VarP(f.subjects, "subject", "s",
		"subject as algorithm:digest, eg sha256:<hex> (repeatable)")
	cmd.Flags().StringSliceVar(&f.hashAlgorithms, "hash-algorithms", []string{"sha256"},
		"digest algorithms to hash the subject files with")
	return f
}

// attestOptions requires at least one subject (a file argument or a --subject
// digest) and returns the attest options adding the declared digests and the
// configured hash algorithms.
func (f *subjectFlags) attestOptions(cmd *cobra.Command, args []string) ([]attest.OptFn, error) {
	if len(args) == 0 && len(f.subjects.Values) == 0 {
		return nil, errors.New("at least one subject is required: pass artifact files as arguments or --subject digests")
	}
	var opts []attest.OptFn
	if cmd.Flags().Changed("hash-algorithms") {
		opts = append(opts, attest.WithHashAlgorithms(f.hashAlgorithms...))
	}
	if len(f.subjects.Values) > 0 {
		opts = append(opts, attest.WithSubjects(f.subjects.Values...))
	}
	return opts, nil
}
