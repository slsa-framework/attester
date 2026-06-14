// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/carabiner-dev/command/output"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-attester/attest"
)

// buildProvenanceVersions maps the user-facing --predicate-version values to the
// library's attestation format. "v1" is the latest and the default.
var buildProvenanceVersions = map[string]attest.AttestationVersion{
	"v1":   attest.SlsaProvenanceV1,
	"v0.2": attest.SlsaProvenanceV02,
}

// resolveBuildVersion maps a --predicate-version value to a format, listing the
// accepted values on error.
func resolveBuildVersion(v string) (attest.AttestationVersion, error) {
	if format, ok := buildProvenanceVersions[v]; ok {
		return format, nil
	}
	accepted := make([]string, 0, len(buildProvenanceVersions))
	for k := range buildProvenanceVersions {
		accepted = append(accepted, k)
	}
	sort.Strings(accepted)
	return "", fmt.Errorf("unsupported predicate version %q (accepted: %s)", v, strings.Join(accepted, ", "))
}

// addBuild attaches the "build" subcommand to the parent command.
func addBuild(parent *cobra.Command) {
	outOpts := &output.Options{}
	predicateVersion := "v1"

	buildCmd := &cobra.Command{
		Use:   "build [flags] SUBJECT...",
		Short: "Generate a SLSA build provenance attestation",
		Long: "Generate a SLSA build provenance attestation over one or more subject\n" +
			"files. Each subject is hashed and recorded in the statement.",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := outOpts.Validate(); err != nil {
				return err
			}
			version, err := resolveBuildVersion(predicateVersion)
			if err != nil {
				return err
			}
			w, err := outOpts.GetWriter()
			if err != nil {
				return err
			}
			writer := &attest.Writer{}
			return writer.Attest(version, args, attest.WithWriter(w))
		},
	}

	outOpts.AddFlags(buildCmd)
	buildCmd.Flags().StringVar(
		&predicateVersion, "predicate-version", predicateVersion,
		"SLSA build provenance version to generate (v1, v0.2)",
	)

	parent.AddCommand(buildCmd)
}
