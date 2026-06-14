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

// vsaVersions maps the user-facing --predicate-version values to the library's
// attestation format. "v1" is the latest and the default.
var vsaVersions = map[string]attest.AttestationVersion{
	"v1": attest.VsaV1,
}

// resolveVsaVersion maps a --predicate-version value to a format, listing the
// accepted values on error.
func resolveVsaVersion(v string) (attest.AttestationVersion, error) {
	if format, ok := vsaVersions[v]; ok {
		return format, nil
	}
	accepted := make([]string, 0, len(vsaVersions))
	for k := range vsaVersions {
		accepted = append(accepted, k)
	}
	sort.Strings(accepted)
	return "", fmt.Errorf("unsupported predicate version %q (accepted: %s)", v, strings.Join(accepted, ", "))
}

// addVSA attaches the "vsa" subcommand to the parent command.
func addVSA(parent *cobra.Command) {
	outOpts := &output.Options{}
	predicateVersion := "v1"

	vsaCmd := &cobra.Command{
		Use:   "vsa [flags] SUBJECT...",
		Short: "Generate a SLSA verification summary attestation (VSA)",
		Long: "Generate a SLSA verification summary attestation over one or more\n" +
			"subject files. Each subject is hashed and recorded in the statement.",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := outOpts.Validate(); err != nil {
				return err
			}
			version, err := resolveVsaVersion(predicateVersion)
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

	outOpts.AddFlags(vsaCmd)
	vsaCmd.Flags().StringVar(
		&predicateVersion, "predicate-version", predicateVersion,
		"SLSA VSA version to generate (v1)",
	)

	parent.AddCommand(vsaCmd)
}
