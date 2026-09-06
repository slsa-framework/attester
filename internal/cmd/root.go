// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package cmd implements the slsa-attester command line interface.
package cmd

import (
	"github.com/carabiner-dev/command/log"
	"github.com/spf13/cobra"
)

// version is the CLI version. It is overridable at build time via -ldflags.
var version = "devel"

// New builds the root command with its persistent options and subcommands wired
// in. Subcommands are attached by their respective addXxx helpers.
func New() *cobra.Command {
	logOpts := &log.Options{}

	rootCmd := &cobra.Command{
		Use:   "slsa-attester",
		Short: "Generate SLSA attestations",
		Long: "slsa-attester generates in-toto attestations for the SLSA predicate\n" +
			"types (build provenance and verification summaries).",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
		// Default to printing help when invoked with no subcommand.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := logOpts.Validate(); err != nil {
				return err
			}
			ctx, err := logOpts.WithLogger(cmd.Context())
			if err != nil {
				return err
			}
			cmd.SetContext(ctx)
			return nil
		},
	}

	logOpts.AddFlags(rootCmd)

	addBuild(rootCmd)
	addVSA(rootCmd)
	addWatch(rootCmd)

	return rootCmd
}

// Execute runs the root command. It returns the error so main can set the exit
// code cobra has already printed it to stderr.
func Execute() error {
	return New().Execute()
}
