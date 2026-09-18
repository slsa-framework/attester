// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/carabiner-dev/command/output"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/attester/attest"
	"github.com/slsa-framework/attester/internal/flagvalue"
	"github.com/slsa-framework/attester/internal/gha"
	"github.com/slsa-framework/attester/internal/sbom"
)

// addWatch attaches the "watch" subcommand to the parent command.
func addWatch(parent *cobra.Command) {
	outOpts := &output.Options{}
	var sf *signFlags
	subjects := &flagvalue.SubjectSlice{}
	checksums := &flagvalue.ChecksumFileSlice{}
	dependencies := &flagvalue.ResourceDescriptorSlice{}
	var (
		watchJobs        []string
		timeout          time.Duration
		pollInterval     time.Duration
		collectArtifacts bool
		expandArtifacts  bool
		artifactsFilter  []string
		allowSharedJob   bool
		release          string
		sboms            []string
	)

	watchCmd := &cobra.Command{
		Use:   "watch [flags] [github://owner/repo/runID]",
		Short: "Watch a GitHub Actions run and attest its results",
		Long: "Watch a GitHub Actions workflow run, wait for its jobs to complete, and\n" +
			"generate a signed SLSA build provenance attestation over the run's\n" +
			"artifacts.\n\n" +
			"With no run spec the current run is watched (from the GitHub Actions\n" +
			"environment). When watching the run it is itself part of, the watcher\n" +
			"excludes its own job and waits for every sibling job. That job must be\n" +
			"dedicated to attesting: other steps sharing it could tamper with the\n" +
			"attester or its signing identity, so the watcher refuses them.",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := outOpts.Validate(); err != nil {
				return err
			}

			spec := gha.SpecFromEnvironment()
			if len(args) == 1 {
				spec = args[0]
			}
			if spec == "" {
				return errors.New("no run spec given and not running in GitHub Actions")
			}

			client, err := gha.New(spec)
			if err != nil {
				return err
			}

			run, err := client.Wait(cmd.Context(), gha.WatchOptions{
				Jobs:           watchJobs,
				Timeout:        timeout,
				PollInterval:   pollInterval,
				AllowSharedJob: allowSharedJob,
			})
			if err != nil {
				return err
			}

			pred, err := client.Predicate(run, client.RunRef(cmd.Context(), run), client.RunInputs(cmd.Context(), run))
			if err != nil {
				return err
			}
			if len(dependencies.Values) > 0 {
				pred.BuildDefinition.ResolvedDependencies = append(
					pred.BuildDefinition.ResolvedDependencies, dependencies.Values...)
			}

			opts := []attest.OptFn{attest.WithPredicate(pred)}

			if collectArtifacts {
				subs, err := client.CollectArtifacts(cmd.Context(), gha.ArtifactOptions{
					Expand: expandArtifacts,
					Filter: artifactsFilter,
				})
				if err != nil {
					return err
				}
				opts = append(opts, attest.WithSubjects(subs...))
			}
			if release != "" {
				subs, err := client.CollectReleaseAssets(cmd.Context(), release, artifactsFilter)
				if err != nil {
					return err
				}
				opts = append(opts, attest.WithSubjects(subs...))
			}
			for _, init := range sboms {
				subs, err := sbom.CollectSubjects(cmd.Context(), init, artifactsFilter)
				if err != nil {
					return err
				}
				opts = append(opts, attest.WithSubjects(subs...))
			}
			if len(subjects.Values) > 0 {
				opts = append(opts, attest.WithSubjects(subjects.Values...))
			}
			if len(checksums.Values) > 0 {
				opts = append(opts, attest.WithSubjects(checksums.Values...))
			}

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
			err = writer.AttestSlsaProvenanceV1(nil, opts...)
			if cerr := closeWriter(w); cerr != nil && err == nil {
				err = cerr
			}
			if err != nil {
				return fmt.Errorf("attesting run: %w", err)
			}
			return nil
		},
	}

	flags := watchCmd.Flags()
	flags.StringSliceVar(&watchJobs, "watch-jobs", nil,
		"job names to watch (default: every job, minus the watcher's own)")
	flags.DurationVar(&timeout, "timeout", 20*time.Minute,
		"max time to wait for the watched jobs to complete (0 disables)")
	flags.DurationVar(&pollInterval, "poll-interval", 15*time.Second,
		"how often to poll the run's state")
	flags.BoolVar(&collectArtifacts, "collect-artifacts", true,
		"collect the run's GitHub Actions artifacts as subjects")
	flags.BoolVar(&expandArtifacts, "expand-artifacts", true,
		"unpack artifact archives and attest one subject per contained file")
	flags.StringSliceVar(&artifactsFilter, "artifacts-filter", nil,
		"glob(s) matched against artifact, release asset and SBOM element names, only matches are attested")
	flags.StringVar(&release, "release", "",
		"also attest the assets of this release (tag) in the watched repository")
	flags.StringArrayVar(&sboms, "sbom", nil,
		"collector source to fetch SBOMs from, eg fs:sboms/ or release:owner/repo@v1.0.0; their top-level elements are attested (repeatable)")
	flags.BoolVar(&allowSharedJob, "allow-shared-job", false,
		"UNSAFE: attest even when other steps share the attester's job (and its signing identity)")
	flags.Var(dependencies, "dependency",
		"an extra resolved dependency: JSON, @file, or name=,uri=,sha256= shorthand (repeatable)")
	flags.VarP(subjects, "subject", "s",
		"extra subject as algorithm:digest, eg sha256:<hex> (repeatable)")
	flags.Var(checksums, "checksums",
		"file with extra subjects in sha256sum format, one digest and name per line (repeatable)")

	outOpts.AddFlags(watchCmd)
	sf = addSignFlags(watchCmd)
	parent.AddCommand(watchCmd)
}
