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
	"github.com/slsa-framework/slsa-attester/internal/flagvalue"
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

// vsaFlags holds the targets the vsa command's flags write into.
type vsaFlags struct {
	verifierID         string
	timeVerified       *flagvalue.Time
	resourceURI        string
	policyURI          string
	policyDigest       *flagvalue.StringMap
	inputAttestations  *flagvalue.ResourceDescriptorSlice
	verificationResult string
	verifiedLevels     []string
	dependencyLevels   *flagvalue.Uint64Map
	slsaVersion        string
}

func newVsaFlags() *vsaFlags {
	return &vsaFlags{
		timeVerified:      &flagvalue.Time{},
		policyDigest:      &flagvalue.StringMap{},
		inputAttestations: &flagvalue.ResourceDescriptorSlice{},
		dependencyLevels:  &flagvalue.Uint64Map{},
	}
}

// addVSA attaches the "vsa" subcommand to the parent command.
func addVSA(parent *cobra.Command) {
	outOpts := &output.Options{}
	predicateVersion := "v1"
	f := newVsaFlags()
	var sf *signFlags
	var subjects *flagvalue.SubjectSlice

	vsaCmd := &cobra.Command{
		Use:   "vsa [flags] [SUBJECT_FILE...]",
		Short: "Generate a SLSA verification summary attestation (VSA)",
		Long: "Generate a SLSA verification summary attestation over one or more\n" +
			"subjects: files given as arguments are hashed and recorded in the\n" +
			"statement, and digests of artifacts not at hand can be declared with\n" +
			"-s algorithm:digest.",
		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := outOpts.Validate(); err != nil {
				return err
			}
			version, err := resolveVsaVersion(predicateVersion)
			if err != nil {
				return err
			}
			opts, err := subjectOptions(args, subjects)
			if err != nil {
				return err
			}
			opts = append(opts, vsaAttestOptions(cmd, f)...)
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
		},
	}

	outOpts.AddFlags(vsaCmd)
	registerVsaFlags(vsaCmd, &predicateVersion, f)
	subjects = addSubjectFlag(vsaCmd)
	sf = addSignFlags(vsaCmd)
	parent.AddCommand(vsaCmd)
}

// registerVsaFlags wires the VSA flags onto the command.
func registerVsaFlags(cmd *cobra.Command, predicateVersion *string, f *vsaFlags) {
	flags := cmd.Flags()

	flags.StringVar(predicateVersion, "predicate-version", *predicateVersion,
		"SLSA VSA version to generate (v1)")

	flags.StringVar(&f.verifierID, "verifier-id", "", "verifier id URI")
	flags.Var(f.timeVerified, "time-verified", "verification time, RFC3339")
	flags.StringVar(&f.resourceURI, "resource-uri", "", "URI of the resource that was verified")
	flags.StringVar(&f.policyURI, "policy-uri", "", "URI of the policy used for verification")
	flags.Var(f.policyDigest, "policy-digest", "policy digest entries key=value")
	flags.Var(f.inputAttestations, "input-attestation", "an input attestation: JSON, @file, or uri=,sha256= shorthand (repeatable)")
	flags.StringVar(&f.verificationResult, "verification-result", "", "verification result, e.g. PASSED or FAILED")
	flags.StringArrayVar(&f.verifiedLevels, "verified-level", nil, "a verified SLSA level, e.g. SLSA_BUILD_LEVEL_3 (repeatable)")
	flags.Var(f.dependencyLevels, "dependency-level", "dependency level counts key=uint (repeatable)")
	flags.StringVar(&f.slsaVersion, "slsa-version", "", "the SLSA spec version used for verification")
}

// vsaAttestOptions translates the set flags into library options.
func vsaAttestOptions(cmd *cobra.Command, f *vsaFlags) []attest.OptFn {
	changed := cmd.Flags().Changed

	var opts []attest.OptFn
	if changed("verifier-id") {
		opts = append(opts, attest.WithVerifierID(f.verifierID))
	}
	if changed("time-verified") {
		opts = append(opts, attest.WithTimeVerified(*f.timeVerified.Value))
	}
	if changed("resource-uri") {
		opts = append(opts, attest.WithResourceURI(f.resourceURI))
	}
	if changed("policy-uri") {
		opts = append(opts, attest.WithPolicyURI(f.policyURI))
	}
	if changed("policy-digest") {
		opts = append(opts, attest.WithPolicyDigest(f.policyDigest.Values))
	}
	if changed("input-attestation") {
		opts = append(opts, attest.WithInputAttestations(f.inputAttestations.Values...))
	}
	if changed("verification-result") {
		opts = append(opts, attest.WithVerificationResult(f.verificationResult))
	}
	if changed("verified-level") {
		opts = append(opts, attest.WithVerifiedLevels(f.verifiedLevels...))
	}
	if changed("dependency-level") {
		opts = append(opts, attest.WithDependencyLevels(f.dependencyLevels.Values))
	}
	if changed("slsa-version") {
		opts = append(opts, attest.WithSlsaVersion(f.slsaVersion))
	}
	return opts
}
