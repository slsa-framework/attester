// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/carabiner-dev/command/output"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-attester/attest"
	"github.com/slsa-framework/slsa-attester/internal/flagvalue"
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

// buildFlags holds the targets the build command's flags write into. The flag
// names are canonical (modern, v1-style); the value is mapped to the field
// appropriate for the selected predicate version at run time.
type buildFlags struct {
	predicate *flagvalue.RawJSON

	buildType string
	builderID string

	externalParameters *flagvalue.Struct
	internalParameters *flagvalue.Struct
	resolvedDeps       *flagvalue.ResourceDescriptorSlice
	builderVersion     *flagvalue.StringMap
	builderDeps        *flagvalue.ResourceDescriptorSlice
	invocationID       string
	startedOn          *flagvalue.Time
	finishedOn         *flagvalue.Time
	byproducts         *flagvalue.ResourceDescriptorSlice

	// v0.2-only (hidden) fields.
	configSourceURI        string
	configSourceDigest     *flagvalue.StringMap
	configSourceEntryPoint string
	environment            *flagvalue.Struct
	buildConfig            *flagvalue.Struct
	reproducible           bool
	completenessParams     bool
	completenessEnv        bool
	completenessMaterials  bool
}

func newBuildFlags() *buildFlags {
	return &buildFlags{
		predicate:          &flagvalue.RawJSON{},
		externalParameters: &flagvalue.Struct{},
		internalParameters: &flagvalue.Struct{},
		resolvedDeps:       &flagvalue.ResourceDescriptorSlice{},
		builderVersion:     &flagvalue.StringMap{},
		builderDeps:        &flagvalue.ResourceDescriptorSlice{},
		startedOn:          &flagvalue.Time{},
		finishedOn:         &flagvalue.Time{},
		byproducts:         &flagvalue.ResourceDescriptorSlice{},
		configSourceDigest: &flagvalue.StringMap{},
		environment:        &flagvalue.Struct{},
		buildConfig:        &flagvalue.Struct{},
	}
}

// addBuild attaches the "build" subcommand to the parent command.
func addBuild(parent *cobra.Command) {
	outOpts := &output.Options{}
	predicateVersion := "v1"
	f := newBuildFlags()

	buildCmd := &cobra.Command{
		Use:   "build [flags] [SUBJECT_FILE...]",
		Short: "Generate a SLSA build provenance attestation",
		Long: "Generate a SLSA build provenance attestation over one or more subjects:\n" +
			"files given as arguments are hashed and recorded in the statement, and\n" +
			"digests of artifacts not at hand can be declared with -s algorithm:digest.\n\n" +
			"Flags use the latest (v1) terminology. When an older predicate version is\n" +
			"selected with --predicate-version, equivalent fields are mapped to the\n" +
			"older names automatically.",
		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
	}

	outOpts.AddFlags(buildCmd)
	registerBuildFlags(buildCmd, &predicateVersion, f)
	subjects := addSubjectFlags(buildCmd)
	sf := addSignFlags(buildCmd)
	buildCmd.RunE = attestRunE(outOpts, sf, subjects, f.predicate, &predicateVersion,
		resolveBuildVersion, func(cmd *cobra.Command) []attest.OptFn {
			return buildAttestOptions(cmd, f)
		})
	parent.AddCommand(buildCmd)
}

// registerBuildFlags wires the canonical flags, hidden legacy aliases, and
// hidden v0.2-only flags onto the command.
func registerBuildFlags(cmd *cobra.Command, predicateVersion *string, f *buildFlags) {
	flags := cmd.Flags()

	flags.StringVar(predicateVersion, "predicate-version", *predicateVersion,
		"SLSA build provenance version to generate (v1, v0.2)")

	// Shared / canonical (modern) flags.
	flags.Var(f.predicate, "predicate",
		"base predicate as JSON or @file, matching the official SLSA proto for the selected version; content flags are merged onto it")
	flags.StringVar(&f.buildType, "build-type", "", "build type URI")
	flags.StringVar(&f.builderID, "builder-id", "", "builder id URI")
	flags.Var(f.externalParameters, "external-parameters", "external parameters as JSON or @file (v0.2: invocation.parameters)")
	flags.Var(f.resolvedDeps, "resolved-dependency", "a resolved dependency: JSON, @file, or name=,uri=,sha256= shorthand (repeatable; v0.2: materials)")
	flags.StringVar(&f.invocationID, "invocation-id", "", "build invocation id (v0.2: metadata.buildInvocationId)")
	flags.Var(f.startedOn, "started-on", "build start time, RFC3339 (v0.2: metadata.buildStartedOn)")
	flags.Var(f.finishedOn, "finished-on", "build finish time, RFC3339 (v0.2: metadata.buildFinishedOn)")

	// Modern (v1-only) flags. Visible, but error if used with v0.2.
	flags.Var(f.internalParameters, "internal-parameters", "internal parameters as JSON or @file (v1 only)")
	flags.Var(f.builderVersion, "builder-version", "builder version entries key=value (v1 only)")
	flags.Var(f.builderDeps, "builder-dependency", "a builder dependency, same syntax as --resolved-dependency (repeatable; v1 only)")
	flags.Var(f.byproducts, "byproduct", "a byproduct, same syntax as --resolved-dependency (repeatable; v1 only)")

	// Hidden legacy-name aliases, bound to the same targets.
	flags.Var(f.externalParameters, "parameters", "alias of --external-parameters")
	flags.Var(f.resolvedDeps, "materials", "alias of --resolved-dependency")
	flags.StringVar(&f.invocationID, "build-invocation-id", "", "alias of --invocation-id")
	flags.Var(f.startedOn, "build-started-on", "alias of --started-on")
	flags.Var(f.finishedOn, "build-finished-on", "alias of --finished-on")

	// Hidden v0.2-only flags. Error if used with v1.
	flags.StringVar(&f.configSourceURI, "config-source-uri", "", "invocation.configSource.uri (v0.2 only)")
	flags.Var(f.configSourceDigest, "config-source-digest", "invocation.configSource.digest key=value (v0.2 only)")
	flags.StringVar(&f.configSourceEntryPoint, "config-source-entry-point", "", "invocation.configSource.entryPoint (v0.2 only)")
	flags.Var(f.environment, "environment", "invocation.environment as JSON or @file (v0.2 only)")
	flags.Var(f.buildConfig, "build-config", "buildConfig as JSON or @file (v0.2 only)")
	flags.BoolVar(&f.reproducible, "reproducible", false, "metadata.reproducible (v0.2 only)")
	flags.BoolVar(&f.completenessParams, "completeness-parameters", false, "metadata.completeness.parameters (v0.2 only)")
	flags.BoolVar(&f.completenessEnv, "completeness-environment", false, "metadata.completeness.environment (v0.2 only)")
	flags.BoolVar(&f.completenessMaterials, "completeness-materials", false, "metadata.completeness.materials (v0.2 only)")

	for _, name := range []string{
		"parameters", "materials", "build-invocation-id", "build-started-on", "build-finished-on",
		"config-source-uri", "config-source-digest", "config-source-entry-point",
		"environment", "build-config", "reproducible",
		"completeness-parameters", "completeness-environment", "completeness-materials",
	} {
		_ = flags.MarkHidden(name) //nolint:errcheck // hiding known flag names
	}
}

// buildAttestOptions translates the set flags into canonical library options.
// Flags use modern (v1) names; the library maps them to the selected predicate
// version and rejects options that the version does not support. Hidden legacy
// aliases (--materials, --parameters, etc.) are bound to the same targets as
// their canonical flags, so they are handled by the same cases here.
func buildAttestOptions(cmd *cobra.Command, f *buildFlags) []attest.OptFn {
	changed := func(names ...string) bool {
		return slices.ContainsFunc(names, cmd.Flags().Changed)
	}

	var opts []attest.OptFn

	if changed("build-type") {
		opts = append(opts, attest.WithBuildType(f.buildType))
	}
	if changed("builder-id") {
		opts = append(opts, attest.WithBuilderID(f.builderID))
	}
	if changed("external-parameters", "parameters") {
		opts = append(opts, attest.WithExternalParameters(f.externalParameters.Value))
	}
	if changed("resolved-dependency", "materials") {
		opts = append(opts, attest.WithResolvedDependencies(f.resolvedDeps.Values...))
	}
	if changed("invocation-id", "build-invocation-id") {
		opts = append(opts, attest.WithInvocationID(f.invocationID))
	}
	if changed("started-on", "build-started-on") {
		opts = append(opts, attest.WithStartedOn(*f.startedOn.Value))
	}
	if changed("finished-on", "build-finished-on") {
		opts = append(opts, attest.WithFinishedOn(*f.finishedOn.Value))
	}

	// Modern v1-only fields (the library errors if used while targeting v0.2).
	if changed("internal-parameters") {
		opts = append(opts, attest.WithInternalParameters(f.internalParameters.Value))
	}
	if changed("builder-version") {
		opts = append(opts, attest.WithBuilderVersion(f.builderVersion.Values))
	}
	if changed("builder-dependency") {
		opts = append(opts, attest.WithBuilderDependencies(f.builderDeps.Values...))
	}
	if changed("byproduct") {
		opts = append(opts, attest.WithByproducts(f.byproducts.Values...))
	}

	// v0.2-only fields (the library errors if used while targeting v1).
	if changed("config-source-uri") {
		opts = append(opts, attest.WithConfigSourceURI(f.configSourceURI))
	}
	if changed("config-source-digest") {
		opts = append(opts, attest.WithConfigSourceDigest(f.configSourceDigest.Values))
	}
	if changed("config-source-entry-point") {
		opts = append(opts, attest.WithConfigSourceEntryPoint(f.configSourceEntryPoint))
	}
	if changed("environment") {
		opts = append(opts, attest.WithEnvironment(f.environment.Value))
	}
	if changed("build-config") {
		opts = append(opts, attest.WithBuildConfig(f.buildConfig.Value))
	}
	if changed("reproducible") {
		opts = append(opts, attest.WithReproducible(f.reproducible))
	}
	if changed("completeness-parameters", "completeness-environment", "completeness-materials") {
		opts = append(opts, attest.WithCompleteness(f.completenessParams, f.completenessEnv, f.completenessMaterials))
	}

	return opts
}
