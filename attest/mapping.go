// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"

	buildv02 "github.com/slsa-framework/slsa-core/predicates/build/v02"

	buildgenv1 "github.com/slsa-framework/slsa-attester/attest/build/v1"
	buildgenv02 "github.com/slsa-framework/slsa-attester/attest/build/v02"
	vsagenv1 "github.com/slsa-framework/slsa-attester/attest/vsa/v1"
)

// The Writer owns the translation of its single canonical option set into each
// predicate version's own option set. This is also where cross-version
// compatibility is enforced: options that have no place in the target version
// are rejected rather than silently dropped.

func errFieldOnlyIn(field, version string) error {
	return fmt.Errorf("%s is only supported by predicate version %s", field, version)
}

// rejectV02Only fails if any v0.2-only field is set (used when targeting v1).
func rejectV02Only(o *Options) error {
	switch {
	case o.ConfigSourceURI != "" || len(o.ConfigSourceDigest) > 0 || o.ConfigSourceEntryPoint != "":
		return errFieldOnlyIn("config source", "v0.2")
	case o.Environment != nil:
		return errFieldOnlyIn("environment", "v0.2")
	case o.BuildConfig != nil:
		return errFieldOnlyIn("build config", "v0.2")
	case o.Reproducible != nil:
		return errFieldOnlyIn("reproducible", "v0.2")
	case o.Completeness != nil:
		return errFieldOnlyIn("completeness", "v0.2")
	}
	return nil
}

// rejectV1Only fails if any v1-only field is set (used when targeting v0.2).
func rejectV1Only(o *Options) error {
	switch {
	case o.InternalParameters != nil:
		return errFieldOnlyIn("internal parameters", "v1")
	case len(o.BuilderVersion) > 0:
		return errFieldOnlyIn("builder version", "v1")
	case len(o.BuilderDependencies) > 0:
		return errFieldOnlyIn("builder dependencies", "v1")
	case len(o.Byproducts) > 0:
		return errFieldOnlyIn("byproducts", "v1")
	}
	return nil
}

// mapToBuildV1 translates the canonical options to build provenance v1 options.
func mapToBuildV1(o *Options) (buildgenv1.Options, error) {
	if err := rejectV02Only(o); err != nil {
		return buildgenv1.Options{}, err
	}
	return buildgenv1.Options{
		Base:                 o.Predicate,
		BuildType:            o.BuildType,
		BuilderID:            o.BuilderID,
		ExternalParameters:   o.ExternalParameters,
		InternalParameters:   o.InternalParameters,
		ResolvedDependencies: o.ResolvedDependencies,
		BuilderVersion:       o.BuilderVersion,
		BuilderDependencies:  o.BuilderDependencies,
		Byproducts:           o.Byproducts,
		InvocationID:         o.InvocationID,
		StartedOn:            o.StartedOn,
		FinishedOn:           o.FinishedOn,
	}, nil
}

// mapToBuildV02 translates the canonical options to build provenance v0.2
// options, renaming the modern fields to their v0.2 counterparts.
func mapToBuildV02(o *Options) (buildgenv02.Options, error) {
	if err := rejectV1Only(o); err != nil {
		return buildgenv02.Options{}, err
	}
	opts := buildgenv02.Options{
		Base:                   o.Predicate,
		BuildType:              o.BuildType,
		BuilderID:              o.BuilderID,
		Parameters:             o.ExternalParameters,
		Environment:            o.Environment,
		BuildConfig:            o.BuildConfig,
		ConfigSourceURI:        o.ConfigSourceURI,
		ConfigSourceDigest:     o.ConfigSourceDigest,
		ConfigSourceEntryPoint: o.ConfigSourceEntryPoint,
		BuildInvocationID:      o.InvocationID,
		BuildStartedOn:         o.StartedOn,
		BuildFinishedOn:        o.FinishedOn,
		Reproducible:           o.Reproducible,
		Materials:              o.ResolvedDependencies,
	}
	if o.Completeness != nil {
		opts.Completeness = &buildv02.Completeness{
			Parameters:  o.Completeness.Parameters,
			Environment: o.Completeness.Environment,
			Materials:   o.Completeness.Materials,
		}
	}
	return opts, nil
}

// mapToVsaV1 translates the canonical options to VSA v1 options.
func mapToVsaV1(o *Options) vsagenv1.Options {
	return vsagenv1.Options{
		Base:               o.Predicate,
		VerifierID:         o.VerifierID,
		TimeVerified:       o.TimeVerified,
		ResourceURI:        o.ResourceURI,
		PolicyURI:          o.PolicyURI,
		PolicyDigest:       o.PolicyDigest,
		InputAttestations:  o.InputAttestations,
		VerificationResult: o.VerificationResult,
		VerifiedLevels:     o.VerifiedLevels,
		DependencyLevels:   o.DependencyLevels,
		SlsaVersion:        o.SlsaVersion,
	}
}
