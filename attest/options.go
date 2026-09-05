// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"io"
	"maps"
	"os"
	"time"

	"github.com/carabiner-dev/signer"
	signeroptions "github.com/carabiner-dev/signer/options"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Signer signs a serialized in-toto statement, returning the signed artifact
// (a sigstore bundle or a DSSE envelope). It is satisfied by *signer.Signer
// from github.com/carabiner-dev/signer.
type Signer interface {
	SignStatement(data []byte, funcs ...signeroptions.SignOptFn) (signer.SignedArtifact, error)
}

// Completeness mirrors the SLSA build provenance v0.2 completeness flags. It is a
// legacy-only concept with no v1 equivalent.
type Completeness struct {
	Parameters  bool
	Environment bool
	Materials   bool
}

// Options is the single, canonical option set for the Writer. Field names use
// the latest (v1) terminology; the Writer maps them to each predicate version's
// own option set at attest time (see mapping.go). Fields that exist only in an
// older predicate are kept here too so the one option set stays complete.
type Options struct {
	// Writer is where the serialized attestation is written (default os.Stdout).
	Writer io.Writer
	// HashAlgorithms are the digest algorithms used to hash subjects (default sha256).
	HashAlgorithms []string
	// Subjects are pre-built subject descriptors added to the statement after
	// the hashed subject files, for artifacts only known by their digest.
	Subjects []*intoto.ResourceDescriptor
	// Predicate is an optional base predicate the content options are merged
	// onto. It must match the target version's concrete predicate type.
	Predicate proto.Message
	// Signer, when set, signs the serialized statement and the signed artifact
	// (sigstore bundle or DSSE envelope) is emitted instead of the bare
	// statement. When nil the statement is emitted unsigned.
	Signer Signer

	// --- Build provenance content (canonical / modern names) ---
	BuildType            string
	BuilderID            string
	ExternalParameters   *structpb.Struct // v0.2: invocation.parameters
	InternalParameters   *structpb.Struct // v1 only
	ResolvedDependencies []*intoto.ResourceDescriptor // v0.2: materials
	BuilderVersion       map[string]string // v1 only
	BuilderDependencies  []*intoto.ResourceDescriptor // v1 only
	Byproducts           []*intoto.ResourceDescriptor // v1 only
	InvocationID         string // v0.2: metadata.buildInvocationId
	StartedOn            *timestamppb.Timestamp // v0.2: metadata.buildStartedOn
	FinishedOn           *timestamppb.Timestamp // v0.2: metadata.buildFinishedOn

	// --- Build provenance content with no v1 equivalent (v0.2 only) ---
	ConfigSourceURI        string
	ConfigSourceDigest     map[string]string
	ConfigSourceEntryPoint string
	Environment            *structpb.Struct
	BuildConfig            *structpb.Struct
	Reproducible           *bool
	Completeness           *Completeness

	// --- Verification summary attestation content ---
	VerifierID         string
	TimeVerified       *timestamppb.Timestamp
	ResourceURI        string
	PolicyURI          string
	PolicyDigest       map[string]string
	InputAttestations  []*intoto.ResourceDescriptor
	VerificationResult string
	VerifiedLevels     []string
	DependencyLevels   map[string]uint64
	SlsaVersion        string
}

// defaultOptions returns the baseline Options before any OptFn is applied.
func defaultOptions() Options {
	return Options{
		Writer:         os.Stdout,
		HashAlgorithms: []string{"sha256"},
	}
}

// OptFn is a functional option mutating an Options value.
type OptFn func(*Options) error

// mergeStringMap merges src into dst, allocating dst if needed.
func mergeStringMap(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	maps.Copy(dst, src)
	return dst
}

// mergeUint64Map merges src into dst, allocating dst if needed.
func mergeUint64Map(dst, src map[string]uint64) map[string]uint64 {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]uint64, len(src))
	}
	maps.Copy(dst, src)
	return dst
}

// --- General options ---

// WithWriter sets the destination for the serialized attestation.
func WithWriter(w io.Writer) OptFn {
	return func(o *Options) error { o.Writer = w; return nil }
}

// WithHashAlgorithms sets the digest algorithms used to hash subject files.
func WithHashAlgorithms(algos ...string) OptFn {
	return func(o *Options) error { o.HashAlgorithms = algos; return nil }
}

// WithSubjects appends pre-built subject descriptors for artifacts only known
// by their digest. They are added to the statement after the hashed files.
func WithSubjects(subjects ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.Subjects = append(o.Subjects, subjects...)
		return nil
	}
}

// WithPredicate sets a base predicate the content options are merged onto.
func WithPredicate(p proto.Message) OptFn {
	return func(o *Options) error { o.Predicate = p; return nil }
}

// WithSigner sets the signer used to sign the attestation.
func WithSigner(s Signer) OptFn {
	return func(o *Options) error { o.Signer = s; return nil }
}

// --- Build provenance options (canonical) ---

// WithBuildType sets the build type URI.
func WithBuildType(buildType string) OptFn {
	return func(o *Options) error { o.BuildType = buildType; return nil }
}

// WithBuilderID sets the builder id URI.
func WithBuilderID(id string) OptFn {
	return func(o *Options) error { o.BuilderID = id; return nil }
}

// WithExternalParameters sets the external parameters (v0.2: invocation.parameters).
func WithExternalParameters(s *structpb.Struct) OptFn {
	return func(o *Options) error { o.ExternalParameters = s; return nil }
}

// WithInternalParameters sets the internal parameters (v1 only).
func WithInternalParameters(s *structpb.Struct) OptFn {
	return func(o *Options) error { o.InternalParameters = s; return nil }
}

// WithResolvedDependencies appends resolved dependencies (v0.2: materials).
func WithResolvedDependencies(deps ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.ResolvedDependencies = append(o.ResolvedDependencies, deps...)
		return nil
	}
}

// WithBuilderVersion merges builder version entries (v1 only).
func WithBuilderVersion(version map[string]string) OptFn {
	return func(o *Options) error {
		o.BuilderVersion = mergeStringMap(o.BuilderVersion, version)
		return nil
	}
}

// WithBuilderDependencies appends builder dependencies (v1 only).
func WithBuilderDependencies(deps ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.BuilderDependencies = append(o.BuilderDependencies, deps...)
		return nil
	}
}

// WithByproducts appends byproducts (v1 only).
func WithByproducts(deps ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.Byproducts = append(o.Byproducts, deps...)
		return nil
	}
}

// WithInvocationID sets the build invocation id (v0.2: metadata.buildInvocationId).
func WithInvocationID(id string) OptFn {
	return func(o *Options) error { o.InvocationID = id; return nil }
}

// WithStartedOn sets the build start time (v0.2: metadata.buildStartedOn).
func WithStartedOn(t time.Time) OptFn {
	return func(o *Options) error { o.StartedOn = timestamppb.New(t); return nil }
}

// WithFinishedOn sets the build finish time (v0.2: metadata.buildFinishedOn).
func WithFinishedOn(t time.Time) OptFn {
	return func(o *Options) error { o.FinishedOn = timestamppb.New(t); return nil }
}

// --- Build provenance options with no v1 equivalent (v0.2 only) ---

// WithConfigSourceURI sets invocation.configSource.uri (v0.2 only).
func WithConfigSourceURI(uri string) OptFn {
	return func(o *Options) error { o.ConfigSourceURI = uri; return nil }
}

// WithConfigSourceDigest merges invocation.configSource.digest (v0.2 only).
func WithConfigSourceDigest(digest map[string]string) OptFn {
	return func(o *Options) error {
		o.ConfigSourceDigest = mergeStringMap(o.ConfigSourceDigest, digest)
		return nil
	}
}

// WithConfigSourceEntryPoint sets invocation.configSource.entryPoint (v0.2 only).
func WithConfigSourceEntryPoint(entryPoint string) OptFn {
	return func(o *Options) error { o.ConfigSourceEntryPoint = entryPoint; return nil }
}

// WithEnvironment sets invocation.environment (v0.2 only).
func WithEnvironment(s *structpb.Struct) OptFn {
	return func(o *Options) error { o.Environment = s; return nil }
}

// WithBuildConfig sets buildConfig (v0.2 only).
func WithBuildConfig(s *structpb.Struct) OptFn {
	return func(o *Options) error { o.BuildConfig = s; return nil }
}

// WithReproducible sets metadata.reproducible (v0.2 only).
func WithReproducible(reproducible bool) OptFn {
	return func(o *Options) error { o.Reproducible = &reproducible; return nil }
}

// WithCompleteness sets metadata.completeness (v0.2 only).
func WithCompleteness(parameters, environment, materials bool) OptFn {
	return func(o *Options) error {
		o.Completeness = &Completeness{Parameters: parameters, Environment: environment, Materials: materials}
		return nil
	}
}

// --- Verification summary attestation options ---

// WithVerifierID sets verifier.id.
func WithVerifierID(id string) OptFn {
	return func(o *Options) error { o.VerifierID = id; return nil }
}

// WithTimeVerified sets timeVerified.
func WithTimeVerified(t time.Time) OptFn {
	return func(o *Options) error { o.TimeVerified = timestamppb.New(t); return nil }
}

// WithResourceURI sets resourceUri.
func WithResourceURI(uri string) OptFn {
	return func(o *Options) error { o.ResourceURI = uri; return nil }
}

// WithPolicyURI sets policy.uri.
func WithPolicyURI(uri string) OptFn {
	return func(o *Options) error { o.PolicyURI = uri; return nil }
}

// WithPolicyDigest merges policy.digest entries.
func WithPolicyDigest(digest map[string]string) OptFn {
	return func(o *Options) error {
		o.PolicyDigest = mergeStringMap(o.PolicyDigest, digest)
		return nil
	}
}

// WithInputAttestations appends inputAttestations.
func WithInputAttestations(inputs ...*intoto.ResourceDescriptor) OptFn {
	return func(o *Options) error {
		o.InputAttestations = append(o.InputAttestations, inputs...)
		return nil
	}
}

// WithVerificationResult sets verificationResult, e.g. "PASSED".
func WithVerificationResult(result string) OptFn {
	return func(o *Options) error { o.VerificationResult = result; return nil }
}

// WithVerifiedLevels appends verifiedLevels.
func WithVerifiedLevels(levels ...string) OptFn {
	return func(o *Options) error {
		o.VerifiedLevels = append(o.VerifiedLevels, levels...)
		return nil
	}
}

// WithDependencyLevels merges dependencyLevels entries.
func WithDependencyLevels(levels map[string]uint64) OptFn {
	return func(o *Options) error {
		o.DependencyLevels = mergeUint64Map(o.DependencyLevels, levels)
		return nil
	}
}

// WithSlsaVersion sets slsaVersion.
func WithSlsaVersion(version string) OptFn {
	return func(o *Options) error { o.SlsaVersion = version; return nil }
}
