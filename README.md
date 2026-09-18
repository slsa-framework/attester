# SLSA Attester

`slsa-attester` generates signed [SLSA](https://slsa.dev) attestations: build
provenance (v1 and v0.2) and verification summary attestations (VSAs), as
in-toto statements built on the official SLSA predicate protos.

It is both a command line tool and a Go library, and it includes a *watcher*
that observes GitHub Actions runs and attests the artifacts they produce,
the successor to the attestation half of `slsa-github-generator`.

Attestations produced by the attester verify with the
[SLSA Verifier](https://github.com/slsa-framework/verifier). The subject
flags of the two tools share the same syntax, so digests round-trip verbatim
between attest and verify time.

## Installing

Download a binary from the
[releases](https://github.com/slsa-framework/attester/releases). Every
release ships its own SLSA provenance (`attestations.jsonl`) to verify the
download against.

## Attesting builds

Subject files given as arguments are hashed and recorded in the statement:

```sh
slsa-attester build --builder-id=https://builder.example/ci -o provenance.json bin/app
```

By default the attestation is signed with sigstore: ambient CI credentials
(GitHub Actions, GitLab CI, GCP, etc) are used when detected, with the interactive
browser flow as fallback. Signing produces a sigstore bundle, when signing with a
key the attester produces a DSSE envelope; `--sign=false` emits the bare statement:

```sh
slsa-attester build --signing-key key.pem ... # DSSE envelope
slsa-attester build --sign=false ...          # unsigned statement
```

### Subject sources

Subjects can come from more places than local files:

| Source | Flag | Digests computed by |
| --- | --- | --- |
| Local files | arguments | the attester (`--hash-algorithms`, default sha256) |
| Explicit digests | `-s algorithm:digest` | asserted by the caller |
| Checksum files (`sha256sum` output) | `--checksums file` | asserted by the caller |
| GitHub Actions workflow artifacts | `watch` (automatic) | the attester downloads and hashes them |
| GitHub release assets | `watch --release <tag>` | the platform (GitHub's API digests) |
| SBOM top-level elements | `watch --sbom <source>` | asserted by the SBOM (elements must carry hashes) |

The `-s` flag uses the same `algorithm:digest` syntax the verifier accepts,
and `--checksums` reads the same `sha256sum`-format listings
slsa-github-generator accepted through its `base64-subjects` input.

### Predicate content

Flags use the latest (v1) SLSA vocabulary. Selecting an older predicate with
`--predicate-version` maps them to the older field names automatically and
fields that exist in only one version are rejected when targeting the other.
A full predicate can be passed as a base with `--predicate` (JSON or
`@file`). It is parsed strictly against the official SLSA proto for the
selected version, and content flags are merged onto it:

```sh
slsa-attester build --predicate @predicate.json --invocation-id run-42 bin/app
```

## Attesting verifications (VSAs)

```sh
slsa-attester vsa --verifier-id=https://verifier.example \
  --verification-result=PASSED --verified-level=SLSA_BUILD_LEVEL_3 \
  -s sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

## Attesting GitHub Actions runs

`slsa-attester watch` observes a workflow run, waits for its jobs to finish
and attests the artifacts they produced, emitting provenance with the
[watcher build type](docs/buildtypes/watcher/v1.md)
(`https://slsa.dev/buildtypes/watcher/v1`).

The easiest way to use it is the reusable workflow in
[slsa-framework/actions](https://github.com/slsa-framework/actions), added as
a job to the workflow being attested. It gives the attester a dedicated job
and signs the provenance with the `slsa-framework/actions` identity, a
builder identity independent of the workflow being attested (the way
slsa-github-generator worked):

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # ... build and upload your artifacts ...

  provenance:
    permissions:
      id-token: write
      actions: read
      contents: read
    uses: slsa-framework/actions/.github/workflows/attest_actions.yml@main
```

The watcher excludes its own job and waits for every sibling, and it
**refuses to run in a job that contains any other step**: steps that run
earlier can tamper with the attester, and every step in a job shares the
OIDC identity the attestation is signed with. Give it a job of its own.

Outside the run being attested, any run can be watched by spec:

```sh
slsa-attester watch github://owner/repo/123456789 --release v1.0.0
```

## Verifying

Attestations verify with the slsa-verifier, which binds the provenance's
`builder.id` to the signing certificate: for provenance generated through
the reusable workflow, the certificate proves which workflow's run the
attester observed, so the builder identity is proven rather than claimed:

```sh
slsa-verifier build \
  --param expected_source:github.com/your-org/your-repo \
  --param 'trusted_builders:[https://github.com/your-org/your-repo/.github/workflows/release.yml@refs/tags/v1.0.0]' \
  attestations.jsonl your-artifact
```

## Using the library

The `attest` package exposes the same functionality with a single canonical
option set, per-version mapping and compatibility checks are handled
internally:

```go
import "github.com/slsa-framework/attester/attest"

writer := &attest.Writer{}
err := writer.Attest(attest.SlsaProvenanceV1, []string{"bin/app"},
    attest.WithBuilderID("https://builder.example/ci"),
    attest.WithInvocationID("run-42"),
)
```

## Contributing

The SLSA attester is released under the terms of the  Apache 2.0 license.
Feel free to submit patches and open issues in the repo!
