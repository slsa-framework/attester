// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package sbom turns the top-level elements of an SBOM into attestation
// subjects. The SBOM is located and fetched with the carabiner collector (so
// it can live on a filesystem, a release, an OCI registry, etc — anywhere a
// collector driver reaches) and parsed with protobom, so both SPDX and
// CycloneDX documents work, bare or wrapped in an attestation.
package sbom

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/protobom/protobom/pkg/reader"
	protobom "github.com/protobom/protobom/pkg/sbom"
)

// sbomPredicateTypes are the predicate types fetched from the collector's
// repositories: SPDX and CycloneDX, base types plus every released version,
// since attesters in the wild stamp both forms. The collector's matcher is
// exact, so the versions are enumerated.
// loadDrivers registers the collector's default repository drivers once.
var loadDrivers sync.Once

var sbomPredicateTypes = func() []attestation.PredicateType {
	types := []attestation.PredicateType{}
	for base, versions := range map[string][]string{
		"https://spdx.dev/Document": {"v2.2", "v2.3", "v3.0"},
		"https://cyclonedx.org/bom": {"v1.2", "v1.3", "v1.4", "v1.5", "v1.6"},
	} {
		types = append(types, attestation.PredicateType(base))
		for _, v := range versions {
			types = append(types, attestation.PredicateType(base+"/"+v))
		}
	}
	return types
}()

// CollectSubjects fetches the SBOM(s) reachable through the collector init
// string (eg "fs:sboms/", "release:owner/repo@v1.0.0", "jsonl:atts.jsonl")
// and returns their top-level elements as attestation subjects. The filter
// globs, when given, are matched against the top-level node names. Because
// the subjects go into an attestation, every collected node must carry at
// least one digest in an algorithm in-toto recognizes.
func CollectSubjects(ctx context.Context, init string, filter []string) ([]*intoto.ResourceDescriptor, error) {
	var loadErr error
	loadDrivers.Do(func() { loadErr = collector.LoadDefaultRepositoryTypes() })
	if loadErr != nil {
		return nil, fmt.Errorf("loading collector drivers: %w", loadErr)
	}

	agent, err := collector.New()
	if err != nil {
		return nil, fmt.Errorf("creating collector agent: %w", err)
	}
	if err := agent.AddRepositoryFromString(init); err != nil {
		return nil, fmt.Errorf("configuring sbom source %q: %w", init, err)
	}

	envelopes, err := agent.FetchAttestationsByPredicateType(ctx, sbomPredicateTypes)
	if err != nil {
		return nil, fmt.Errorf("fetching sboms from %q: %w", init, err)
	}
	if len(envelopes) == 0 {
		return nil, fmt.Errorf("no sboms found in %q", init)
	}

	var subjects []*intoto.ResourceDescriptor
	for _, env := range envelopes {
		docSubjects, err := documentSubjects(env.GetStatement().GetPredicate().GetData(), filter)
		if err != nil {
			return nil, err
		}
		subjects = append(subjects, docSubjects...)
	}
	if len(subjects) == 0 {
		return nil, fmt.Errorf("no sbom top-level elements matched in %q", init)
	}
	return subjects, nil
}

// documentSubjects parses one SBOM and returns its top-level elements as
// subjects.
func documentSubjects(data []byte, filter []string) ([]*intoto.ResourceDescriptor, error) {
	doc, err := reader.New().ParseStream(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parsing sbom: %w", err)
	}

	roots := doc.GetNodeList().GetRootNodes()
	if len(roots) == 0 {
		return nil, fmt.Errorf("sbom has no top-level elements")
	}

	subjects := make([]*intoto.ResourceDescriptor, 0, len(roots))
	for _, node := range roots {
		name := node.GetName()
		if name == "" {
			name = node.GetId()
		}
		match, err := matchesAnyGlob(filter, name)
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}

		digests := nodeDigests(node)
		if len(digests) == 0 {
			return nil, fmt.Errorf(
				"sbom element %q has no hashes in an algorithm in-toto recognizes; cannot attest it as a subject", name)
		}

		rd := &intoto.ResourceDescriptor{
			Name:   name,
			Digest: digests,
		}
		if purl := node.GetIdentifiers()[int32(protobom.SoftwareIdentifierType_PURL)]; purl != "" {
			rd.Uri = purl
		}
		subjects = append(subjects, rd)
	}
	return subjects, nil
}

// nodeDigests converts a node's hashes into an in-toto digest set, keeping
// only algorithms in-toto defines (protobom names them upper-case, in-toto
// lower-case).
func nodeDigests(node *protobom.Node) map[string]string {
	digests := map[string]string{}
	for algo, value := range node.GetHashes() {
		name := strings.ToLower(protobom.HashAlgorithm(algo).String())
		if _, ok := intoto.HashAlgorithms[name]; !ok {
			continue
		}
		digests[name] = strings.ToLower(value)
	}
	return digests
}

// matchesAnyGlob reports whether name matches at least one of the globs
// (path.Match syntax). An empty glob list matches everything.
func matchesAnyGlob(globs []string, name string) (bool, error) {
	if len(globs) == 0 {
		return true, nil
	}
	for _, glob := range globs {
		match, err := path.Match(glob, name)
		if err != nil {
			return false, fmt.Errorf("invalid filter %q: %w", glob, err)
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}
