// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/carabiner-dev/hasher"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// attesterImpl is the internal implementation seam for the Writer. The public
// Attest* methods orchestrate calls to these atomic operations, which lets us
// mock the implementation in tests.
type attesterImpl interface {
	// ValidateOptions checks that the resolved Options are coherent.
	ValidateOptions(*Options) error

	// ReadSubjects hashes the given subject paths into resource descriptors.
	ReadSubjects(*Options, []string) ([]*intoto.ResourceDescriptor, error)

	// GenerateSlsaProvenanceV1Statement builds an in-toto statement carrying a
	// SLSA Build provenance v1 predicate.
	GenerateSlsaProvenanceV1Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error)

	// GenerateSlsaProvenanceV02Statement builds an in-toto statement carrying a
	// SLSA Build provenance v0.2 predicate.
	GenerateSlsaProvenanceV02Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error)

	// GenerateVsaV1Statement builds an in-toto statement carrying a SLSA
	// Verification Summary Attestation v1 predicate.
	GenerateVsaV1Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error)

	// Serialize renders a statement to its wire representation.
	Serialize(*Options, *intoto.Statement) ([]byte, error)

	// Write emits the serialized attestation to the configured destination.
	Write(*Options, []byte) error
}

// defaultImpl is the production implementation of attesterImpl. The format
// generators are filled in by subsequent chunks.
type defaultImpl struct{}

// ValidateOptions checks the resolved options before any work is done.
func (*defaultImpl) ValidateOptions(o *Options) error {
	if o.Writer == nil {
		return fmt.Errorf("no output writer configured")
	}
	return nil
}

// ReadSubjects hashes the subject paths and returns one resource descriptor per
// unique path, preserving the order in which the paths were given.
func (*defaultImpl) ReadSubjects(o *Options, paths []string) ([]*intoto.ResourceDescriptor, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	h := hasher.New()
	if len(o.HashAlgorithms) > 0 {
		if err := hasher.WithAlgorithms(o.HashAlgorithms)(&h.Options); err != nil {
			return nil, fmt.Errorf("configuring hash algorithms: %w", err)
		}
	}

	fileHashes, err := h.HashFiles(paths)
	if err != nil {
		return nil, fmt.Errorf("hashing subjects: %w", err)
	}

	subjects := make([]*intoto.ResourceDescriptor, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}

		hashSet, ok := (*fileHashes)[path]
		if !ok {
			return nil, fmt.Errorf("no hashes computed for %q", path)
		}
		rd := hashSet.ToResourceDescriptor()
		rd.Name = filepath.Base(path)
		subjects = append(subjects, rd)
	}

	return subjects, nil
}

func (*defaultImpl) GenerateVsaV1Statement(*Options, []*intoto.ResourceDescriptor) (*intoto.Statement, error) {
	return nil, errNotImplemented("GenerateVsaV1Statement")
}

// Serialize renders the statement as compact, single-line JSON. protojson emits
// intentionally unstable whitespace, so we normalize through json.Compact to get
// a deterministic one-line result.
func (*defaultImpl) Serialize(_ *Options, stmt *intoto.Statement) ([]byte, error) {
	data, err := protojson.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshaling statement: %w", err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return nil, fmt.Errorf("compacting statement json: %w", err)
	}
	return buf.Bytes(), nil
}

// Write emits the serialized attestation followed by a newline.
func (*defaultImpl) Write(o *Options, data []byte) error {
	w := o.Writer
	if w == nil {
		w = os.Stdout
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("writing attestation: %w", err)
	}
	return nil
}
