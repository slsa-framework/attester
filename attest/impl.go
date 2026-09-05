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

// attesterImpl is the version-independent implementation seam for the Writer.
// Statement generation is owned by the per-version generator packages, so this
// seam only covers the shared pipeline steps, which lets us mock them in tests.
type attesterImpl interface {
	// ValidateOptions checks that the resolved Options are coherent.
	ValidateOptions(*Options) error
	// ReadSubjects hashes the given subject paths into resource descriptors.
	ReadSubjects(*Options, []string) ([]*intoto.ResourceDescriptor, error)
	// Serialize renders a statement to its wire representation.
	Serialize(*Options, *intoto.Statement) ([]byte, error)
	// Sign signs the serialized statement with the configured signer. When no
	// signer is configured the data passes through unchanged.
	Sign(*Options, []byte) ([]byte, error)
	// Write emits the serialized attestation to the configured destination.
	Write(*Options, []byte) error
}

// defaultImpl is the production implementation of attesterImpl.
type defaultImpl struct{}

// ValidateOptions checks the resolved options before any work is done.
func (*defaultImpl) ValidateOptions(o *Options) error {
	if o.Writer == nil {
		return fmt.Errorf("no output writer configured")
	}
	return nil
}

// ReadSubjects hashes the subject paths and returns one resource descriptor per
// unique path, preserving the order in which the paths were given. Pre-built
// descriptors from Options.Subjects are appended after the hashed files.
func (*defaultImpl) ReadSubjects(o *Options, paths []string) ([]*intoto.ResourceDescriptor, error) {
	if len(paths) == 0 {
		if len(o.Subjects) == 0 {
			return nil, nil
		}
		return o.Subjects, nil
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

	return append(subjects, o.Subjects...), nil
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

// Sign signs the serialized statement with the configured signer and returns
// the signed artifact's canonical JSON form (a sigstore bundle or a DSSE
// envelope, depending on the signer's backend). With no signer configured the
// bare statement passes through unchanged.
func (*defaultImpl) Sign(o *Options, data []byte) ([]byte, error) {
	if o.Signer == nil {
		return data, nil
	}
	artifact, err := o.Signer.SignStatement(data)
	if err != nil {
		return nil, fmt.Errorf("signing statement: %w", err)
	}
	var buf bytes.Buffer
	if _, err := artifact.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("serializing signed artifact: %w", err)
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
