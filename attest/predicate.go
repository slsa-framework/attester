// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"

	buildv02 "github.com/slsa-framework/slsa-core/predicates/build/v02"
	buildv1 "github.com/slsa-framework/slsa-core/predicates/build/v1"
	vsav1 "github.com/slsa-framework/slsa-core/predicates/vsa/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// NewPredicate returns an empty instance of the official SLSA predicate proto
// for the version, suitable as an Options.Predicate base. Returns nil for
// unknown versions.
func (v AttestationVersion) NewPredicate() proto.Message {
	switch v {
	case SlsaProvenanceV1:
		return &buildv1.Provenance{}
	case SlsaProvenanceV02:
		return &buildv02.Provenance{}
	case VsaV1:
		return &vsav1.VerificationSummary{}
	default:
		return nil
	}
}

// ParsePredicate parses JSON into the official SLSA predicate proto for the
// version. Parsing is strict: fields the predicate proto does not define are
// rejected rather than dropped, so malformed or mismatched predicates fail
// here instead of producing an attestation that silently lost content.
func ParsePredicate(version AttestationVersion, data []byte) (proto.Message, error) {
	p := version.NewPredicate()
	if p == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownVersion, version)
	}
	if err := protojson.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("parsing predicate as %s: %w", version.PredicateType(), err)
	}
	return p, nil
}
