// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package statement assembles in-toto v1 statements from a predicate proto and a
// set of subjects. It is shared by the per-version generator packages.
package statement

import (
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// Build wraps the given predicate in an in-toto v1 statement over the supplied
// subjects. The predicate proto is converted to a structpb value so it can ride
// in the statement's Predicate field. A nil predicate yields a statement with an
// empty predicate object.
func Build(predicateType string, subjects []*intoto.ResourceDescriptor, predicate proto.Message) (*intoto.Statement, error) {
	pred, err := toStruct(predicate)
	if err != nil {
		return nil, err
	}
	return &intoto.Statement{
		Type:          intoto.StatementTypeUri,
		Subject:       subjects,
		PredicateType: predicateType,
		Predicate:     pred,
	}, nil
}

// toStruct marshals a predicate proto through protojson (which gives the
// spec-correct field naming) and loads the result into a structpb.Struct.
func toStruct(predicate proto.Message) (*structpb.Struct, error) {
	if predicate == nil {
		return &structpb.Struct{}, nil
	}
	data, err := protojson.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}
	s := &structpb.Struct{}
	if err := protojson.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("loading predicate into struct: %w", err)
	}
	return s, nil
}
