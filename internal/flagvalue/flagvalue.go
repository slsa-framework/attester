// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package flagvalue provides reusable pflag.Value implementations for the
// complex inputs the slsa-attester CLI accepts: resource descriptors, digest
// and level maps, arbitrary JSON structs, and RFC3339 timestamps.
//
// Where it makes sense, a value can be supplied as inline JSON, as @path to a
// JSON file, or as a key=value shorthand.
package flagvalue

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// readJSONOrInline returns the JSON bytes for in: when in starts with '@' the
// remainder is read as a file path, otherwise in is returned verbatim.
func readJSONOrInline(in string) ([]byte, error) {
	if path, ok := strings.CutPrefix(in, "@"); ok {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %q: %w", path, err)
		}
		return data, nil
	}
	return []byte(in), nil
}

// looksLikeJSON reports whether the trimmed input begins like a JSON object.
func looksLikeJSON(in string) bool {
	t := strings.TrimSpace(in)
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "@")
}

// ResourceDescriptorSlice accumulates intoto ResourceDescriptors from repeated
// flag occurrences. Each occurrence may be inline JSON, @file, or the shorthand
// "name=foo,uri=...,sha256=abc" where name/uri are scalar fields and any other
// key is treated as a digest algorithm.
type ResourceDescriptorSlice struct {
	Values []*intoto.ResourceDescriptor
}

func (r *ResourceDescriptorSlice) Set(in string) error {
	rd, err := parseResourceDescriptor(in)
	if err != nil {
		return err
	}
	r.Values = append(r.Values, rd)
	return nil
}

func (r *ResourceDescriptorSlice) Type() string { return "resourceDescriptor" }

func (r *ResourceDescriptorSlice) String() string {
	if len(r.Values) == 0 {
		return ""
	}
	return fmt.Sprintf("[%d descriptor(s)]", len(r.Values))
}

func parseResourceDescriptor(in string) (*intoto.ResourceDescriptor, error) {
	if looksLikeJSON(in) {
		data, err := readJSONOrInline(in)
		if err != nil {
			return nil, err
		}
		rd := &intoto.ResourceDescriptor{}
		if err := protojson.Unmarshal(data, rd); err != nil {
			return nil, fmt.Errorf("parsing resource descriptor JSON: %w", err)
		}
		return rd, nil
	}
	return parseResourceDescriptorShorthand(in)
}

func parseResourceDescriptorShorthand(in string) (*intoto.ResourceDescriptor, error) {
	rd := &intoto.ResourceDescriptor{}
	for pair := range strings.SplitSeq(in, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("invalid shorthand %q: expected key=value", pair)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "name":
			rd.Name = value
		case "uri":
			rd.Uri = value
		default:
			if rd.Digest == nil {
				rd.Digest = map[string]string{}
			}
			rd.Digest[key] = value
		}
	}
	if rd.GetName() == "" && rd.GetUri() == "" && len(rd.GetDigest()) == 0 {
		return nil, fmt.Errorf("empty resource descriptor %q", in)
	}
	return rd, nil
}

// SubjectSlice accumulates subject resource descriptors from repeated flag
// occurrences given as algorithm:digest, e.g. sha256:<hex>. The syntax and
// validation mirror the slsa verifier's -s/--subject flag so digests stated at
// attest time can be restated verbatim at verify time: the algorithm must be
// one in-toto defines, the digest must be hex of the algorithm's length, and it
// is normalized to lower case.
type SubjectSlice struct {
	Values []*intoto.ResourceDescriptor
}

func (s *SubjectSlice) Set(in string) error {
	algoName, digest, ok := strings.Cut(strings.TrimSpace(in), ":")
	if !ok || algoName == "" || digest == "" {
		return fmt.Errorf("invalid subject %q: want algorithm:digest, e.g. sha256:<hex>", in)
	}
	algo, ok := intoto.HashAlgorithms[algoName]
	if !ok {
		return fmt.Errorf("invalid subject %q: unknown digest algorithm %q (want one of %s)", in, algoName, knownAlgorithms())
	}
	digest = strings.ToLower(digest)
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("invalid subject %q: digest is not hex: %w", in, err)
	}
	if want := algo.HexLength() * 2; want > 0 && len(digest) != want {
		return fmt.Errorf("invalid subject %q: %s digests are %d hex characters, got %d", in, algo, want, len(digest))
	}
	s.Values = append(s.Values, &intoto.ResourceDescriptor{
		Digest: map[string]string{string(algo): digest},
	})
	return nil
}

func (s *SubjectSlice) Type() string { return "algorithm:digest" }

func (s *SubjectSlice) String() string {
	if len(s.Values) == 0 {
		return ""
	}
	return fmt.Sprintf("[%d subject(s)]", len(s.Values))
}

func knownAlgorithms() string {
	names := make([]string, 0, len(intoto.HashAlgorithms))
	for name := range intoto.HashAlgorithms {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// StringMap accumulates key=value string entries. Multiple comma-separated pairs
// per occurrence are allowed, and the flag may be repeated; later keys win.
type StringMap struct {
	Values map[string]string
}

func (m *StringMap) Set(in string) error {
	for pair := range strings.SplitSeq(in, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			return fmt.Errorf("invalid entry %q: expected key=value", pair)
		}
		if m.Values == nil {
			m.Values = map[string]string{}
		}
		m.Values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return nil
}

func (m *StringMap) Type() string { return "key=value" }

func (m *StringMap) String() string { return "" }

// Uint64Map accumulates key=value entries whose values are unsigned integers.
type Uint64Map struct {
	Values map[string]uint64
}

func (m *Uint64Map) Set(in string) error {
	for pair := range strings.SplitSeq(in, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			return fmt.Errorf("invalid entry %q: expected key=value", pair)
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return fmt.Errorf("invalid unsigned integer for %q: %w", key, err)
		}
		if m.Values == nil {
			m.Values = map[string]uint64{}
		}
		m.Values[strings.TrimSpace(key)] = n
	}
	return nil
}

func (m *Uint64Map) Type() string { return "key=uint" }

func (m *Uint64Map) String() string { return "" }

// RawJSON holds raw JSON given inline or as @file. Only the JSON syntax is
// checked at flag-parse time; the schema is validated by whoever consumes the
// bytes (e.g. a strict proto unmarshal once the target type is known).
type RawJSON struct {
	Data []byte
}

func (r *RawJSON) Set(in string) error {
	data, err := readJSONOrInline(in)
	if err != nil {
		return err
	}
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON")
	}
	r.Data = data
	return nil
}

func (r *RawJSON) Type() string { return "json" }

func (r *RawJSON) String() string { return "" }

// Struct holds a structpb.Struct parsed from inline JSON or @file.
type Struct struct {
	Value *structpb.Struct
}

func (s *Struct) Set(in string) error {
	data, err := readJSONOrInline(in)
	if err != nil {
		return err
	}
	value := &structpb.Struct{}
	if err := protojson.Unmarshal(data, value); err != nil {
		return fmt.Errorf("parsing JSON object: %w", err)
	}
	s.Value = value
	return nil
}

func (s *Struct) Type() string { return "json" }

func (s *Struct) String() string { return "" }

// Time holds a timestamp parsed from RFC3339.
type Time struct {
	Value *time.Time
}

func (t *Time) Set(in string) error {
	parsed, err := time.Parse(time.RFC3339, in)
	if err != nil {
		return fmt.Errorf("parsing RFC3339 time: %w", err)
	}
	t.Value = &parsed
	return nil
}

func (t *Time) Type() string { return "rfc3339" }

func (t *Time) String() string {
	if t.Value == nil {
		return ""
	}
	return t.Value.Format(time.RFC3339)
}
