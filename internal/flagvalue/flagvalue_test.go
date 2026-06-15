// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package flagvalue

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
)

// Compile-time checks that all values satisfy pflag.Value.
var (
	_ pflag.Value = (*ResourceDescriptorSlice)(nil)
	_ pflag.Value = (*StringMap)(nil)
	_ pflag.Value = (*Uint64Map)(nil)
	_ pflag.Value = (*Struct)(nil)
	_ pflag.Value = (*Time)(nil)
)

func TestResourceDescriptorShorthand(t *testing.T) {
	t.Parallel()
	rd := &ResourceDescriptorSlice{}
	if err := rd.Set("name=foo,uri=git+https://example.com/repo,sha256=abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Values) != 1 {
		t.Fatalf("expected 1 value, got %d", len(rd.Values))
	}
	v := rd.Values[0]
	if v.GetName() != "foo" || v.GetUri() != "git+https://example.com/repo" {
		t.Fatalf("unexpected name/uri: %q %q", v.GetName(), v.GetUri())
	}
	if v.GetDigest()["sha256"] != "abc" {
		t.Fatalf("unexpected digest: %v", v.GetDigest())
	}
}

func TestResourceDescriptorJSONAndRepeat(t *testing.T) {
	t.Parallel()
	rd := &ResourceDescriptorSlice{}
	if err := rd.Set(`{"uri":"pkg:generic/x","digest":{"sha512":"ff"}}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := rd.Set("name=second"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rd.Values) != 2 {
		t.Fatalf("expected 2 values (append), got %d", len(rd.Values))
	}
	if rd.Values[0].GetDigest()["sha512"] != "ff" {
		t.Fatalf("unexpected digest: %v", rd.Values[0].GetDigest())
	}
}

func TestResourceDescriptorFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rd.json")
	if err := os.WriteFile(path, []byte(`{"name":"fromfile","uri":"u"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rd := &ResourceDescriptorSlice{}
	if err := rd.Set("@" + path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rd.Values[0].GetName() != "fromfile" {
		t.Fatalf("unexpected name: %q", rd.Values[0].GetName())
	}
}

func TestResourceDescriptorErrors(t *testing.T) {
	t.Parallel()
	rd := &ResourceDescriptorSlice{}
	if err := rd.Set("noequalsign"); err == nil {
		t.Fatal("expected error for bad shorthand")
	}
	if err := rd.Set("{bad json"); err == nil {
		t.Fatal("expected error for bad JSON")
	}
	if err := rd.Set("@/no/such/file.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestStringMap(t *testing.T) {
	t.Parallel()
	m := &StringMap{}
	if err := m.Set("sha256=aaa,sha512=bbb"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := m.Set("host=ci"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Values["sha256"] != "aaa" || m.Values["sha512"] != "bbb" || m.Values["host"] != "ci" {
		t.Fatalf("unexpected map: %v", m.Values)
	}
	if err := m.Set("bad"); err == nil {
		t.Fatal("expected error for missing =")
	}
}

func TestUint64Map(t *testing.T) {
	t.Parallel()
	m := &Uint64Map{}
	if err := m.Set("SLSA_BUILD_LEVEL_3=5"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Values["SLSA_BUILD_LEVEL_3"] != 5 {
		t.Fatalf("unexpected value: %v", m.Values)
	}
	if err := m.Set("x=notanint"); err == nil {
		t.Fatal("expected error for non-integer")
	}
}

func TestStruct(t *testing.T) {
	t.Parallel()
	s := &Struct{}
	if err := s.Set(`{"k":"v","n":1}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Value.GetFields()["k"].GetStringValue() != "v" {
		t.Fatalf("unexpected struct: %v", s.Value)
	}
	if err := s.Set("{not json"); err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestTime(t *testing.T) {
	t.Parallel()
	tv := &Time{}
	if err := tv.Set("2026-06-14T10:00:00Z"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tv.Value == nil || tv.Value.Year() != 2026 {
		t.Fatalf("unexpected time: %v", tv.Value)
	}
	if tv.String() != "2026-06-14T10:00:00Z" {
		t.Fatalf("unexpected String(): %q", tv.String())
	}
	if err := tv.Set("not-a-time"); err == nil {
		t.Fatal("expected error for bad time")
	}
}
