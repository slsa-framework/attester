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
	_ pflag.Value = (*SubjectSlice)(nil)
	_ pflag.Value = (*RawJSON)(nil)
	_ pflag.Value = (*ChecksumFileSlice)(nil)
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

func TestSubjectSlice(t *testing.T) {
	t.Parallel()
	sha := "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"

	t.Run("valid-and-normalized", func(t *testing.T) {
		t.Parallel()
		s := &SubjectSlice{}
		// Upper-case digests must be normalized to lower case.
		if err := s.Set("sha256:" + "8F434346648F6B96DF89DDA901C5176B10A6D83961DD3C1AC88B59B2DC327AA4"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := s.Set("gitCommit:2f1e83b1e6c58239b0f8a9be6817f4f5f3d98f0f"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(s.Values) != 2 {
			t.Fatalf("expected 2 values, got %d", len(s.Values))
		}
		if got := s.Values[0].GetDigest()["sha256"]; got != sha {
			t.Fatalf("unexpected digest: %q", got)
		}
		if _, ok := s.Values[1].GetDigest()["gitCommit"]; !ok {
			t.Fatalf("expected gitCommit digest: %v", s.Values[1].GetDigest())
		}
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{
			"",                   // empty
			"sha256",             // no colon
			"sha256:",            // no digest
			":abcd",              // no algorithm
			"not-an-algo:" + sha, // unknown algorithm
			"sha256:zz",          // not hex
			"sha256:abcd",        // wrong length
			"sha512:" + sha,      // wrong length for algorithm
		} {
			s := &SubjectSlice{}
			if err := s.Set(in); err == nil {
				t.Errorf("expected error for %q", in)
			}
		}
	})
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

func TestChecksumFileSlice(t *testing.T) {
	t.Parallel()
	sha256 := "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"
	sha512 := "b09e99c2c541ef4a11916549b4bad1bbb70e1a41f56a3e51fd57f39e18d92283" +
		"a6ec0c68f446f051a2678de263e30ad3ba0a3e0d3f6f0d227ba76e5b6e1a4a4b"

	writeFile := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "checksums.txt")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("sha256sum-format", func(t *testing.T) {
		t.Parallel()
		// Upper-case digest, binary-mode marker and blank lines must all be
		// handled; the sha512 line infers its algorithm from the length.
		c := &ChecksumFileSlice{}
		content := "8F434346648F6B96DF89DDA901C5176B10A6D83961DD3C1AC88B59B2DC327AA4  bin/tool\n" +
			"\n" +
			sha256 + " *tool.tar.gz\n" +
			sha512 + "  big.bin\n"
		if err := c.Set(writeFile(t, content)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(c.Values) != 3 {
			t.Fatalf("expected 3 subjects, got %d", len(c.Values))
		}
		if c.Values[0].GetName() != "bin/tool" || c.Values[0].GetDigest()["sha256"] != sha256 {
			t.Fatalf("unexpected first subject: %v", c.Values[0])
		}
		if c.Values[1].GetName() != "tool.tar.gz" {
			t.Fatalf("binary marker not stripped: %v", c.Values[1])
		}
		if c.Values[2].GetDigest()["sha512"] != sha512 {
			t.Fatalf("expected sha512 digest: %v", c.Values[2])
		}
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		for name, content := range map[string]string{
			"missing-name":   sha256 + "\n",
			"not-hex":        "zz434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4  x\n",
			"bad-length":     "abcd  x\n",
			"duplicate-name": sha256 + "  x\n" + sha256 + "  x\n",
		} {
			c := &ChecksumFileSlice{}
			if err := c.Set(writeFile(t, content)); err == nil {
				t.Errorf("expected error for %s", name)
			}
		}
		c := &ChecksumFileSlice{}
		if err := c.Set("/no/such/file"); err == nil {
			t.Error("expected error for missing file")
		}
	})
}

func TestRawJSON(t *testing.T) {
	t.Parallel()
	r := &RawJSON{}
	if err := r.Set(`{"k":"v"}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(r.Data) != `{"k":"v"}` {
		t.Fatalf("unexpected data: %s", r.Data)
	}

	path := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(path, []byte(`{"from":"file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Set("@" + path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(r.Data) != `{"from":"file"}` {
		t.Fatalf("unexpected data: %s", r.Data)
	}

	if err := r.Set(`{not json`); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if err := r.Set("@/no/such/file.json"); err == nil {
		t.Fatal("expected error for missing file")
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
