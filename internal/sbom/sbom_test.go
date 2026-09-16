// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spdxDoc is a minimal SPDX 2.3 document describing two packages, one of
// them digestless.
const spdxDoc = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "documentNamespace": "https://example.com/test-sbom",
  "creationInfo": {"created": "2026-09-16T00:00:00Z", "creators": ["Tool: test"]},
  "documentDescribes": ["SPDXRef-Package-tool", "SPDXRef-Package-docs"],
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-tool",
      "name": "tool-linux-amd64",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:generic/tool@1.0.0"}
      ],
      "checksums": [
        {"algorithm": "SHA256", "checksumValue": "8F434346648F6B96DF89DDA901C5176B10A6D83961DD3C1AC88B59B2DC327AA4"},
        {"algorithm": "SHA1", "checksumValue": "2f1e83b1e6c58239b0f8a9be6817f4f5f3d98f0f"}
      ]
    },
    {
      "SPDXID": "SPDXRef-Package-docs",
      "name": "docs-bundle",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION"
    }
  ]
}`

// writeSbomDir writes doc into a temp dir the fs collector can read.
func writeSbomDir(t *testing.T, doc string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.spdx.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCollectSubjects(t *testing.T) {
	t.Parallel()
	dir := writeSbomDir(t, spdxDoc)

	// The digestless docs-bundle node must fail the collection...
	if _, err := CollectSubjects(t.Context(), "fs:"+dir, nil); err == nil ||
		!strings.Contains(err.Error(), "docs-bundle") {
		t.Fatalf("expected a no-hashes error naming docs-bundle, got: %v", err)
	}

	// ...unless the filter narrows collection to the hashed element.
	subs, err := CollectSubjects(t.Context(), "fs:"+dir, []string{"tool-*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected one subject, got: %v", subs)
	}
	s := subs[0]
	if s.GetName() != "tool-linux-amd64" {
		t.Fatalf("unexpected name: %q", s.GetName())
	}
	if s.GetDigest()["sha256"] != "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4" {
		t.Fatalf("expected normalized sha256, got: %v", s.GetDigest())
	}
	if s.GetDigest()["sha1"] != "2f1e83b1e6c58239b0f8a9be6817f4f5f3d98f0f" {
		t.Fatalf("expected sha1 digest, got: %v", s.GetDigest())
	}
	if s.GetUri() != "pkg:generic/tool@1.0.0" {
		t.Fatalf("expected purl as uri, got: %q", s.GetUri())
	}
}

func TestCollectSubjectsNoMatch(t *testing.T) {
	t.Parallel()
	dir := writeSbomDir(t, spdxDoc)
	if _, err := CollectSubjects(t.Context(), "fs:"+dir, []string{"nothing-*"}); err == nil {
		t.Fatal("expected error when no top-level element matches")
	}
}

func TestCollectSubjectsBadSource(t *testing.T) {
	t.Parallel()
	if _, err := CollectSubjects(t.Context(), "nosuchdriver:xx", nil); err == nil {
		t.Fatal("expected error for an unknown collector driver")
	}
	if _, err := CollectSubjects(t.Context(), "fs:"+t.TempDir(), nil); err == nil {
		t.Fatal("expected error when the source holds no sboms")
	}
}
