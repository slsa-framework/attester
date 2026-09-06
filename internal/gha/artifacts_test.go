// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestZip writes a zip with the given entries and returns its path.
func writeTestZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "artifact.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestHashArtifactZip(t *testing.T) {
	t.Parallel()
	path := writeTestZip(t, map[string]string{
		"bin/tool":   "binary-content",
		"../../evil": "hostile",
	})

	subs, err := hashArtifactZip(path, "release", "https://api.example/artifacts/5/zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 subjects, got %d", len(subs))
	}
	byName := map[string]string{}
	for _, s := range subs {
		byName[s.GetName()] = s.GetDigest()["sha256"]
		if strings.Contains(s.GetName(), "..") {
			t.Fatalf("hostile entry name escaped the artifact prefix: %q", s.GetName())
		}
		if !strings.HasPrefix(s.GetName(), "release/") {
			t.Fatalf("subject not namespaced by artifact: %q", s.GetName())
		}
	}
	if byName["release/bin/tool"] != sha256Hex("binary-content") {
		t.Fatalf("unexpected digest for bin/tool: %v", byName)
	}
}

func TestHashArtifactZipNotAZip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(path, []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	subs, err := hashArtifactZip(path, "blob-artifact", "https://api.example/artifacts/6/zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 1 || subs[0].GetName() != "blob-artifact" {
		t.Fatalf("expected single raw-blob subject, got: %v", subs)
	}
	if subs[0].GetDigest()["sha256"] != sha256Hex("not a zip") {
		t.Fatalf("unexpected digest: %v", subs[0].GetDigest())
	}
}

func TestCollectArtifacts(t *testing.T) {
	zipPath := writeTestZip(t, map[string]string{"tool": "tool-bytes"})
	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/repos/org/proj/actions/runs/7/artifacts", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `{"total_count": 2, "artifacts": [
			{"id": 5, "name": "release", "archive_download_url": "https://api.example/artifacts/5/zip"},
			{"id": 6, "name": "debug-logs", "archive_download_url": "https://api.example/artifacts/6/zip"}
		]}`)
	})
	mux.HandleFunc("/repos/org/proj/actions/artifacts/5/zip", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvURL+"/blob.zip", http.StatusFound)
	})
	mux.HandleFunc("/blob.zip", func(w http.ResponseWriter, _ *http.Request) {
		w.Write(zipData) //nolint:errcheck,gosec // test server response
	})

	c := testClient(t, mux)
	srvURL = strings.TrimSuffix(c.gh.BaseURL(), "/")

	// The filter keeps only the release artifact, so the debug-logs artifact
	// is never downloaded (its download route would 404).
	subs, err := c.CollectArtifacts(t.Context(), ArtifactOptions{
		Expand: true,
		Filter: []string{"release"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 1 || subs[0].GetName() != "release/tool" {
		t.Fatalf("unexpected subjects: %v", subs)
	}
	if subs[0].GetDigest()["sha256"] != sha256Hex("tool-bytes") {
		t.Fatalf("unexpected digest: %v", subs[0].GetDigest())
	}
}
