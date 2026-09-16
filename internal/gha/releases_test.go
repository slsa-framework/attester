// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"net/http"
	"testing"
)

func TestParseAssetDigest(t *testing.T) {
	t.Parallel()
	d, err := parseAssetDigest("sha256:" + sha256Hex("x"))
	if err != nil || d[sha256Algo] != sha256Hex("x") {
		t.Fatalf("unexpected result: %v %v", d, err)
	}
	if d, err := parseAssetDigest(""); err != nil || d != nil {
		t.Fatalf("empty digest must return nil, nil: %v %v", d, err)
	}
	for _, in := range []string{"sha256", "sha256:", ":abc", "sha256:zz"} {
		if _, err := parseAssetDigest(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestCollectReleaseAssets(t *testing.T) {
	blob := "legacy-asset-bytes"

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/org/proj/releases/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `{"id": 11, "tag_name": "v1.0.0"}`)
	})
	mux.HandleFunc("/repos/org/proj/releases/11/assets", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `[
			{"id": 1, "name": "tool-linux-amd64", "digest": "sha256:%s",
			 "browser_download_url": "https://github.com/org/proj/releases/download/v1.0.0/tool-linux-amd64"},
			{"id": 2, "name": "tool-legacy",
			 "browser_download_url": "https://github.com/org/proj/releases/download/v1.0.0/tool-legacy"},
			{"id": 3, "name": "notes.txt", "digest": "sha256:%s",
			 "browser_download_url": "https://github.com/org/proj/releases/download/v1.0.0/notes.txt"}
		]`, sha256Hex("binary-one"), sha256Hex("notes"))
	})
	// The legacy asset carries no API digest, so it is downloaded and hashed.
	mux.HandleFunc("/repos/org/proj/releases/assets/2", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, "%s", blob)
	})

	c := testClient(t, mux)

	subs, err := c.CollectReleaseAssets(t.Context(), "v1.0.0", []string{"tool-*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 subjects (notes.txt filtered out), got: %v", subs)
	}
	if subs[0].GetName() != "tool-linux-amd64" || subs[0].GetDigest()[sha256Algo] != sha256Hex("binary-one") {
		t.Fatalf("unexpected API-digest subject: %v", subs[0])
	}
	if subs[1].GetName() != "tool-legacy" || subs[1].GetDigest()[sha256Algo] != sha256Hex(blob) {
		t.Fatalf("unexpected hashed subject: %v", subs[1])
	}
	if subs[0].GetUri() != "https://github.com/org/proj/releases/download/v1.0.0/tool-linux-amd64" {
		t.Fatalf("unexpected uri: %q", subs[0].GetUri())
	}
}

func TestCollectReleaseAssetsMissingRelease(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/org/proj/releases/tags/nope", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	c := testClient(t, mux)
	if _, err := c.CollectReleaseAssets(t.Context(), "nope", nil); err == nil {
		t.Fatal("expected error for a missing release")
	}
}
