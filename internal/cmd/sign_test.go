// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// writeTestKey generates an ed25519 private key and writes it to a PKCS#8 PEM
// file, returning the path.
func writeTestKey(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSignWithKeyEmitsDSSE runs the build subcommand signing with a private key
// and checks the output is a DSSE envelope wrapping the statement.
func TestSignWithKeyEmitsDSSE(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	subject := filepath.Join(dir, "subject.txt")
	if err := os.WriteFile(subject, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "att.json")
	keyPath := writeTestKey(t, dir)

	root := New()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"build", "-o", out,
		"--signing-key", keyPath,
		"--builder-id", "https://example.com/builder",
		subject,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("output is not valid json: %v", err)
	}
	if env.PayloadType != "https://in-toto.io/Statement/v1" {
		t.Fatalf("unexpected payloadType: %q", env.PayloadType)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].Sig == "" {
		t.Fatalf("expected one signature, got: %+v", env.Signatures)
	}

	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var stmt map[string]any
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatalf("payload is not a valid statement: %v", err)
	}
	if stmt["predicateType"] != "https://slsa.dev/provenance/v1" {
		t.Fatalf("unexpected predicateType: %v", stmt["predicateType"])
	}
}

// TestSignFalseEmitsBareStatement checks --sign=false skips signing entirely.
func TestSignFalseEmitsBareStatement(t *testing.T) {
	t.Parallel()
	stmt, err := runBuild(t, "--builder-id", "https://example.com/builder")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stmt["predicateType"] != "https://slsa.dev/provenance/v1" {
		t.Fatalf("unexpected predicateType: %v", stmt["predicateType"])
	}
	if _, ok := stmt["payloadType"]; ok {
		t.Fatal("bare statement must not be a DSSE envelope")
	}
}
