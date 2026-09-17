// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	gogithub "github.com/google/go-github/v90/github"
)

const workflowYAML = `name: release
on:
  workflow_dispatch:
    inputs:
      environment:
        type: string
        default: staging
      skip-tests:
        type: boolean
        default: false
  push: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make
`

// contentsMux serves the workflow file through the fake contents API.
func contentsMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/org/proj/contents/.github/workflows/ci.yml", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `{"type": "file", "name": "ci.yml", "encoding": "base64", "content": %q}`,
			base64.StdEncoding.EncodeToString([]byte(workflowYAML)))
	})
	return mux
}

func testRun() *gogithub.WorkflowRun {
	return &gogithub.WorkflowRun{
		Path:    gogithub.Ptr(".github/workflows/ci.yml"),
		HeadSHA: gogithub.Ptr("abc123"),
	}
}

func TestRunInputsFromWorkflowDefaults(t *testing.T) {
	// Not running inside the attested run: the declared defaults are
	// recorded, including the yaml "on" keyword quirk handling.
	t.Setenv("GITHUB_ACTIONS", "")
	c := testClient(t, contentsMux(t))

	inputs := c.RunInputs(t.Context(), testRun())
	if inputs["environment"] != "staging" || inputs["skip-tests"] != false {
		t.Fatalf("unexpected input defaults: %v", inputs)
	}
}

func TestRunInputsFromEventPayload(t *testing.T) {
	// Inside the attested run the actual values come from the event payload
	// and win over the workflow defaults.
	eventPath := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(eventPath,
		[]byte(`{"inputs": {"environment": "prod", "skip-tests": "true"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "org/proj")
	t.Setenv("GITHUB_RUN_ID", "7")
	t.Setenv("GITHUB_EVENT_PATH", eventPath)

	c := testClient(t, contentsMux(t))
	inputs := c.RunInputs(t.Context(), testRun())
	if inputs["environment"] != "prod" || inputs["skip-tests"] != "true" {
		t.Fatalf("expected event payload values, got: %v", inputs)
	}
}

func TestRunInputsBestEffort(t *testing.T) {
	// A run without a fetchable workflow definition must not fail: inputs
	// are best-effort and come back empty.
	t.Setenv("GITHUB_ACTIONS", "")
	c := testClient(t, http.NewServeMux())
	if inputs := c.RunInputs(t.Context(), testRun()); len(inputs) != 0 {
		t.Fatalf("expected no inputs, got: %v", inputs)
	}
}
