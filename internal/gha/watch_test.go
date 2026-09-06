// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	gogithub "github.com/google/go-github/v90/github"
)

// servef writes a canned response body from a test handler.
func servef(w http.ResponseWriter, format string, args ...any) {
	fmt.Fprintf(w, format, args...) //nolint:errcheck // test server response
}

// testClient wires a Client to a fake GitHub API served by mux.
func testClient(t *testing.T, mux *http.ServeMux) *Client {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	base := srv.URL + "/"
	gh, err := gogithub.NewClient(gogithub.WithURLs(&base, nil))
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{Owner: "org", Repo: "proj", RunID: 7}
	c.SetAPIClient(gh)
	return c
}

func TestWaitForRunCompletion(t *testing.T) {
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/org/proj/actions/runs/7", func(w http.ResponseWriter, _ *http.Request) {
		status := "in_progress"
		if polls.Add(1) > 2 {
			status = "completed"
		}
		servef(w, `{"id": 7, "status": %q, "head_sha": "abc123"}`, status)
	})

	c := testClient(t, mux)
	run, err := c.Wait(t.Context(), WatchOptions{PollInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run.GetStatus() != "completed" {
		t.Fatalf("unexpected final status: %q", run.GetStatus())
	}
	if polls.Load() < 3 {
		t.Fatalf("expected at least 3 polls, got %d", polls.Load())
	}
}

func TestWaitTimesOut(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/org/proj/actions/runs/7", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `{"id": 7, "status": "in_progress"}`)
	})
	c := testClient(t, mux)
	if _, err := c.Wait(t.Context(), WatchOptions{
		PollInterval: 5 * time.Millisecond,
		Timeout:      20 * time.Millisecond,
	}); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestWaitSameRunExcludesOwnJob(t *testing.T) {
	// Pretend we run inside the watched run, on runner "runner-9". The build
	// job completes but our own attest job never does; the wait must still
	// finish because our job is excluded.
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "org/proj")
	t.Setenv("GITHUB_RUN_ID", "7")
	t.Setenv("GITHUB_JOB", "attest")
	t.Setenv("RUNNER_NAME", "runner-9")
	t.Setenv("GITHUB_TOKEN", "")

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/org/proj/actions/runs/7/jobs", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `{"total_count": 2, "jobs": [
			{"id": 1, "name": "Attest the build", "status": "in_progress", "runner_name": "runner-9"},
			{"id": 2, "name": "build", "status": "completed", "conclusion": "success", "runner_name": "runner-3"}
		]}`)
	})
	mux.HandleFunc("/repos/org/proj/actions/runs/7", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `{"id": 7, "status": "in_progress", "head_sha": "abc123"}`)
	})

	c := testClient(t, mux)
	run, err := c.Wait(t.Context(), WatchOptions{PollInterval: 5 * time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run.GetID() != 7 {
		t.Fatalf("unexpected run: %v", run)
	}
}

func TestWaitWatchedJobStillRunning(t *testing.T) {
	// Watching a named job that never completes must time out even though
	// other jobs are done.
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/org/proj/actions/runs/7/jobs", func(w http.ResponseWriter, _ *http.Request) {
		servef(w, `{"total_count": 2, "jobs": [
			{"id": 1, "name": "build", "status": "completed", "conclusion": "success"},
			{"id": 2, "name": "release", "status": "in_progress"}
		]}`)
	})
	c := testClient(t, mux)
	if _, err := c.Wait(t.Context(), WatchOptions{
		Jobs:         []string{"release"},
		PollInterval: 5 * time.Millisecond,
		Timeout:      25 * time.Millisecond,
	}); err == nil {
		t.Fatal("expected timeout waiting for the watched job")
	}
}
