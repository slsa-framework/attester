// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package gha observes GitHub Actions workflow runs: it waits for a run's
// jobs to complete, collects the run's artifacts as attestation subjects, and
// renders the run as a SLSA build provenance predicate.
//
// The job watching and artifact collection logic is ported from the tejolote
// attester (kubernetes-sigs/tejolote, Apache-2.0, Copyright The Kubernetes
// Authors), adapted to feed the slsa-attester library.
package gha

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	gogithub "github.com/google/go-github/v90/github"
)

// Environment variables the GitHub Actions runner sets.
const (
	envRepository = "GITHUB_REPOSITORY"
	envRunID      = "GITHUB_RUN_ID"
	envActions    = "GITHUB_ACTIONS"
	envJob        = "GITHUB_JOB"
	envRunner     = "RUNNER_NAME"
	envToken      = "GITHUB_TOKEN"
)

// Client watches one GitHub Actions workflow run.
type Client struct {
	Owner string
	Repo  string
	RunID int64

	gh *gogithub.Client
}

// New returns a Client for the run identified by a github://owner/repo/runID
// spec. The GitHub API client authenticates with $GITHUB_TOKEN when set.
func New(spec string) (*Client, error) {
	owner, repo, runID, err := ParseSpec(spec)
	if err != nil {
		return nil, err
	}
	var clientOpts []gogithub.ClientOptionsFunc
	if token := os.Getenv(envToken); token != "" {
		clientOpts = append(clientOpts, gogithub.WithAuthToken(token))
	}
	gh, err := gogithub.NewClient(clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating github client: %w", err)
	}
	return &Client{Owner: owner, Repo: repo, RunID: runID, gh: gh}, nil
}

// SetAPIClient replaces the GitHub API client (for tests).
func (c *Client) SetAPIClient(gh *gogithub.Client) { c.gh = gh }

// ParseSpec parses a github://owner/repo/runID run spec.
func ParseSpec(spec string) (owner, repo string, runID int64, err error) {
	rest, ok := strings.CutPrefix(spec, "github://")
	if !ok {
		return "", "", 0, fmt.Errorf("invalid run spec %q: want github://owner/repo/runID", spec)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", "", 0, fmt.Errorf("invalid run spec %q: want github://owner/repo/runID", spec)
	}
	runID, err = strconv.ParseInt(parts[2], 10, 64)
	if err != nil || runID <= 0 {
		return "", "", 0, fmt.Errorf("invalid run id in spec %q", spec)
	}
	return parts[0], parts[1], runID, nil
}

// SpecFromEnvironment derives the current run's spec from the environment the
// GitHub Actions runner sets, or "" when not running in GitHub Actions.
func SpecFromEnvironment() string {
	repo := os.Getenv(envRepository)
	runID := os.Getenv(envRunID)
	if repo == "" || runID == "" {
		return ""
	}
	return "github://" + repo + "/" + runID
}

// sameRun reports whether this process is executing inside the GitHub Actions
// run the client is watching.
func (c *Client) sameRun() bool {
	return os.Getenv(envActions) == "true" &&
		os.Getenv(envRepository) == c.Owner+"/"+c.Repo &&
		os.Getenv(envRunID) == strconv.FormatInt(c.RunID, 10)
}

// matchJobName checks if an API job name matches a YAML job key. GitHub
// Actions formats reusable workflow job names as "caller_key / inner_job", so
// we match if the API name equals the key or starts with "key / ".
func matchJobName(apiName, yamlKey string) bool {
	return apiName == yamlKey || strings.HasPrefix(apiName, yamlKey+" / ")
}

// matchesAnyJobName checks if an API job name matches any of the given names.
func matchesAnyJobName(apiName string, names []string) bool {
	for _, n := range names {
		if matchJobName(apiName, n) {
			return true
		}
	}
	return false
}
