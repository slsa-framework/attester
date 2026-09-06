// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-FileCopyrightText: Copyright The Kubernetes Authors (ported from kubernetes-sigs/tejolote)
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	gogithub "github.com/google/go-github/v90/github"
)

// WatchOptions tune how a run is watched.
type WatchOptions struct {
	// Jobs restricts watching to these job names (YAML keys or display
	// names). Empty means every job in the run.
	Jobs []string
	// Timeout is the maximum time to wait for the run to complete. Zero
	// disables the timeout.
	Timeout time.Duration
	// PollInterval is how often the run is polled (default 15s).
	PollInterval time.Duration
}

// Wait polls the watched run until it completes and returns its final state.
//
// When the process is running inside the very run it is watching, waiting for
// the whole run to complete would deadlock: the watcher's own job is part of
// the run. In that case the watcher switches to job-level watching and
// excludes its own job, resolved through the runner name because the jobs API
// reports display names while $GITHUB_JOB only carries the YAML key.
func (c *Client) Wait(ctx context.Context, opts WatchOptions) (*gogithub.WorkflowRun, error) {
	interval := opts.PollInterval
	if interval == 0 {
		interval = 15 * time.Second
	}

	excludeJob := ""
	if c.sameRun() {
		excludeJob = os.Getenv(envJob)
		job, err := c.currentJob(ctx)
		switch {
		case err != nil:
			slog.Warn("resolving own job, falling back to $GITHUB_JOB", "job", excludeJob, "error", err)
		case job != nil:
			excludeJob = job.GetName()
			slog.Info("same-run detected; excluding own job", "job", excludeJob)
		default:
			slog.Info("same-run detected; could not uniquely resolve own job, excluding by key", "job", excludeJob)
		}
	}

	var deadline time.Time
	if opts.Timeout > 0 {
		deadline = time.Now().Add(opts.Timeout)
	}

	watchJobs := len(opts.Jobs) > 0 || excludeJob != ""
	for {
		var done bool
		var err error
		if watchJobs {
			done, err = c.jobsCompleted(ctx, opts.Jobs, excludeJob)
		} else {
			done, err = c.runCompleted(ctx)
		}
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out after %s waiting for the run to complete", opts.Timeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}

	run, _, err := c.gh.Actions.GetWorkflowRunByID(ctx, c.Owner, c.Repo, c.RunID)
	if err != nil {
		return nil, fmt.Errorf("fetching run: %w", err)
	}
	return run, nil
}

// runCompleted reports whether the whole run has completed.
func (c *Client) runCompleted(ctx context.Context) (bool, error) {
	run, _, err := c.gh.Actions.GetWorkflowRunByID(ctx, c.Owner, c.Repo, c.RunID)
	if err != nil {
		return false, fmt.Errorf("fetching run: %w", err)
	}
	return run.GetStatus() == "completed", nil
}

// jobsCompleted reports whether every watched job has completed. With an
// explicit job list only those jobs are checked; excludeJob (the watcher's
// own job) is always skipped.
func (c *Client) jobsCompleted(ctx context.Context, jobNames []string, excludeJob string) (bool, error) {
	jobs, err := c.runJobs(ctx)
	if err != nil {
		return false, err
	}
	for _, job := range jobs {
		name := job.GetName()
		if excludeJob != "" && matchJobName(name, excludeJob) {
			continue
		}
		if len(jobNames) > 0 && !matchesAnyJobName(name, jobNames) {
			continue
		}
		if job.GetStatus() != "completed" {
			slog.Info("waiting for job", "job", name, "status", job.GetStatus())
			return false, nil
		}
	}
	return true, nil
}

// currentJob resolves the job this process is running in by matching the
// runner name against the run's in-progress jobs. Returns (nil, nil) when
// there is no unique match.
func (c *Client) currentJob(ctx context.Context) (*gogithub.WorkflowJob, error) {
	runnerName := os.Getenv(envRunner)
	if runnerName == "" {
		return nil, nil
	}
	jobs, err := c.runJobs(ctx)
	if err != nil {
		return nil, err
	}
	var match *gogithub.WorkflowJob
	for _, job := range jobs {
		if job.GetStatus() == "in_progress" && job.GetRunnerName() == runnerName {
			if match != nil {
				// Ambiguous: two in-progress jobs share the runner name.
				return nil, nil
			}
			match = job
		}
	}
	return match, nil
}

// runJobs lists every job of the watched run.
func (c *Client) runJobs(ctx context.Context) ([]*gogithub.WorkflowJob, error) {
	opts := &gogithub.ListWorkflowJobsOptions{
		ListOptions: gogithub.ListOptions{PerPage: 100},
	}
	var jobs []*gogithub.WorkflowJob
	for {
		page, res, err := c.gh.Actions.ListWorkflowJobs(ctx, c.Owner, c.Repo, c.RunID, opts)
		if err != nil {
			return nil, fmt.Errorf("listing run jobs: %w", err)
		}
		jobs = append(jobs, page.Jobs...)
		if res.NextPage == 0 {
			return jobs, nil
		}
		opts.Page = res.NextPage
	}
}
