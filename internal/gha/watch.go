// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-FileCopyrightText: Copyright The Kubernetes Authors (ported from kubernetes-sigs/tejolote)
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
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
	// AllowSharedJob skips the dedicated-job check when attesting the run
	// the watcher itself runs in. See checkDedicatedJob for why sharing a
	// job with build steps is refused by default.
	AllowSharedJob bool
}

// statusCompleted is the status the API reports for finished runs, jobs and
// steps.
const statusCompleted = "completed"

// statusInProgress is the status the API reports for the step (and job)
// currently executing.
const statusInProgress = "in_progress"

// dedicatedJobSteps are the step names allowed to appear in the attester's
// job besides its own: the runner's infrastructure steps plus the steps of
// the attest_actions reusable workflow in slsa-framework/actions (keep in
// sync with .github/workflows/attest_actions.yml there).
var dedicatedJobSteps = map[string]bool{
	"Set up job":                        true,
	"Initialize containers":             true,
	"Stop containers":                   true,
	"Complete job":                      true,
	"Locate this workflow's repository": true,
	"Check out the SLSA actions":        true,
	"Attestation summary":               true,
	"Upload attestation":                true,
}

// checkDedicatedJob refuses to attest from a job that contains any step
// besides the attester's own, no matter whether it runs before or after:
// steps that ran earlier can tamper with the runner (replace the attester,
// poison the tool cache) and forge the attestation, and every step in the
// job — including later ones — shares the OIDC workload identity the
// attestation is signed with, so it could mint an equally-valid signature of
// its own. The attester must run in a job of its own. This guards against
// honest misconfiguration; a hostile step that already ran could equally
// tamper with this very check, which is why verifiers must also pin the
// attestation's signing identity.
func checkDedicatedJob(job *gogithub.WorkflowJob) error {
	foreign := make([]string, 0, len(job.Steps))
	for _, step := range job.Steps {
		name := step.GetName()
		switch {
		case step.GetStatus() == statusInProgress:
			// The attester's own step (steps run sequentially, so the
			// in-progress one is the one running this code).
			continue
		case dedicatedJobSteps[name]:
			continue
		case strings.HasPrefix(name, "Pre ") || strings.HasPrefix(name, "Post "):
			// Pre/post phases of an action; the action's main step is
			// always listed too, so a foreign action is caught there.
			continue
		}
		foreign = append(foreign, name)
	}
	if len(foreign) == 0 {
		return nil
	}
	return fmt.Errorf(
		"job %q is not dedicated to attesting: step(s) %q share the job and its signing identity with the attester; "+
			"attest from a job with no other steps (or pass --allow-shared-job to accept the risk)",
		job.GetName(), strings.Join(foreign, ", "))
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
			if !opts.AllowSharedJob {
				if err := checkDedicatedJob(job); err != nil {
					return nil, err
				}
			}
		default:
			slog.Info("same-run detected; could not uniquely resolve own job, excluding by key", "job", excludeJob)
			if !opts.AllowSharedJob {
				slog.Warn("could not verify the attester runs in a dedicated job")
			}
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
	return run.GetStatus() == statusCompleted, nil
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
		if job.GetStatus() != statusCompleted {
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
