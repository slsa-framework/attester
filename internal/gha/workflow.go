// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-FileCopyrightText: Copyright The Kubernetes Authors (ported from kubernetes-sigs/tejolote)
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	gogithub "github.com/google/go-github/v90/github"
	"sigs.k8s.io/yaml"
)

// envEventPath points at the JSON payload of the event that triggered the
// current run; the GitHub Actions runner sets it.
const envEventPath = "GITHUB_EVENT_PATH"

// workflowInput is a single input definition in a workflow YAML.
type workflowInput struct {
	Default any `json:"default"`
}

// workflowTrigger is the "on" section of a workflow YAML.
type workflowTrigger struct {
	WorkflowDispatch *workflowTriggerInputs `json:"workflow_dispatch"`
	WorkflowCall     *workflowTriggerInputs `json:"workflow_call"`
}

type workflowTriggerInputs struct {
	Inputs map[string]workflowInput `json:"inputs"`
}

// workflowData is a parsed representation of a GitHub Actions workflow YAML.
// Note: in YAML, "on" is a boolean keyword that gets converted to "true" by
// sigs.k8s.io/yaml's YAML-to-JSON conversion, so we use json:"true" here.
type workflowData struct {
	On workflowTrigger `json:"true"`
}

// inputDefaults returns the default values of the inputs declared by the
// workflow_dispatch and workflow_call triggers, merged into one map.
func (wd *workflowData) inputDefaults() map[string]any {
	defaults := map[string]any{}
	for _, trigger := range []*workflowTriggerInputs{wd.On.WorkflowDispatch, wd.On.WorkflowCall} {
		if trigger == nil {
			continue
		}
		for name, input := range trigger.Inputs {
			defaults[name] = input.Default
		}
	}
	return defaults
}

// RunInputs returns the workflow inputs of the watched run for the
// provenance's external parameters. When running inside the attested run the
// actual values come from the triggering event's payload; otherwise the
// workflow definition is fetched at the run's commit and the declared
// defaults are recorded, since the API does not expose the values a
// triggerer overrode. Inputs are best-effort: failures are logged and an
// empty map returned, so a deleted workflow file does not fail the
// attestation.
func (c *Client) RunInputs(ctx context.Context, run *gogithub.WorkflowRun) map[string]any {
	if c.sameRun() {
		inputs, err := eventInputs()
		if err != nil {
			slog.Warn("reading inputs from the event payload", "error", err)
		} else if len(inputs) > 0 {
			return inputs
		}
	}

	inputs, err := c.workflowInputDefaults(ctx, run.GetPath(), run.GetHeadSHA())
	if err != nil {
		slog.Warn("reading input defaults from the workflow definition", "error", err)
		return nil
	}
	return inputs
}

// eventInputs reads the "inputs" object from the triggering event's payload
// (workflow_dispatch runs carry the values the triggerer chose).
func eventInputs() (map[string]any, error) {
	path := os.Getenv(envEventPath)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // the runner sets GITHUB_EVENT_PATH; reading it is the point
	if err != nil {
		return nil, fmt.Errorf("reading event payload: %w", err)
	}
	var event struct {
		Inputs map[string]any `json:"inputs"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("parsing event payload: %w", err)
	}
	return event.Inputs, nil
}

// workflowInputDefaults fetches the workflow YAML at ref through the contents
// API and returns the declared input defaults.
func (c *Client) workflowInputDefaults(ctx context.Context, path, ref string) (map[string]any, error) {
	if path == "" {
		return nil, nil
	}
	fileContent, _, _, err := c.gh.Repositories.GetContents(
		ctx, c.Owner, c.Repo, path, &gogithub.RepositoryContentGetOptions{Ref: ref},
	)
	if err != nil {
		return nil, fmt.Errorf("fetching workflow file: %w", err)
	}
	if fileContent == nil {
		return nil, fmt.Errorf("%s is not a file", path)
	}
	yamlData, err := fileContent.GetContent()
	if err != nil {
		return nil, fmt.Errorf("decoding workflow contents: %w", err)
	}

	var wf workflowData
	if err := yaml.Unmarshal([]byte(yamlData), &wf); err != nil {
		return nil, fmt.Errorf("parsing workflow YAML: %w", err)
	}
	return wf.inputDefaults(), nil
}
