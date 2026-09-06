// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-FileCopyrightText: Copyright The Kubernetes Authors (ported from kubernetes-sigs/tejolote)
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	gogithub "github.com/google/go-github/v90/github"
	intoto "github.com/in-toto/attestation/go/v1"
)

// maxZipEntrySize caps how many bytes are read and hashed from a single file
// inside a GitHub Actions artifact zip. Real artifacts are far smaller and a
// larger declared size may be a decompression bomb.
const maxZipEntrySize = 10 << 30 // 10 GiB

// ArtifactOptions tune how the run's artifacts are collected.
type ArtifactOptions struct {
	// Expand controls how artifacts are hashed. When true each artifact zip
	// is unpacked and every contained file becomes its own subject, named
	// "<artifact>/<path in zip>". When false each artifact archive is hashed
	// as a single subject.
	Expand bool
	// Filter, when non-empty, is a list of globs (path.Match syntax) matched
	// against artifact names; only matching artifacts are collected.
	Filter []string
}

// CollectArtifacts downloads the run's GitHub Actions artifacts and returns
// one resource descriptor per attested file.
func (c *Client) CollectArtifacts(ctx context.Context, opts ArtifactOptions) ([]*intoto.ResourceDescriptor, error) {
	artifacts, err := c.listArtifacts(ctx)
	if err != nil {
		return nil, err
	}

	var subjects []*intoto.ResourceDescriptor
	for _, artifact := range artifacts {
		match, err := matchesAnyGlob(opts.Filter, artifact.GetName())
		if err != nil {
			return nil, err
		}
		if !match {
			slog.Debug("artifact does not match filter, skipping", "artifact", artifact.GetName())
			continue
		}
		subs, err := c.collectArtifact(ctx, artifact, opts.Expand)
		if err != nil {
			return nil, fmt.Errorf("collecting artifact %q: %w", artifact.GetName(), err)
		}
		subjects = append(subjects, subs...)
	}
	return subjects, nil
}

// listArtifacts lists every artifact the watched run stored.
func (c *Client) listArtifacts(ctx context.Context) ([]*gogithub.Artifact, error) {
	opts := &gogithub.ListOptions{PerPage: 100}
	var artifacts []*gogithub.Artifact
	for {
		page, res, err := c.gh.Actions.ListWorkflowRunArtifacts(ctx, c.Owner, c.Repo, c.RunID, opts)
		if err != nil {
			return nil, fmt.Errorf("listing run artifacts: %w", err)
		}
		artifacts = append(artifacts, page.Artifacts...)
		if res.NextPage == 0 {
			return artifacts, nil
		}
		opts.Page = res.NextPage
	}
}

// collectArtifact downloads one artifact and hashes it into subjects.
func (c *Client) collectArtifact(ctx context.Context, artifact *gogithub.Artifact, expand bool) ([]*intoto.ResourceDescriptor, error) {
	dlURL, _, err := c.gh.Actions.DownloadArtifact(ctx, c.Owner, c.Repo, artifact.GetID(), 3)
	if err != nil {
		return nil, fmt.Errorf("resolving download url: %w", err)
	}

	tmp, err := os.CreateTemp("", "artifact-*.zip")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if err := download(ctx, dlURL.String(), tmp); err != nil {
		return nil, err
	}

	if expand {
		return hashArtifactZip(tmp.Name(), artifact.GetName(), artifact.GetArchiveDownloadURL())
	}
	digest, err := sha256File(tmp.Name())
	if err != nil {
		return nil, err
	}
	return []*intoto.ResourceDescriptor{{
		Name:   artifact.GetName(),
		Uri:    artifact.GetArchiveDownloadURL(),
		Digest: map[string]string{"sha256": digest},
	}}, nil
}

// download fetches url into w. The artifact download URL returned by the API
// is pre-signed, so no additional authentication is attached.
func download(ctx context.Context, url string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating download request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading artifact: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading artifact: HTTP %d", resp.StatusCode)
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("writing artifact: %w", err)
	}
	return nil
}

// hashArtifactZip unpacks a downloaded GitHub Actions artifact (always a zip)
// and returns one subject per contained file, named "<artifact>/<path in
// zip>" so files sharing a name across artifacts stay distinct. When the blob
// is not a valid zip it falls back to hashing the raw blob as one subject.
func hashArtifactZip(zipPath, artifactName, artifactURL string) ([]*intoto.ResourceDescriptor, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		slog.Warn("artifact is not a zip archive, hashing raw blob", "artifact", artifactName, "error", err)
		digest, herr := sha256File(zipPath)
		if herr != nil {
			return nil, herr
		}
		return []*intoto.ResourceDescriptor{{
			Name:   artifactName,
			Uri:    artifactURL,
			Digest: map[string]string{"sha256": digest},
		}}, nil
	}
	defer zr.Close()

	subjects := make([]*intoto.ResourceDescriptor, 0, len(zr.File))
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		digest, err := sha256ZipEntry(zf)
		if err != nil {
			return nil, fmt.Errorf("hashing %s: %w", zf.Name, err)
		}
		// Drop the leading slash so a hostile entry name (eg "../../x")
		// cannot escape the artifact-name prefix.
		entry := strings.TrimPrefix(path.Clean("/"+zf.Name), "/")
		subjects = append(subjects, &intoto.ResourceDescriptor{
			Name:   artifactName + "/" + entry,
			Uri:    zipEntryURI(artifactURL, entry),
			Digest: map[string]string{"sha256": digest},
		})
	}
	return subjects, nil
}

// zipEntryURI points an artifact's download URL at a specific file inside the
// zip using the URL fragment, eg .../artifacts/42/zip#bin/attester.
func zipEntryURI(artifactURL, entry string) string {
	u, err := url.Parse(artifactURL)
	if err != nil {
		return artifactURL + "#" + entry
	}
	u.Fragment = entry
	return u.String()
}

// sha256ZipEntry hashes the decompressed content of one zip entry.
func sha256ZipEntry(zf *zip.File) (string, error) {
	if zf.UncompressedSize64 > maxZipEntrySize {
		return "", fmt.Errorf("entry %s declares %d bytes, over the %d limit", zf.Name, zf.UncompressedSize64, uint64(maxZipEntrySize))
	}
	rc, err := zf.Open()
	if err != nil {
		return "", fmt.Errorf("opening zip entry: %w", err)
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(rc, maxZipEntrySize)); err != nil {
		return "", fmt.Errorf("hashing zip entry: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sha256File hashes a file on disk.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// matchesAnyGlob reports whether name matches at least one of the globs
// (path.Match syntax). An empty glob list matches everything.
func matchesAnyGlob(globs []string, name string) (bool, error) {
	if len(globs) == 0 {
		return true, nil
	}
	for _, glob := range globs {
		match, err := path.Match(glob, name)
		if err != nil {
			return false, fmt.Errorf("invalid artifacts filter %q: %w", glob, err)
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}
