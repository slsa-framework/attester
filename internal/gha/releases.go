// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package gha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	gogithub "github.com/google/go-github/v90/github"
	intoto "github.com/in-toto/attestation/go/v1"
)

// CollectReleaseAssets returns one resource descriptor per asset of the
// release tagged tag in the watched repository. The digests come straight
// from the API, which records them as algorithm:hex when the asset is
// uploaded; assets predating GitHub's digest computation are downloaded and
// hashed as a fallback. The filter globs, when given, restrict collection by
// asset name.
func (c *Client) CollectReleaseAssets(ctx context.Context, tag string, filter []string) ([]*intoto.ResourceDescriptor, error) {
	release, _, err := c.gh.Repositories.GetReleaseByTag(ctx, c.Owner, c.Repo, tag)
	if err != nil {
		return nil, fmt.Errorf("fetching release %q: %w", tag, err)
	}

	assets, err := c.listReleaseAssets(ctx, release.GetID())
	if err != nil {
		return nil, err
	}

	subjects := make([]*intoto.ResourceDescriptor, 0, len(assets))
	for _, asset := range assets {
		match, err := matchesAnyGlob(filter, asset.GetName())
		if err != nil {
			return nil, err
		}
		if !match {
			slog.Debug("release asset does not match filter, skipping", "asset", asset.GetName())
			continue
		}

		digests, err := parseAssetDigest(asset.GetDigest())
		if err != nil {
			return nil, fmt.Errorf("asset %q: %w", asset.GetName(), err)
		}
		if digests == nil {
			slog.Info("release asset has no API digest, downloading to hash", "asset", asset.GetName())
			digest, err := c.hashReleaseAsset(ctx, asset.GetID())
			if err != nil {
				return nil, fmt.Errorf("hashing asset %q: %w", asset.GetName(), err)
			}
			digests = map[string]string{sha256Algo: digest}
		}

		subjects = append(subjects, &intoto.ResourceDescriptor{
			Name:   asset.GetName(),
			Uri:    asset.GetBrowserDownloadURL(),
			Digest: digests,
		})
	}
	return subjects, nil
}

// listReleaseAssets lists every asset of a release.
func (c *Client) listReleaseAssets(ctx context.Context, releaseID int64) ([]*gogithub.ReleaseAsset, error) {
	opts := &gogithub.ListOptions{PerPage: 100}
	var assets []*gogithub.ReleaseAsset
	for {
		page, res, err := c.gh.Repositories.ListReleaseAssets(ctx, c.Owner, c.Repo, releaseID, opts)
		if err != nil {
			return nil, fmt.Errorf("listing release assets: %w", err)
		}
		assets = append(assets, page...)
		if res.NextPage == 0 {
			return assets, nil
		}
		opts.Page = res.NextPage
	}
}

// parseAssetDigest parses the algorithm:hex digest the API reports for an
// asset. An empty digest returns (nil, nil): the asset predates GitHub's
// digest computation and must be hashed by hand.
func parseAssetDigest(digest string) (map[string]string, error) {
	if digest == "" {
		return nil, nil
	}
	algo, hexDigest, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || hexDigest == "" {
		return nil, fmt.Errorf("unparsable API digest %q", digest)
	}
	hexDigest = strings.ToLower(hexDigest)
	if _, err := hex.DecodeString(hexDigest); err != nil {
		return nil, fmt.Errorf("API digest %q is not hex: %w", digest, err)
	}
	return map[string]string{algo: hexDigest}, nil
}

// hashReleaseAsset downloads one release asset and returns its sha256.
func (c *Client) hashReleaseAsset(ctx context.Context, assetID int64) (string, error) {
	rc, redirect, err := c.gh.Repositories.DownloadReleaseAsset(ctx, c.Owner, c.Repo, assetID, http.DefaultClient)
	if err != nil {
		return "", fmt.Errorf("downloading asset: %w", err)
	}
	if rc == nil {
		// The client was told to follow redirects, so this should not
		// happen, but handle a bare redirect URL just in case.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, redirect, nil)
		if err != nil {
			return "", fmt.Errorf("creating download request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("downloading asset: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close() //nolint:errcheck,gosec
			return "", fmt.Errorf("downloading asset: HTTP %d", resp.StatusCode)
		}
		rc = resp.Body
	}
	defer rc.Close() //nolint:errcheck

	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return "", fmt.Errorf("hashing asset: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
