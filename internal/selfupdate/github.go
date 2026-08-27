package selfupdate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const apiBaseDefault = "https://api.github.com"

// Release is the subset of a GitHub release used by the updater.
type Release struct {
	TagName    string  `json:"tag_name"`
	Name       string  `json:"name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

// Asset is one downloadable file in a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// ReleasesClient fetches release metadata from the GitHub API.
type ReleasesClient struct {
	BaseURL   string
	Owner     string
	Repo      string
	HTTP      *http.Client
	UserAgent string
}

func (c *ReleasesClient) url() string {
	if c.BaseURL == "" {
		return apiBaseDefault
	}
	return strings.TrimRight(c.BaseURL, "/")
}

// Latest returns the newest non-draft, non-prerelease release.
func (c *ReleasesClient) Latest(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.url()+"/repos/"+c.Owner+"/"+c.Repo+"/releases/latest", nil)
	if err != nil {
		return nil, upErr(KindNetwork, "building release request", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return nil, upErr(KindRateLimited, "GitHub API rate limited", nil)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, upErr(KindAPI, "GitHub API returned "+resp.Status, nil)
	}
	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rel); err != nil {
		return nil, upErr(KindAPI, "decoding release", err)
	}
	return &rel, nil
}

func (c *ReleasesClient) do(req *http.Request) (*http.Response, error) {
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, upErr(KindNetwork, "GitHub API request failed: "+err.Error(), err)
	}
	return resp, nil
}
