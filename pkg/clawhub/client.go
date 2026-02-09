package clawhub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/safedep/vet/pkg/common/logger"
)

const defaultBaseURL = "https://clawhub.ai"

const maxDownloadSize = 50 * 1024 * 1024 // 50MB

// Client is an HTTP client for the ClawHub V1 API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithBaseURL sets the base URL for API requests.
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// NewClient creates a new ClawHub API client.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		baseURL: defaultBaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// normalizeSlug extracts the skill name from an "owner/skill" slug.
// The ClawHub API expects only the skill name, not the owner prefix.
func normalizeSlug(slug string) string {
	if parts := strings.SplitN(slug, "/", 2); len(parts) == 2 {
		return parts[1]
	}

	return slug
}

// GetSkill fetches metadata for a skill by its slug.
func (c *Client) GetSkill(ctx context.Context, slug string) (*SkillResponse, error) {
	slug = normalizeSlug(slug)
	reqURL := fmt.Sprintf("%s/api/v1/skills/%s", c.baseURL, url.PathEscape(slug))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch skill: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("failed to close response body for skill %q: %v", slug, err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d for skill %q", resp.StatusCode, slug)
	}

	var result SkillResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode skill response: %w", err)
	}

	return &result, nil
}

// GetVersion fetches metadata for a specific skill version.
func (c *Client) GetVersion(ctx context.Context, slug, version string) (*VersionResponse, error) {
	slug = normalizeSlug(slug)
	reqURL := fmt.Sprintf("%s/api/v1/skills/%s/versions/%s", c.baseURL, url.PathEscape(slug), url.PathEscape(version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch version: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("failed to close response body for version %s/%s: %v", slug, version, err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d for version %s/%s", resp.StatusCode, slug, version)
	}

	var result VersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode version response: %w", err)
	}

	return &result, nil
}

// DownloadSkillZip downloads the skill package as a zip archive.
func (c *Client) DownloadSkillZip(ctx context.Context, slug string) ([]byte, error) {
	slug = normalizeSlug(slug)
	reqURL := fmt.Sprintf("%s/api/v1/download?slug=%s", c.baseURL, url.QueryEscape(slug))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download skill: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("failed to close response body for skill download %q: %v", slug, err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d downloading skill %q", resp.StatusCode, slug)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read download response: %w", err)
	}

	if len(data) > maxDownloadSize {
		return nil, fmt.Errorf("skill zip too large (max %d bytes)", maxDownloadSize)
	}

	return data, nil
}
