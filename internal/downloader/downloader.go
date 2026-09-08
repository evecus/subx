package downloader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"substore/internal/model"
)

// FallbackUA mirrors Sub-Store's download.js default
// (ua || defaultUserAgent || 'clash.meta/v1.19.23'). Most airport
// subscription endpoints negotiate the payload by User-Agent: a clash UA
// gets a full YAML config, a browser UA often gets an HTML page or a
// different base64 list, so a clash-like default yields the richest result.
const FallbackUA = "clash.meta/v1.19.23"

// Client fetches subscription content, honoring per-sub settings.
type Client struct {
	HTTP *http.Client
	// DefaultUA is used when the subscription has no UA of its own. It is
	// wired to the `defaultUserAgent` setting by SettingsFetcher.
	DefaultUA string
}

// NewClient creates a downloader with sane timeouts.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
}

// SettingsFetcher builds a Fetch function whose default UA follows the
// `defaultUserAgent` setting at call time, mirroring Sub-Store's
// (ua || defaultUserAgent || 'clash.meta/v1.19.23') precedence.
func SettingsFetcher(getSettings func() (map[string]any, error)) func(ctx context.Context, sub model.Sub) (string, error) {
	return func(ctx context.Context, sub model.Sub) (string, error) {
		c := NewClient()
		if settings, err := getSettings(); err == nil && settings != nil {
			if d, ok := settings["defaultUserAgent"].(string); ok {
				c.DefaultUA = d
			}
		}
		return c.Fetch(ctx, sub)
	}
}

// Fetch downloads subscription content for a sub entry. Precedence: local
// user-authored Content, then the cached snapshot (CachedContent), then a
// live HTTP fetch of URL. The cache is only populated by explicit refreshes
// (save / manual update / cron), so downloads always serve the locally
// stored node list when one exists.
func (c *Client) Fetch(ctx context.Context, sub model.Sub) (string, error) {
	if sub.Content != "" {
		return sub.Content, nil
	}
	if sub.CachedContent != "" {
		return sub.CachedContent, nil
	}
	if sub.URL == "" {
		return "", fmt.Errorf("sub has no url")
	}
	return c.FetchURL(ctx, sub.URL, sub.UA)
}

// FetchURL performs a live HTTP GET, bypassing any cached content. UA
// precedence: explicit ua > c.DefaultUA > FallbackUA.
func (c *Client) FetchURL(ctx context.Context, url, ua string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if ua == "" {
		ua = c.DefaultUA
	}
	if ua == "" {
		ua = FallbackUA
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	// forward proxies are not supported yet (no CGO proxy stack)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// MaxDownloadSize bounds cached raw content.
const MaxDownloadSize = 16 << 20
