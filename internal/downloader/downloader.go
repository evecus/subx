package downloader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"substore/internal/model"
)

// Client fetches subscription content, honoring per-sub settings.
type Client struct {
	HTTP *http.Client
}

// NewClient creates a downloader with sane timeouts.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
}

// Fetch downloads subscription content for a sub entry. Precedence: local
// user-authored Content, then a cron-refreshed cache (CachedContent), then a
// live HTTP fetch of URL.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return "", err
	}
	if sub.UA != "" {
		req.Header.Set("User-Agent", sub.UA)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0")
	}
	req.Header.Set("Accept", "*/*")

	// forward proxies are not supported yet (no CGO proxy stack)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, sub.URL)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// MaxDownloadSize bounds cached raw content.
const MaxDownloadSize = 16 << 20
