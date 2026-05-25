package harvest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// GitHubClient queries the GitHub code-search API for a domain and fetches the
// matching file contents (decoded) so they can be scanned for leaks.
type GitHubClient struct {
	token  string
	client *http.Client
}

// NewGitHubClient builds a client bound to a personal access token.
func NewGitHubClient(token string, timeout time.Duration) *GitHubClient {
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	return &GitHubClient{token: token, client: &http.Client{Timeout: timeout}}
}

// SearchContentURLs returns contents-API URLs of code matching the domain.
func (g *GitHubClient) SearchContentURLs(ctx context.Context, domain string) ([]string, error) {
	queries := []string{
		`https://api.github.com/search/code?q="` + domain + `"&per_page=100&sort=indexed`,
		`https://api.github.com/search/code?q="` + domain + `"&per_page=100`,
	}
	seen := map[string]bool{}
	var out []string
	var firstErr error
	for _, q := range queries {
		body, err := g.get(ctx, q)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		var parsed struct {
			Items []struct {
				URL string `json:"url"`
			} `json:"items"`
		}
		if json.Unmarshal(body, &parsed) != nil {
			continue
		}
		for _, it := range parsed.Items {
			if it.URL != "" && !seen[it.URL] {
				seen[it.URL] = true
				out = append(out, it.URL)
			}
		}
	}
	if len(out) == 0 {
		return nil, firstErr
	}
	return out, nil
}

// FetchContent fetches a contents-API URL and returns (decodedBody, htmlURL).
func (g *GitHubClient) FetchContent(ctx context.Context, apiURL string) (string, string, bool) {
	body, err := g.get(ctx, apiURL)
	if err != nil {
		return "", "", false
	}
	var meta struct {
		Content string `json:"content"`
		HTMLURL string `json:"html_url"`
	}
	if json.Unmarshal(body, &meta) != nil || meta.Content == "" {
		return "", "", false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(meta.Content, "\n", ""))
	if err != nil {
		return "", "", false
	}
	htmlURL := meta.HTMLURL
	if i := strings.Index(htmlURL, "?ref="); i >= 0 {
		htmlURL = htmlURL[:i]
	}
	return string(dec), htmlURL, true
}

func (g *GitHubClient) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "PHANTOM-recon")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}
