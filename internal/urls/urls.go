// Package urls mines historical/known URLs for a domain from public archives.
package urls

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// Fetch gathers URLs from the Wayback Machine CDX API and AlienVault OTX.
func Fetch(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	set := map[string]bool{}
	var firstErr error

	if u, err := wayback(ctx, client, domain); err == nil {
		for _, x := range u {
			set[x] = true
		}
	} else {
		firstErr = err
	}
	if u, err := otxURLs(ctx, client, domain); err == nil {
		for _, x := range u {
			set[x] = true
		}
	} else if firstErr == nil {
		firstErr = err
	}

	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, firstErr
	}
	return out, nil
}

func body(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "specter-recon")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func wayback(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	url := "https://web.archive.org/cdx/search/cdx?url=*." + domain +
		"/*&output=text&fl=original&collapse=urlkey&limit=50000"
	data, err := body(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func otxURLs(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	url := "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/url_list?limit=500&page=1"
	data, err := body(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	var out []string
	for _, u := range parsed.URLList {
		if u.URL != "" {
			out = append(out, u.URL)
		}
	}
	return out, nil
}

// Interesting flags URLs whose extension or path commonly leads to findings.
func Interesting(urls []string) []string {
	markers := []string{
		".json", ".xml", ".sql", ".bak", ".old", ".zip", ".tar", ".gz", ".env",
		".config", ".yml", ".yaml", ".log", ".txt", ".git", "/api/", "/admin",
		"/internal", "/debug", "/graphql", "/swagger", "token=", "key=", "apikey=",
		"password", "secret", "redirect=", "url=", "callback=", "file=", "path=",
	}
	var out []string
	seen := map[string]bool{}
	for _, u := range urls {
		low := strings.ToLower(u)
		for _, m := range markers {
			if strings.Contains(low, m) && !seen[u] {
				seen[u] = true
				out = append(out, u)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
