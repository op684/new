package harvest

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Fetcher performs HTTP fetching with cookie/header support and optional TLS
// verification bypass.
type Fetcher struct {
	client  *http.Client
	headers map[string]string
}

// FetcherOptions configures a Fetcher.
type FetcherOptions struct {
	Timeout  time.Duration
	Insecure bool
	Cookie   string
	Headers  []string
}

const defaultUA = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 PHANTOM/2.1"

var (
	scriptSrcRX = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	inlineRX    = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
	sourceMapRX = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=(\S+)`)
	jsRefRX     = regexp.MustCompile(`(?i)["'(]([^"'()\s]+?\.js(?:\?[^"'()\s]*)?)["')]`)
)

// NewFetcher builds a Fetcher.
func NewFetcher(o FetcherOptions) *Fetcher {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: o.Insecure},
		MaxIdleConnsPerHost: 32,
		ForceAttemptHTTP2:   true,
	}
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	hdr := map[string]string{"User-Agent": defaultUA}
	if o.Cookie != "" {
		hdr["Cookie"] = o.Cookie
	}
	for _, h := range o.Headers {
		if i := strings.IndexByte(h, ':'); i > 0 {
			hdr[strings.TrimSpace(h[:i])] = strings.TrimSpace(h[i+1:])
		}
	}
	return &Fetcher{client: &http.Client{Timeout: o.Timeout, Transport: tr}, headers: hdr}
}

// Get fetches a URL and returns body, content-type and ok.
func (f *Fetcher) Get(ctx context.Context, raw string) (string, string, bool) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", "", false
	}
	for k, v := range f.headers {
		req.Header.Set(k, v)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", "", false
	}
	return string(data), resp.Header.Get("Content-Type"), true
}

// DiscoverScripts returns external JS URLs (absolute) and inline script bodies
// found in an HTML page.
func (f *Fetcher) DiscoverScripts(pageURL, html string) (jsURLs, inline []string) {
	base, _ := url.Parse(pageURL)
	seen := map[string]bool{}
	add := func(ref string) {
		if abs := absURL(base, ref); abs != "" && !seen[abs] {
			seen[abs] = true
			jsURLs = append(jsURLs, abs)
		}
	}
	for _, m := range scriptSrcRX.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	// Catch lazily-referenced bundles (webpack chunk maps, etc.).
	for _, m := range jsRefRX.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range inlineRX.FindAllStringSubmatch(html, -1) {
		if code := strings.TrimSpace(m[1]); len(code) > 20 {
			inline = append(inline, code)
		}
	}
	return jsURLs, inline
}

// SourceMapContent fetches a JS file's source map (via //# sourceMappingURL or
// the conventional .map sibling) and returns the concatenated original sources
// — frequently a goldmine of secrets and internal hostnames.
func (f *Fetcher) SourceMapContent(ctx context.Context, jsURL, jsBody string) string {
	mapRef := ""
	if m := sourceMapRX.FindStringSubmatch(jsBody); len(m) > 1 {
		mapRef = strings.TrimSpace(m[1])
	} else {
		mapRef = jsURL + ".map"
	}
	if strings.HasPrefix(mapRef, "data:") {
		return ""
	}
	base, _ := url.Parse(jsURL)
	abs := absURL(base, mapRef)
	if abs == "" {
		return ""
	}
	body, _, ok := f.Get(ctx, abs)
	if !ok {
		return ""
	}
	var sm struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
	}
	if err := json.Unmarshal([]byte(body), &sm); err != nil {
		return ""
	}
	var sb strings.Builder
	for _, s := range sm.Sources {
		sb.WriteString(s)
		sb.WriteByte('\n')
	}
	for _, c := range sm.SourcesContent {
		sb.WriteString(c)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func absURL(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return u.String()
}
