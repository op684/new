// Package jsrecon performs deep JavaScript reconnaissance: it discovers JS
// files referenced by live pages, fetches them, and mines endpoints, paths,
// API routes, subdomains and hardcoded secrets/keys.
package jsrecon

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"specter/internal/core"
)

// Scanner drives JS discovery and analysis.
type Scanner struct {
	client    *http.Client
	userAgent string
	domain    string
	maxFiles  int
}

// Report is the aggregated output of a JS recon pass.
type Report struct {
	JSFiles    []string
	Endpoints  []string
	Secrets    []core.Secret
	Subdomains []string
}

var scriptSrcRX = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
var inlineScriptRX = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)

// New builds a Scanner. maxFiles caps how many JS files are fetched per run.
func New(client *http.Client, userAgent, domain string, maxFiles int) *Scanner {
	if maxFiles <= 0 {
		maxFiles = 250
	}
	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
	}
	return &Scanner{client: client, userAgent: userAgent, domain: domain, maxFiles: maxFiles}
}

// DiscoverFromPage fetches an HTML page and returns referenced JS file URLs
// (absolute) plus the bodies of any inline <script> blocks.
func (s *Scanner) DiscoverFromPage(ctx context.Context, pageURL string) (jsURLs, inline []string) {
	body, _, ok := s.fetch(ctx, pageURL)
	if !ok {
		return nil, nil
	}
	base, _ := url.Parse(pageURL)
	for _, m := range scriptSrcRX.FindAllStringSubmatch(body, -1) {
		if abs := absolute(base, m[1]); abs != "" {
			jsURLs = append(jsURLs, abs)
		}
	}
	for _, m := range inlineScriptRX.FindAllStringSubmatch(body, -1) {
		if code := strings.TrimSpace(m[1]); len(code) > 24 {
			inline = append(inline, code)
		}
	}
	return jsURLs, inline
}

// Run fetches every JS URL concurrently, analyzes each plus any inline blobs,
// and returns the merged report. onSecret/onFile fire live for UX.
func (s *Scanner) Run(ctx context.Context, jsURLs, inlineBlobs []string, workers int,
	onSecret func(core.Secret), onFile func(url string, endpoints, secrets int)) Report {

	jsURLs = dedupe(jsURLs)
	if len(jsURLs) > s.maxFiles {
		jsURLs = jsURLs[:s.maxFiles]
	}

	var mu sync.Mutex
	agg := Report{}
	endpointSet := map[string]bool{}
	subSet := map[string]bool{}
	secretSet := map[string]bool{}

	merge := func(r Report) {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range r.Endpoints {
			if !endpointSet[e] {
				endpointSet[e] = true
				agg.Endpoints = append(agg.Endpoints, e)
			}
		}
		for _, sub := range r.Subdomains {
			if !subSet[sub] {
				subSet[sub] = true
				agg.Subdomains = append(agg.Subdomains, sub)
			}
		}
		for _, sec := range r.Secrets {
			key := sec.Type + "|" + sec.Match
			if !secretSet[key] {
				secretSet[key] = true
				agg.Secrets = append(agg.Secrets, sec)
				if onSecret != nil {
					onSecret(sec)
				}
			}
		}
	}

	// Inline scripts first — synchronous, cheap.
	for i, blob := range inlineBlobs {
		src := "inline-script#" + itoa(i+1)
		merge(Extract(src, blob, s.domain))
	}

	var fetched int64
	jobs := make(chan string, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ju := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				body, _, ok := s.fetch(ctx, ju)
				if !ok {
					continue
				}
				atomic.AddInt64(&fetched, 1)
				r := Extract(ju, body, s.domain)
				merge(r)
				mu.Lock()
				agg.JSFiles = append(agg.JSFiles, ju)
				mu.Unlock()
				if onFile != nil {
					onFile(ju, len(r.Endpoints), len(r.Secrets))
				}
			}
		}()
	}
	for _, ju := range jsURLs {
		jobs <- ju
	}
	close(jobs)
	wg.Wait()

	sort.Strings(agg.Endpoints)
	sort.Strings(agg.Subdomains)
	sort.Strings(agg.JSFiles)
	return agg
}

// Extract runs all endpoint/secret/subdomain patterns over a body.
func Extract(source, body, domain string) Report {
	r := Report{}
	seen := map[string]bool{}
	addEndpoint := func(e string) {
		e = strings.TrimSpace(e)
		if e == "" || len(e) > 400 || seen[e] {
			return
		}
		seen[e] = true
		r.Endpoints = append(r.Endpoints, e)
	}

	for _, m := range urlRX.FindAllString(body, -1) {
		addEndpoint(m)
	}
	for _, m := range pathRX.FindAllStringSubmatch(body, -1) {
		addEndpoint(m[1])
	}
	for _, m := range fileRX.FindAllString(body, -1) {
		addEndpoint(m)
	}

	if domain != "" {
		subRX := regexp.MustCompile(`(?i)[a-z0-9][a-z0-9._\-]*\.` + regexp.QuoteMeta(domain))
		subSeen := map[string]bool{}
		for _, m := range subRX.FindAllString(body, -1) {
			m = strings.ToLower(strings.Trim(m, ".-"))
			if !subSeen[m] {
				subSeen[m] = true
				r.Subdomains = append(r.Subdomains, m)
			}
		}
	}

	for _, sig := range secretSigs {
		for _, m := range sig.rx.FindAllString(body, -1) {
			r.Secrets = append(r.Secrets, core.Secret{
				Type:   sig.name,
				Match:  redact(m),
				Source: source,
			})
		}
	}
	return r
}

func (s *Scanner) fetch(ctx context.Context, target string) (string, http.Header, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", nil, false
	}
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", nil, false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return "", nil, false
	}
	return string(data), resp.Header, true
}

func absolute(base *url.URL, ref string) string {
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

// redact trims very long secrets and masks the middle of medium ones so the
// output is useful without dumping full live credentials to logs.
func redact(s string) string {
	if len(s) <= 12 {
		return s
	}
	if len(s) > 80 {
		s = s[:80]
	}
	keep := 6
	return s[:keep] + "…" + s[len(s)-4:]
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
