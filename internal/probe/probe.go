// Package probe checks hosts for live HTTP/HTTPS services and extracts a
// rich fingerprint (status, title, server, tech, favicon hash).
package probe

import (
	"context"
	"crypto/tls"
	"hash/crc32"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"specter/internal/core"
	"specter/internal/tech"
)

// Prober performs HTTP probing with a configured client.
type Prober struct {
	client    *http.Client
	userAgent string
	headers   map[string]string
	detect    bool
	maxBody   int64
}

// Options configures a Prober.
type Options struct {
	Timeout        time.Duration
	UserAgent      string
	Headers        []string
	FollowRedirect bool
	DetectTech     bool
}

var titleRX = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// New creates a Prober.
func New(o Options) *Prober {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{
		Timeout:   o.Timeout,
		Transport: tr,
	}
	if !o.FollowRedirect {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	hdr := map[string]string{}
	for _, h := range o.Headers {
		if i := strings.IndexByte(h, ':'); i > 0 {
			hdr[strings.TrimSpace(h[:i])] = strings.TrimSpace(h[i+1:])
		}
	}
	return &Prober{client: client, userAgent: o.UserAgent, headers: hdr, detect: o.DetectTech, maxBody: 2 << 20}
}

// corsProbeOrigin is a sentinel Origin we send to detect reflective CORS.
const corsProbeOrigin = "https://specter-evil.example"

// Probe tries HTTPS then HTTP for a host. It returns the first live result and
// a capped body snippet (used for takeover fingerprinting); both are nil/"" if
// the host is unreachable.
func (p *Prober) Probe(ctx context.Context, host string) (*core.HTTPResult, string) {
	for _, scheme := range []string{"https", "http"} {
		if r, snippet := p.do(ctx, scheme+"://"+host); r != nil {
			return r, snippet
		}
	}
	return nil, ""
}

func (p *Prober) do(ctx context.Context, url string) (*core.HTTPResult, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", corsProbeOrigin)
	for k, v := range p.headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, p.maxBody))
	latency := time.Since(start)
	body := string(bodyBytes)

	res := &core.HTTPResult{
		URL:           url,
		Scheme:        strings.SplitN(url, ":", 2)[0],
		StatusCode:    resp.StatusCode,
		Server:        resp.Header.Get("Server"),
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: int64(len(bodyBytes)),
		Location:      resp.Header.Get("Location"),
		Latency:       latency / time.Millisecond,
		Words:         len(strings.Fields(body)),
		Lines:         strings.Count(body, "\n") + 1,
		Headers:       flatten(resp.Header),
	}
	if m := titleRX.FindStringSubmatch(body); len(m) > 1 {
		res.Title = sanitize(m[1])
	}
	if p.detect {
		res.Technology = tech.Detect(resp.Header, body)
	}
	res.SecurityIssues = securityIssues(resp.Header, res.Scheme)
	res.CORS = corsIssue(resp.Header)
	res.Favicon = p.favicon(ctx, res.Scheme+"://"+host(url))

	snippet := body
	if len(snippet) > 8192 {
		snippet = snippet[:8192]
	}
	return res, snippet
}

// securityIssues reports missing/weak response security headers.
func securityIssues(h http.Header, scheme string) []string {
	var issues []string
	if scheme == "https" && h.Get("Strict-Transport-Security") == "" {
		issues = append(issues, "missing HSTS")
	}
	if h.Get("Content-Security-Policy") == "" {
		issues = append(issues, "missing CSP")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		issues = append(issues, "clickjacking (no X-Frame-Options)")
	}
	if h.Get("X-Content-Type-Options") == "" {
		issues = append(issues, "no X-Content-Type-Options")
	}
	return issues
}

// corsIssue detects reflective / wildcard CORS misconfigurations.
func corsIssue(h http.Header) string {
	acao := h.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true")
	switch {
	case acao == corsProbeOrigin && acac:
		return "CRITICAL: reflects arbitrary Origin with credentials"
	case acao == corsProbeOrigin:
		return "reflects arbitrary Origin"
	case acao == "*" && acac:
		return "wildcard ACAO with credentials"
	case acao == "*":
		return "wildcard Access-Control-Allow-Origin"
	}
	return ""
}

func (p *Prober) favicon(ctx context.Context, base string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/favicon.ico", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", p.userAgent)
	resp, err := p.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil || len(data) == 0 {
		return ""
	}
	return crc32hex(data)
}

func host(url string) string {
	u := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

func crc32hex(b []byte) string {
	h := crc32.ChecksumIEEE(b)
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[7-i] = hex[h&0xf]
		h >>= 4
	}
	return string(out)
}

func flatten(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}
