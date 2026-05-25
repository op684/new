package epanalyze

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ProbeResult holds live verification data for an endpoint.
type ProbeResult struct {
	Status            int      `json:"status"`
	ContentType       string   `json:"content_type,omitempty"`
	Length            int64    `json:"length"`
	Title             string   `json:"title,omitempty"`
	Location          string   `json:"location,omitempty"`
	Reflected         []string `json:"reflected_params,omitempty"`
	OpenRedirect      bool     `json:"open_redirect,omitempty"`
	OpenRedirectParam string   `json:"open_redirect_param,omitempty"`
	Server            string   `json:"server,omitempty"`
}

// Prober performs live checks. In active mode it injects benign canaries to
// detect parameter reflection (XSS surface) and open redirects.
type Prober struct {
	client    *http.Client
	userAgent string
	active    bool
	canary    string
	redirHost string
}

var probeTitleRX = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// NewProber builds a Prober. active enables canary injection tests.
func NewProber(timeout time.Duration, userAgent string, active bool) *Prober {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 50,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	suffix := fmt.Sprintf("%06x", rand.Intn(0xffffff))
	return &Prober{
		client:    client,
		userAgent: userAgent,
		active:    active,
		canary:    "spcan" + suffix,
		redirHost: "canary" + suffix + ".specter.invalid",
	}
}

// Probeable reports whether an endpoint can be requested (has scheme+host).
func Probeable(e *Endpoint) bool {
	return (e.Scheme == "http" || e.Scheme == "https") && e.Host != ""
}

// Probe requests the endpoint and (when active) runs canary tests.
func (p *Prober) Probe(ctx context.Context, e *Endpoint) *ProbeResult {
	if !Probeable(e) {
		return nil
	}
	body, hdr, status, ok := p.get(ctx, e.URL)
	if !ok {
		return nil
	}
	res := &ProbeResult{
		Status:      status,
		ContentType: hdr.Get("Content-Type"),
		Length:      int64(len(body)),
		Location:    hdr.Get("Location"),
		Server:      hdr.Get("Server"),
	}
	if m := probeTitleRX.FindStringSubmatch(body); len(m) > 1 {
		res.Title = squish(m[1])
	}

	if p.active && len(e.Params) > 0 {
		p.activeTests(ctx, e, res)
	}
	return res
}

func (p *Prober) activeTests(ctx context.Context, e *Endpoint, res *ProbeResult) {
	candidates := interestingParams(e)
	reflectedSet := map[string]bool{}
	for i, param := range candidates {
		if i >= 12 { // cap requests per endpoint
			break
		}
		// Reflection (XSS surface): plant a benign alnum canary.
		if body, _, _, ok := p.get(ctx, withParam(e.URL, param, p.canary)); ok {
			if strings.Contains(body, p.canary) && !reflectedSet[param] {
				reflectedSet[param] = true
				res.Reflected = append(res.Reflected, param)
			}
		}
		// Open redirect: plant a canary host and inspect the redirect target.
		if isRedirectParam(param) && !res.OpenRedirect {
			_, hdr, status, ok := p.get(ctx, withParam(e.URL, param, "https://"+p.redirHost+"/"))
			if ok && status >= 300 && status < 400 {
				loc := hdr.Get("Location")
				if redirectsTo(loc, p.redirHost) {
					res.OpenRedirect = true
					res.OpenRedirectParam = param
				}
			}
		}
	}
}

func (p *Prober) get(ctx context.Context, target string) (string, http.Header, int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", nil, 0, false
	}
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", nil, 0, false
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(data), resp.Header, resp.StatusCode, true
}

func interestingParams(e *Endpoint) []string {
	want := map[string]bool{}
	for _, v := range e.Vulns {
		switch v.Category {
		case "XSS", "Open Redirect", "SSRF":
			for _, p := range v.Params {
				want[p] = true
			}
		}
	}
	var out []string
	for _, p := range e.Params {
		if want[p] {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = e.Params // fall back to all params
	}
	return out
}

func isRedirectParam(p string) bool {
	for _, sig := range paramSignatures {
		if sig.category == "Open Redirect" || sig.category == "SSRF" {
			for _, want := range sig.params {
				if want == p {
					return true
				}
			}
		}
	}
	return false
}

func redirectsTo(location, host string) bool {
	location = strings.TrimSpace(location)
	if location == "" {
		return false
	}
	if strings.HasPrefix(location, "//"+host) || strings.HasPrefix(location, "/\\"+host) {
		return true
	}
	if u, err := url.Parse(location); err == nil {
		return strings.EqualFold(u.Hostname(), host)
	}
	return false
}

func withParam(rawURL, param, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func squish(s string) string {
	s = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(strings.TrimSpace(s))
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > 100 {
		s = s[:100] + "…"
	}
	return s
}
