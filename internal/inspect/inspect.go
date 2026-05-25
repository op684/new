// Package inspect deeply interrogates a single URL to extract the maximum
// amount of intelligence: redirect chain, headers, security-header and cookie
// gaps, CORS, allowed methods, TLS certificate, technology fingerprint, body
// intelligence (secrets, endpoints, emails, stack traces, directory listings,
// WAF), reflected parameters, GraphQL introspection and backup/source variants.
// It powers the `specter inspect` subcommand, which feeds on VECTOR's
// high-risk.txt.
package inspect

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"specter/internal/core"
	"specter/internal/harvest"
	"specter/internal/jsrecon"
	"specter/internal/tech"
)

// Finding is a single piece of intelligence or weakness on a target.
type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`

	rank int
}

// TLSInfo summarizes a server certificate.
type TLSInfo struct {
	Subject  string   `json:"subject,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	NotAfter string   `json:"not_after,omitempty"`
	DNSNames []string `json:"dns_names,omitempty"`
	Expired  bool     `json:"expired,omitempty"`
	SelfSign bool     `json:"self_signed,omitempty"`
	DaysLeft int      `json:"days_left"`
	TLSVer   string   `json:"tls_version,omitempty"`
}

// Target is everything we learn about one inspected URL.
type Target struct {
	URL           string            `json:"url"`
	Severity      string            `json:"severity,omitempty"`
	Risk          int               `json:"risk,omitempty"`
	Reachable     bool              `json:"reachable"`
	Status        int               `json:"status"`
	FinalURL      string            `json:"final_url,omitempty"`
	RedirectChain []string          `json:"redirect_chain,omitempty"`
	Title         string            `json:"title,omitempty"`
	Server        string            `json:"server,omitempty"`
	PoweredBy     string            `json:"powered_by,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	Length        int64             `json:"length"`
	Words         int               `json:"words"`
	LatencyMS     int64             `json:"latency_ms"`
	Tech          []string          `json:"tech,omitempty"`
	AllowMethods  string            `json:"allow_methods,omitempty"`
	CORS          string            `json:"cors,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Cookies       []string          `json:"cookies,omitempty"`
	TLS           *TLSInfo          `json:"tls,omitempty"`
	Favicon       string            `json:"favicon_hash,omitempty"`
	WAF           string            `json:"waf,omitempty"`
	Reflected     []string          `json:"reflected_params,omitempty"`
	Secrets       []core.Secret     `json:"secrets,omitempty"`
	Endpoints     []string          `json:"endpoints,omitempty"`
	Emails        []string          `json:"emails,omitempty"`
	InternalIPs   []string          `json:"internal_ips,omitempty"`
	Backups       []string          `json:"exposed_variants,omitempty"`
	GraphQL       bool              `json:"graphql_introspection,omitempty"`
	Findings      []Finding         `json:"findings,omitempty"`
}

func (t *Target) add(rank int, sev, title, detail string) {
	t.Findings = append(t.Findings, Finding{Severity: sev, Title: title, Detail: detail, rank: rank})
}

// severities by rank
const (
	rCrit = 4
	rHigh = 3
	rMed  = 2
	rLow  = 1
	rInfo = 0
)

func sevName(r int) string {
	switch r {
	case rCrit:
		return "CRITICAL"
	case rHigh:
		return "HIGH"
	case rMed:
		return "MEDIUM"
	case rLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// Options configures an Inspector.
type Options struct {
	Timeout   time.Duration
	UserAgent string
	Cookie    string
	Headers   []string
	Insecure  bool
	Backups   bool
	Reflect   bool
	TLS       bool
}

// Inspector performs deep inspection with shared state (soft-404 calibration).
type Inspector struct {
	client  *http.Client
	ua      string
	headers map[string]string
	opt     Options

	mu      sync.Mutex
	soft404 map[string]soft404
	canary  string
}

type soft404 struct {
	status int
	size   int
}

const corsOrigin = "https://specter-inspect.evil"

// New builds an Inspector.
func New(o Options) *Inspector {
	if o.Timeout == 0 {
		o.Timeout = 12 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = "Mozilla/5.0 (Linux; Android 11; SPECTER-inspect)"
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 16,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{
		Timeout:   o.Timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // we follow manually to record the chain
		},
	}
	hdr := map[string]string{}
	if o.Cookie != "" {
		hdr["Cookie"] = o.Cookie
	}
	for _, h := range o.Headers {
		if i := strings.IndexByte(h, ':'); i > 0 {
			hdr[strings.TrimSpace(h[:i])] = strings.TrimSpace(h[i+1:])
		}
	}
	return &Inspector{
		client:  client,
		ua:      o.UserAgent,
		headers: hdr,
		opt:     o,
		soft404: map[string]soft404{},
		canary:  fmt.Sprintf("spci%06x", rand.Intn(0xffffff)),
	}
}

// Inspect runs the full battery of checks against t.URL, filling t in place.
func (ins *Inspector) Inspect(ctx context.Context, t *Target) {
	u, err := url.Parse(t.URL)
	if err != nil || u.Host == "" {
		t.add(rInfo, "INFO", "unparseable URL", err.Error())
		return
	}
	regdom := harvest.RegisteredDomain(u.Hostname())

	start := time.Now()
	chain, status, hdr, body := ins.fetchChain(ctx, t.URL)
	t.LatencyMS = time.Since(start).Milliseconds()
	if status == 0 {
		t.add(rInfo, "INFO", "unreachable", "no HTTP response")
		return
	}
	t.Reachable = true
	t.Status = status
	t.RedirectChain = chain
	if len(chain) > 0 {
		t.FinalURL = chain[len(chain)-1]
	}
	t.Headers = flatten(hdr)
	t.Server = hdr.Get("Server")
	t.PoweredBy = hdr.Get("X-Powered-By")
	t.ContentType = hdr.Get("Content-Type")
	t.Length = int64(len(body))
	t.Words = len(strings.Fields(body))
	if m := titleRX.FindStringSubmatch(body); len(m) > 1 {
		t.Title = squish(m[1])
	}
	t.Tech = tech.Detect(hdr, body)

	ins.statusFindings(t)
	ins.headerFindings(t, hdr)
	ins.cookieFindings(t, hdr)
	ins.corsFindings(t, hdr)
	ins.bodyIntel(t, body, regdom)
	ins.methods(ctx, t)

	if ins.opt.TLS && u.Scheme == "https" {
		ins.tlsInfo(t, u.Hostname())
	}
	t.Favicon = ins.favicon(ctx, u.Scheme+"://"+u.Host)
	if ins.opt.Reflect && len(u.Query()) > 0 {
		ins.reflected(ctx, t, u)
	}
	if strings.Contains(strings.ToLower(u.Path), "graphql") {
		ins.graphql(ctx, t)
	}
	if ins.opt.Backups {
		ins.backups(ctx, t, u)
	}

	sort.SliceStable(t.Findings, func(i, j int) bool { return t.Findings[i].rank > t.Findings[j].rank })
}

// ---- HTTP helpers ----

func (ins *Inspector) do(ctx context.Context, method, target string, extra map[string]string) (*http.Response, string, bool) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, "", false
	}
	req.Header.Set("User-Agent", ins.ua)
	req.Header.Set("Accept", "*/*")
	for k, v := range ins.headers {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := ins.client.Do(req)
	if err != nil {
		return nil, "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	return resp, string(body), true
}

func (ins *Inspector) fetchChain(ctx context.Context, start string) ([]string, int, http.Header, string) {
	var chain []string
	cur := start
	var lastHdr http.Header
	var lastStatus int
	var lastBody string
	for i := 0; i < 8; i++ {
		resp, body, ok := ins.do(ctx, http.MethodGet, cur, map[string]string{"Origin": corsOrigin})
		if !ok {
			break
		}
		lastHdr, lastStatus, lastBody = resp.Header, resp.StatusCode, body
		loc := resp.Header.Get("Location")
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			next := resolve(cur, loc)
			if next == "" || next == cur {
				break
			}
			chain = append(chain, next)
			cur = next
			continue
		}
		break
	}
	return chain, lastStatus, lastHdr, lastBody
}

// ---- finding generators ----

func (ins *Inspector) statusFindings(t *Target) {
	switch {
	case t.Status == 401:
		t.add(rInfo, "INFO", "authentication required", "401 — protected endpoint")
	case t.Status == 403:
		t.add(rLow, "LOW", "forbidden", "403 — try auth bypass / path tricks")
	case t.Status == 200:
		t.add(rInfo, "INFO", "accessible", "200 OK")
	case t.Status >= 500:
		t.add(rMed, "MEDIUM", "server error", fmt.Sprintf("%d — may leak stack traces", t.Status))
	}
}

var secHeaders = []struct {
	name string
	rank int
	miss string
}{
	{"Strict-Transport-Security", rLow, "missing HSTS (downgrade/MITM)"},
	{"Content-Security-Policy", rLow, "missing CSP (XSS mitigation absent)"},
	{"X-Frame-Options", rLow, "missing X-Frame-Options (clickjacking)"},
	{"X-Content-Type-Options", rInfo, "missing X-Content-Type-Options (MIME sniffing)"},
}

func (ins *Inspector) headerFindings(t *Target, h http.Header) {
	for _, sh := range secHeaders {
		if h.Get(sh.name) == "" {
			if sh.name == "X-Frame-Options" && strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
				continue
			}
			t.add(sh.rank, sevName(sh.rank), "header gap", sh.miss)
		}
	}
	if t.Server != "" && versionRX.MatchString(t.Server) {
		t.add(rLow, "LOW", "version disclosure", "Server: "+t.Server)
	}
	if t.PoweredBy != "" {
		t.add(rLow, "LOW", "tech disclosure", "X-Powered-By: "+t.PoweredBy)
	}
	for _, hh := range []string{"X-Backend-Server", "X-Served-By", "Via", "X-Cache", "X-Amz-Cf-Id", "X-Aspnet-Version", "X-Debug-Token"} {
		if v := h.Get(hh); v != "" {
			t.add(rInfo, "INFO", "infra header", hh+": "+v)
		}
	}
}

func (ins *Inspector) cookieFindings(t *Target, h http.Header) {
	for _, c := range h.Values("Set-Cookie") {
		t.Cookies = append(t.Cookies, c)
		low := strings.ToLower(c)
		name := strings.SplitN(c, "=", 2)[0]
		var gaps []string
		if !strings.Contains(low, "httponly") {
			gaps = append(gaps, "no HttpOnly")
		}
		if !strings.Contains(low, "secure") {
			gaps = append(gaps, "no Secure")
		}
		if !strings.Contains(low, "samesite") {
			gaps = append(gaps, "no SameSite")
		}
		if len(gaps) > 0 {
			t.add(rLow, "LOW", "weak cookie "+strings.TrimSpace(name), strings.Join(gaps, ", "))
		}
	}
}

func (ins *Inspector) corsFindings(t *Target, h http.Header) {
	acao := h.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true")
	switch {
	case acao == corsOrigin && acac:
		t.CORS = "reflects arbitrary Origin + credentials"
		t.add(rCrit, "CRITICAL", "CORS misconfiguration", t.CORS)
	case acao == corsOrigin:
		t.CORS = "reflects arbitrary Origin"
		t.add(rHigh, "HIGH", "CORS misconfiguration", t.CORS)
	case acao == "*" && acac:
		t.CORS = "wildcard + credentials"
		t.add(rHigh, "HIGH", "CORS misconfiguration", t.CORS)
	case acao == "*":
		t.CORS = "wildcard ACAO"
		t.add(rInfo, "INFO", "permissive CORS", t.CORS)
	}
}

func (ins *Inspector) bodyIntel(t *Target, body, regdom string) {
	if body == "" {
		return
	}
	// Secrets + endpoints via the shared JS-recon extractor.
	r := jsrecon.Extract(t.URL, body, regdom)
	t.Secrets = r.Secrets
	for _, s := range r.Secrets {
		t.add(rHigh, "HIGH", "secret in response", s.Type+": "+s.Match)
	}
	t.Endpoints = capList(r.Endpoints, 50)

	if m := emailRX.FindAllString(body, -1); len(m) > 0 {
		t.Emails = uniqCap(m, 30)
		t.add(rInfo, "INFO", "email addresses", fmt.Sprintf("%d found", len(t.Emails)))
	}
	if m := privIPRX.FindAllString(body, -1); len(m) > 0 {
		t.InternalIPs = uniqCap(m, 30)
		t.add(rMed, "MEDIUM", "internal IPs disclosed", strings.Join(t.InternalIPs, ", "))
	}
	if dirListRX.MatchString(body) {
		t.add(rMed, "MEDIUM", "directory listing", "auto-index enabled — browseable files")
	}
	for _, sig := range errorSigs {
		if sig.rx.MatchString(body) {
			t.add(rMed, "MEDIUM", "verbose error / stack trace", sig.name)
			break
		}
	}
	if waf := detectWAF(t.Headers, t.Cookies, body); waf != "" {
		t.WAF = waf
		t.add(rInfo, "INFO", "WAF/CDN detected", waf)
	}
	if low := strings.ToLower(t.URL); isSensitivePath(low) && t.Status == 200 && t.Length > 0 {
		t.add(rCrit, "CRITICAL", "sensitive file exposed", "leaked: "+snippet(body, 0, 160))
	}
}

func (ins *Inspector) methods(ctx context.Context, t *Target) {
	resp, _, ok := ins.do(ctx, http.MethodOptions, t.URL, nil)
	if !ok {
		return
	}
	allow := resp.Header.Get("Allow")
	if allow == "" {
		allow = resp.Header.Get("Access-Control-Allow-Methods")
	}
	if allow == "" {
		return
	}
	t.AllowMethods = allow
	up := strings.ToUpper(allow)
	for _, m := range []string{"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"} {
		if strings.Contains(up, m) {
			t.add(rMed, "MEDIUM", "risky HTTP method", m+" allowed ("+allow+")")
		}
	}
}

func (ins *Inspector) tlsInfo(t *Target, host string) {
	d := net.Dialer{Timeout: ins.opt.Timeout}
	conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, "443"),
		&tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		return
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return
	}
	c := cs.PeerCertificates[0]
	info := &TLSInfo{
		Subject:  c.Subject.CommonName,
		Issuer:   c.Issuer.CommonName,
		NotAfter: c.NotAfter.Format("2006-01-02"),
		DNSNames: c.DNSNames,
		DaysLeft: int(time.Until(c.NotAfter).Hours() / 24),
		TLSVer:   tlsVersion(cs.Version),
	}
	info.Expired = time.Now().After(c.NotAfter)
	info.SelfSign = c.Issuer.CommonName == c.Subject.CommonName && c.Issuer.CommonName != ""
	t.TLS = info
	if info.Expired {
		t.add(rMed, "MEDIUM", "expired TLS certificate", "expired "+info.NotAfter)
	} else if info.DaysLeft < 14 {
		t.add(rLow, "LOW", "TLS cert expiring soon", fmt.Sprintf("%d days left", info.DaysLeft))
	}
	if info.SelfSign {
		t.add(rLow, "LOW", "self-signed certificate", info.Subject)
	}
	if cs.Version < tls.VersionTLS12 {
		t.add(rMed, "MEDIUM", "weak TLS version", info.TLSVer)
	}
}

func (ins *Inspector) favicon(ctx context.Context, base string) string {
	resp, body, ok := ins.do(ctx, http.MethodGet, base+"/favicon.ico", nil)
	if !ok || resp.StatusCode != 200 || len(body) == 0 {
		return ""
	}
	return crc32hex([]byte(body))
}

func (ins *Inspector) reflected(ctx context.Context, t *Target, u *url.URL) {
	q := u.Query()
	count := 0
	for name := range q {
		if count >= 10 {
			break
		}
		count++
		cp := cloneValues(q)
		cp.Set(name, ins.canary)
		test := *u
		test.RawQuery = cp.Encode()
		_, body, ok := ins.do(ctx, http.MethodGet, test.String(), nil)
		if ok && strings.Contains(body, ins.canary) {
			t.Reflected = append(t.Reflected, name)
		}
	}
	if len(t.Reflected) > 0 {
		t.add(rMed, "MEDIUM", "reflected parameter(s)", "XSS surface: "+strings.Join(t.Reflected, ", "))
	}
}

func (ins *Inspector) graphql(ctx context.Context, t *Target) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL,
		strings.NewReader(`{"query":"{__schema{queryType{name}}}"}`))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ins.ua)
	resp, err := ins.client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	resp.Body.Close()
	if resp.StatusCode == 200 && strings.Contains(string(body), "__schema") || strings.Contains(string(body), "queryType") {
		t.GraphQL = true
		t.add(rHigh, "HIGH", "GraphQL introspection enabled", "full schema disclosed via __schema query")
	}
}

func (ins *Inspector) backups(ctx context.Context, t *Target, u *url.URL) {
	seg := u.Path
	if i := strings.LastIndexByte(seg, '/'); i >= 0 {
		seg = seg[i+1:]
	}
	if seg == "" {
		return
	}
	base := u.Scheme + "://" + u.Host + u.Path
	soft := ins.calibrate(ctx, u)
	variants := []string{base + ".bak", base + ".old", base + ".save", base + ".orig",
		base + "~", base + ".swp", base + ".1", base + ".copy", base + ".txt", base + ".zip"}
	for _, v := range variants {
		select {
		case <-ctx.Done():
			return
		default:
		}
		resp, body, ok := ins.do(ctx, http.MethodGet, v, nil)
		if !ok || resp.StatusCode != 200 || len(body) == 0 {
			continue
		}
		if resp.StatusCode == soft.status && approxEqual(len(body), soft.size) {
			continue // soft-404
		}
		t.Backups = append(t.Backups, v)
		t.add(rHigh, "HIGH", "exposed backup/variant", v+fmt.Sprintf(" (%d bytes)", len(body)))
	}
}

// calibrate fetches a guaranteed-missing path to fingerprint soft 404s.
func (ins *Inspector) calibrate(ctx context.Context, u *url.URL) soft404 {
	host := u.Scheme + "://" + u.Host
	ins.mu.Lock()
	if s, ok := ins.soft404[host]; ok {
		ins.mu.Unlock()
		return s
	}
	ins.mu.Unlock()
	resp, body, ok := ins.do(ctx, http.MethodGet, host+"/specter_404_"+ins.canary+".bak", nil)
	s := soft404{status: 404, size: 0}
	if ok {
		s = soft404{status: resp.StatusCode, size: len(body)}
	}
	ins.mu.Lock()
	ins.soft404[host] = s
	ins.mu.Unlock()
	return s
}

// MaxRank returns the highest finding severity rank (for sorting targets).
func (t *Target) MaxRank() int {
	max := rInfo
	for _, f := range t.Findings {
		if f.rank > max {
			max = f.rank
		}
	}
	if r := sevRank(t.Severity); r > max {
		max = r
	}
	return max
}

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return rCrit
	case "HIGH":
		return rHigh
	case "MEDIUM":
		return rMed
	case "LOW":
		return rLow
	default:
		return rInfo
	}
}
