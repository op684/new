// Package harvest is PHANTOM's extraction engine — the Go reimplementation and
// upgrade of SubDomainizer. Given arbitrary text (HTML, JavaScript, source maps,
// local files, GitHub blobs) it mines subdomains, secrets/credentials, cloud
// storage URLs and IPv4 addresses.
package harvest

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Secret is a discovered credential / high-entropy value.
type Secret struct {
	Type    string  `json:"type"`
	Match   string  `json:"match"`
	Source  string  `json:"source"`
	Entropy float64 `json:"entropy,omitempty"`
}

// Result is the thread-safe aggregate of everything harvested.
type Result struct {
	mu         sync.Mutex
	subdomains map[string]bool
	cloud      map[string]bool
	ips        map[string]bool
	secrets    []Secret
	secretSeen map[string]bool
}

// NewResult builds an empty Result.
func NewResult() *Result {
	return &Result{
		subdomains: map[string]bool{},
		cloud:      map[string]bool{},
		ips:        map[string]bool{},
		secretSeen: map[string]bool{},
	}
}

func (r *Result) addSub(s string) {
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), ".-"))
	if s == "" {
		return
	}
	r.mu.Lock()
	r.subdomains[s] = true
	r.mu.Unlock()
}

func (r *Result) addCloud(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	r.mu.Lock()
	r.cloud[s] = true
	r.mu.Unlock()
}

func (r *Result) addIP(s string) {
	r.mu.Lock()
	r.ips[s] = true
	r.mu.Unlock()
}

func (r *Result) addSecret(s Secret) {
	key := s.Type + "|" + s.Match
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.secretSeen[key] {
		return
	}
	r.secretSeen[key] = true
	r.secrets = append(r.secrets, s)
}

// Subdomains returns the sorted, de-duplicated subdomain list.
func (r *Result) Subdomains() []string { return sortedKeys(r.subdomains) }

// CloudURLs returns the sorted cloud-asset URLs.
func (r *Result) CloudURLs() []string { return sortedKeys(r.cloud) }

// IPs returns the sorted IPv4 addresses.
func (r *Result) IPs() []string { return sortedKeys(r.ips) }

// Secrets returns the discovered secrets.
func (r *Result) Secrets() []Secret {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Secret, len(r.secrets))
	copy(out, r.secrets)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Match < out[j].Match
	})
	return out
}

// Seed manually adds a known subdomain (e.g. the input host).
func (r *Result) Seed(host string) { r.addSub(host) }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Engine applies all extraction patterns to content.
type Engine struct {
	subdomainRX *regexp.Regexp
	entropyMin  float64
}

// NewEngine builds an extraction engine. domains are the registered domains
// (plus any custom -d domains) used to build the subdomain pattern.
func NewEngine(subdomainRX *regexp.Regexp, entropyMin float64) *Engine {
	if entropyMin <= 0 {
		entropyMin = 3.0
	}
	return &Engine{subdomainRX: subdomainRX, entropyMin: entropyMin}
}

// Scan runs every detector over content and records hits in res.
func (e *Engine) Scan(source, content string, res *Result) {
	flat := strings.ReplaceAll(content, "\n", " ")

	// Subdomains for the target scope.
	if e.subdomainRX != nil {
		for _, m := range e.subdomainRX.FindAllString(flat, -1) {
			res.addSub(m)
		}
	}
	// Cloud storage assets.
	for _, rx := range cloudRegexes {
		for _, m := range rx.FindAllString(flat, -1) {
			res.addCloud(m)
		}
	}
	// IPv4 addresses.
	for _, m := range ipv4RX.FindAllString(flat, -1) {
		res.addIP(m)
	}
	// High-confidence credential signatures.
	for _, sig := range highConfidenceSecrets {
		for _, m := range sig.rx.FindAllString(content, -1) {
			res.addSecret(Secret{Type: sig.name, Match: capStr(m, 200), Source: source})
		}
	}
	// Keyword + Shannon-entropy generic secrets (SubDomainizer-style, upgraded).
	for _, m := range keywordSecretRX.FindAllStringSubmatch(content, -1) {
		whole, value := m[0], m[1]
		if isBlacklisted(whole) || len(value) < 6 {
			continue
		}
		ent := Entropy(value)
		if ent <= e.entropyMin {
			continue
		}
		res.addSecret(Secret{
			Type:    "Generic Secret (entropy)",
			Match:   capStr(strings.TrimSpace(whole), 200),
			Source:  source,
			Entropy: round2(ent),
		})
	}
}

// Entropy returns the Shannon entropy (bits/char) of s.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func isBlacklisted(s string) bool {
	low := strings.ToLower(s)
	for _, b := range secretBlacklist {
		if strings.Contains(low, b) {
			return true
		}
	}
	return false
}

func capStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
