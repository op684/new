// Package core holds the shared data types that flow between SPECTER modules.
package core

import (
	"sort"
	"sync"
	"time"
)

// Asset is a single discovered subdomain/host and everything we learn about it.
type Asset struct {
	Host       string            `json:"host"`
	IPs        []string          `json:"ips,omitempty"`
	CNAME      string            `json:"cname,omitempty"`
	Source     string            `json:"source,omitempty"`
	Resolved   bool              `json:"resolved"`
	HTTP       *HTTPResult       `json:"http,omitempty"`
	OpenPorts  []int             `json:"open_ports,omitempty"`
	Technology []string          `json:"technology,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// HTTPResult captures the outcome of probing a host over HTTP/HTTPS.
type HTTPResult struct {
	URL           string            `json:"url"`
	Scheme        string            `json:"scheme"`
	StatusCode    int               `json:"status_code"`
	Title         string            `json:"title,omitempty"`
	Server        string            `json:"server,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int64             `json:"content_length"`
	Words         int               `json:"words"`
	Lines         int               `json:"lines"`
	Location      string            `json:"location,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Technology    []string          `json:"technology,omitempty"`
	Latency       time.Duration     `json:"latency_ms"`
	Favicon       string            `json:"favicon_hash,omitempty"`
}

// Finding is an endpoint discovered during content discovery.
type Finding struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	Words         int    `json:"words"`
	Redirect      string `json:"redirect,omitempty"`
}

// Result is the top-level aggregate produced by a full run against one target.
type Result struct {
	Target    string    `json:"target"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`
	Assets    []*Asset  `json:"assets"`
	URLs      []string  `json:"urls,omitempty"`
	Findings  []Finding `json:"findings,omitempty"`

	mu    sync.Mutex
	index map[string]*Asset
}

// NewResult builds an empty result for a target.
func NewResult(target string) *Result {
	return &Result{
		Target:    target,
		StartedAt: time.Now(),
		index:     make(map[string]*Asset),
	}
}

// Upsert merges a freshly discovered asset into the result, deduplicating by host.
func (r *Result) Upsert(host, source string) *Asset {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.index[host]; ok {
		return a
	}
	a := &Asset{Host: host, Source: source, Tags: map[string]string{}}
	r.index[host] = a
	r.Assets = append(r.Assets, a)
	return a
}

// Get returns an existing asset by host, or nil.
func (r *Result) Get(host string) *Asset {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.index[host]
}

// Hosts returns the sorted list of every known host.
func (r *Result) Hosts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.index))
	for h := range r.index {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Lock/Unlock expose the internal mutex for callers that mutate assets in place.
func (r *Result) Lock()   { r.mu.Lock() }
func (r *Result) Unlock() { r.mu.Unlock() }

// Sort orders assets alphabetically for stable output.
func (r *Result) Sort() {
	r.mu.Lock()
	defer r.mu.Unlock()
	sort.Slice(r.Assets, func(i, j int) bool { return r.Assets[i].Host < r.Assets[j].Host })
}
