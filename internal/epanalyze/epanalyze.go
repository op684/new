// Package epanalyze is SPECTER's endpoint attack-surface analyzer. It ingests
// a list of endpoints (full URLs, protocol-relative URLs, or paths), classifies
// each one, and intelligently flags likely vulnerability classes based on
// parameter names, path tokens, file extensions and sensitive markers.
package epanalyze

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

// VulnHint is a single heuristic finding on an endpoint.
type VulnHint struct {
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Reason   string   `json:"reason"`
	Params   []string `json:"params,omitempty"`

	sev Severity
}

// Endpoint is a parsed, classified endpoint.
type Endpoint struct {
	Raw      string       `json:"raw"`
	URL      string       `json:"url"`
	Scheme   string       `json:"scheme,omitempty"`
	Host     string       `json:"host,omitempty"`
	Path     string       `json:"path"`
	Ext      string       `json:"ext,omitempty"`
	Params   []string     `json:"params,omitempty"`
	Category string       `json:"category"`
	Vulns    []VulnHint   `json:"vulns,omitempty"`
	Risk     int          `json:"risk"`
	MaxSev   string       `json:"max_severity"`
	Probe    *ProbeResult `json:"probe,omitempty"`
}

// Result is the aggregate analysis over a whole endpoint list.
type Result struct {
	Endpoints   []*Endpoint    `json:"endpoints"`
	Total       int            `json:"total"`
	Hosts       []string       `json:"hosts"`
	ParamFreq   map[string]int `json:"param_frequency"`
	ExtFreq     map[string]int `json:"extension_frequency"`
	CategoryCnt map[string]int `json:"category_counts"`
	VulnCounts  map[string]int `json:"vuln_counts"`
}

// Analyze parses, classifies and scores every line. base, if non-empty, is
// prefixed onto relative paths so they become absolute URLs.
func Analyze(lines []string, base string) *Result {
	r := &Result{
		ParamFreq:   map[string]int{},
		ExtFreq:     map[string]int{},
		CategoryCnt: map[string]int{},
		VulnCounts:  map[string]int{},
	}
	seen := map[string]bool{}
	hostSet := map[string]bool{}
	base = strings.TrimRight(base, "/")

	for _, line := range lines {
		ep := parseLine(line, base)
		if ep == nil {
			continue
		}
		if seen[ep.URL] {
			continue
		}
		seen[ep.URL] = true

		ep.classify()
		ep.score()

		r.Endpoints = append(r.Endpoints, ep)
		if ep.Host != "" {
			hostSet[ep.Host] = true
		}
		for _, p := range ep.Params {
			r.ParamFreq[p]++
		}
		if ep.Ext != "" {
			r.ExtFreq[ep.Ext]++
		}
		r.CategoryCnt[ep.Category]++
		for _, v := range ep.Vulns {
			r.VulnCounts[v.Category]++
		}
	}

	r.Total = len(r.Endpoints)
	for h := range hostSet {
		r.Hosts = append(r.Hosts, h)
	}
	sort.Strings(r.Hosts)

	// Triage order: highest max-severity first, then accumulated risk, then URL.
	sort.SliceStable(r.Endpoints, func(i, j int) bool {
		si, sj := sevRank(r.Endpoints[i].MaxSev), sevRank(r.Endpoints[j].MaxSev)
		if si != sj {
			return si > sj
		}
		if r.Endpoints[i].Risk != r.Endpoints[j].Risk {
			return r.Endpoints[i].Risk > r.Endpoints[j].Risk
		}
		return r.Endpoints[i].URL < r.Endpoints[j].URL
	})
	return r
}

func sevRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func parseLine(line, base string) *Endpoint {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	raw := line
	// Strip surrounding quotes that sometimes survive extraction.
	line = strings.Trim(line, `"'`+"`")

	switch {
	case strings.HasPrefix(line, "//"):
		line = "https:" + line
	case strings.HasPrefix(line, "http://"), strings.HasPrefix(line, "https://"):
		// absolute already
	default:
		// relative path
		if base != "" {
			if !strings.HasPrefix(line, "/") {
				line = "/" + line
			}
			line = base + line
		}
	}

	u, err := url.Parse(line)
	if err != nil {
		return nil
	}

	ep := &Endpoint{Raw: raw, URL: line, Scheme: u.Scheme, Host: u.Hostname()}
	ep.Path = u.Path
	if ep.Path == "" && ep.Host == "" {
		ep.Path = line // pure relative with no base
	}
	if ep.Path == "" {
		ep.Path = "/"
	}
	ep.Ext = extOf(ep.Path)

	if q := u.Query(); len(q) > 0 {
		for k := range q {
			ep.Params = append(ep.Params, strings.ToLower(k))
		}
		sort.Strings(ep.Params)
	} else if i := strings.IndexByte(line, '?'); i >= 0 && ep.Host == "" {
		// relative path without base: parse query manually
		for _, pair := range strings.Split(line[i+1:], "&") {
			name := pair
			if j := strings.IndexByte(pair, '='); j >= 0 {
				name = pair[:j]
			}
			if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
				ep.Params = append(ep.Params, name)
			}
		}
		sort.Strings(ep.Params)
	}
	return ep
}

func extOf(p string) string {
	seg := p
	if i := strings.LastIndexByte(seg, '/'); i >= 0 {
		seg = seg[i+1:]
	}
	e := strings.ToLower(strings.TrimPrefix(path.Ext(seg), "."))
	if len(e) > 10 { // not a real extension
		return ""
	}
	return e
}

func (e *Endpoint) addVuln(category string, sev Severity, reason string, params []string) {
	for i := range e.Vulns {
		if e.Vulns[i].Category == category {
			// keep highest severity; merge params
			if sev > e.Vulns[i].sev {
				e.Vulns[i].sev = sev
				e.Vulns[i].Severity = sev.String()
				e.Vulns[i].Reason = reason
			}
			e.Vulns[i].Params = mergeUnique(e.Vulns[i].Params, params)
			return
		}
	}
	e.Vulns = append(e.Vulns, VulnHint{
		Category: category, Severity: sev.String(), Reason: reason, Params: params, sev: sev,
	})
}

func (e *Endpoint) classify() {
	lowPath := strings.ToLower(e.Path)

	switch {
	case containsToken(lowPath, []string{"graphql", "graphiql", "gql"}):
		e.Category = "graphql"
	case staticExt[e.Ext]:
		e.Category = "static"
	case e.Ext == "js":
		e.Category = "script"
	case sensitiveExt[e.Ext].severity >= High || hasSensitiveMarker(e.Path) != "":
		e.Category = "sensitive-file"
	case dynamicExt[e.Ext] != false:
		e.Category = "dynamic"
	case containsToken(lowPath, []string{"api", "rest", "v1", "v2", "v3", "graphql", "rpc"}):
		e.Category = "api"
	case len(e.Params) > 0:
		e.Category = "parameterized"
	default:
		e.Category = "page"
	}
}

func (e *Endpoint) score() {
	// 1. Parameter-based signatures.
	if len(e.Params) > 0 {
		pset := map[string]bool{}
		for _, p := range e.Params {
			pset[p] = true
		}
		for _, sig := range paramSignatures {
			var matched []string
			for _, want := range sig.params {
				if pset[want] {
					matched = append(matched, want)
				}
			}
			if len(matched) > 0 {
				sort.Strings(matched)
				e.addVuln(sig.category, sig.severity, sig.desc, matched)
			}
		}
	}

	// 2. Path-token signatures.
	tokens := tokenize(e.Path)
	for _, sig := range pathSignatures {
		if anyToken(tokens, sig.tokens) {
			e.addVuln(sig.category, sig.severity, sig.desc, nil)
		}
	}

	// 3. Sensitive path markers (substring) and extensions.
	if m := hasSensitiveMarker(e.Path); m != "" {
		for _, sm := range sensitivePathMarkers {
			if strings.Contains(strings.ToLower(e.Path), sm.marker) {
				e.addVuln("Sensitive File/Path", sm.severity, sm.desc, nil)
				break
			}
		}
	}
	if info, ok := sensitiveExt[e.Ext]; ok {
		e.addVuln("Sensitive File/Path", info.severity, "."+e.Ext+" — "+info.desc, nil)
	}

	// 4. Aggregate risk + max severity.
	max := Info
	for _, v := range e.Vulns {
		e.Risk += v.sev.Weight()
		if v.sev > max {
			max = v.sev
		}
	}
	// Extra weight for stacked signals (multiple distinct classes on one URL).
	if len(e.Vulns) >= 3 {
		e.Risk += 3
	}
	e.MaxSev = max.String()

	// Stable ordering of hints: severity desc, then name.
	sort.SliceStable(e.Vulns, func(i, j int) bool {
		if e.Vulns[i].sev != e.Vulns[j].sev {
			return e.Vulns[i].sev > e.Vulns[j].sev
		}
		return e.Vulns[i].Category < e.Vulns[j].Category
	})
}

// ---- helpers ----

func tokenize(p string) map[string]bool {
	out := map[string]bool{}
	field := strings.FieldsFunc(strings.ToLower(p), func(r rune) bool {
		return r == '/' || r == '.' || r == '-' || r == '_' || r == '?' ||
			r == '=' || r == '&' || r == '+' || r == ',' || r == ':'
	})
	for _, f := range field {
		if f != "" {
			out[f] = true
		}
	}
	return out
}

func anyToken(tokens map[string]bool, want []string) bool {
	for _, w := range want {
		if tokens[w] {
			return true
		}
	}
	return false
}

func containsToken(lowPath string, want []string) bool {
	return anyToken(tokenize(lowPath), want)
}

func hasSensitiveMarker(p string) string {
	lp := strings.ToLower(p)
	for _, sm := range sensitivePathMarkers {
		if strings.Contains(lp, sm.marker) {
			return sm.marker
		}
	}
	return ""
}

func mergeUnique(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range append(a, b...) {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
