package harvest

import (
	"net/url"
	"regexp"
	"strings"
)

// multiLabelTLDs is a curated subset of public suffixes with two labels, so
// RegisteredDomain handles e.g. example.co.uk correctly without a full PSL
// (keeps the build dependency-free for Termux).
var multiLabelTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "me.uk": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "go.jp": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "govt.nz": true,
	"co.za": true, "org.za": true, "gov.za": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
	"com.mx": true, "com.tr": true, "com.tw": true, "com.hk": true, "com.sg": true,
	"com.ar": true, "com.co": true, "com.pe": true, "com.ph": true, "com.my": true,
	"co.in": true, "co.id": true, "co.kr": true, "co.th": true, "co.il": true,
	"or.kr": true, "ne.kr": true, "go.kr": true,
}

// RegisteredDomain returns the registrable domain (eTLD+1) of a host/URL using
// the curated multi-label suffix set.
func RegisteredDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.IndexAny(host, "/:?#"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, ".")
	labels := strings.Split(host, ".")
	n := len(labels)
	if n < 2 {
		return host
	}
	lastTwo := labels[n-2] + "." + labels[n-1]
	if multiLabelTLDs[lastTwo] && n >= 3 {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

// HostOf extracts the hostname from a URL or bare host string.
func HostOf(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// BuildSubdomainRegex compiles a pattern matching any subdomain of the given
// registrable domains (and bare custom domains).
func BuildSubdomainRegex(domains []string) *regexp.Regexp {
	seen := map[string]bool{}
	var parts []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		// match: label(.label)* . domain
		parts = append(parts, `[a-zA-Z0-9][a-zA-Z0-9\-.]*\.`+regexp.QuoteMeta(d))
		// also match the apex itself
		parts = append(parts, regexp.QuoteMeta(d))
	}
	if len(parts) == 0 {
		return nil
	}
	return regexp.MustCompile(`(?i)(?:` + strings.Join(parts, "|") + `)`)
}
