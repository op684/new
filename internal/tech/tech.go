// Package tech performs lightweight technology fingerprinting from HTTP
// response headers and body markers — a compact, offline Wappalyzer.
package tech

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
)

type signature struct {
	name      string
	headers   map[string]*regexp.Regexp // header name -> value pattern (nil = presence only)
	bodyRX    []*regexp.Regexp
	cookies   []string
	serverHas []string
}

func rx(p string) *regexp.Regexp { return regexp.MustCompile("(?i)" + p) }

var signatures = []signature{
	{name: "WordPress", bodyRX: []*regexp.Regexp{rx(`wp-content`), rx(`wp-includes`)}, headers: map[string]*regexp.Regexp{"Link": rx(`wp-json`)}},
	{name: "Drupal", headers: map[string]*regexp.Regexp{"X-Generator": rx(`Drupal`), "X-Drupal-Cache": nil}, bodyRX: []*regexp.Regexp{rx(`sites/all`)}},
	{name: "Joomla", bodyRX: []*regexp.Regexp{rx(`/media/jui/`), rx(`Joomla`)}},
	{name: "Nginx", serverHas: []string{"nginx"}},
	{name: "Apache", serverHas: []string{"apache"}},
	{name: "Microsoft-IIS", serverHas: []string{"iis", "microsoft-iis"}},
	{name: "LiteSpeed", serverHas: []string{"litespeed"}},
	{name: "Cloudflare", headers: map[string]*regexp.Regexp{"CF-RAY": nil, "Server": rx(`cloudflare`)}},
	{name: "Akamai", headers: map[string]*regexp.Regexp{"X-Akamai-Transformed": nil}},
	{name: "Fastly", headers: map[string]*regexp.Regexp{"X-Served-By": rx(`cache-`), "Fastly-Debug-Digest": nil}},
	{name: "Amazon-CloudFront", headers: map[string]*regexp.Regexp{"X-Amz-Cf-Id": nil, "Via": rx(`cloudfront`)}},
	{name: "Varnish", headers: map[string]*regexp.Regexp{"X-Varnish": nil, "Via": rx(`varnish`)}},
	{name: "PHP", headers: map[string]*regexp.Regexp{"X-Powered-By": rx(`php`)}, cookies: []string{"phpsessid"}},
	{name: "ASP.NET", headers: map[string]*regexp.Regexp{"X-Powered-By": rx(`asp\.net`), "X-AspNet-Version": nil}, cookies: []string{"asp.net_sessionid"}},
	{name: "Express", headers: map[string]*regexp.Regexp{"X-Powered-By": rx(`express`)}},
	{name: "Laravel", cookies: []string{"laravel_session", "xsrf-token"}},
	{name: "Django", cookies: []string{"csrftoken", "sessionid"}, bodyRX: []*regexp.Regexp{rx(`csrfmiddlewaretoken`)}},
	{name: "Ruby-on-Rails", cookies: []string{"_rails", "_session_id"}, headers: map[string]*regexp.Regexp{"X-Powered-By": rx(`phusion passenger`)}},
	{name: "Next.js", bodyRX: []*regexp.Regexp{rx(`__NEXT_DATA__`), rx(`/_next/`)}},
	{name: "Nuxt.js", bodyRX: []*regexp.Regexp{rx(`__NUXT__`), rx(`/_nuxt/`)}},
	{name: "React", bodyRX: []*regexp.Regexp{rx(`data-reactroot`), rx(`react(\.production)?\.min\.js`)}},
	{name: "Vue.js", bodyRX: []*regexp.Regexp{rx(`data-v-app`), rx(`vue(\.runtime)?(\.min)?\.js`)}},
	{name: "Angular", bodyRX: []*regexp.Regexp{rx(`ng-version`), rx(`ng-app`)}},
	{name: "jQuery", bodyRX: []*regexp.Regexp{rx(`jquery[-.]?\d`)}},
	{name: "Bootstrap", bodyRX: []*regexp.Regexp{rx(`bootstrap(\.min)?\.css`)}},
	{name: "Tomcat", serverHas: []string{"tomcat", "coyote"}},
	{name: "Jetty", serverHas: []string{"jetty"}},
	{name: "Gunicorn", serverHas: []string{"gunicorn"}},
	{name: "Werkzeug/Flask", serverHas: []string{"werkzeug"}},
	{name: "Kestrel", serverHas: []string{"kestrel"}},
	{name: "OpenResty", serverHas: []string{"openresty"}},
	{name: "Shopify", headers: map[string]*regexp.Regexp{"X-Shopify-Stage": nil, "X-ShopId": nil}},
	{name: "GitHub-Pages", serverHas: []string{"github.com"}, headers: map[string]*regexp.Regexp{"Server": rx(`github\.com`)}},
	{name: "Vercel", headers: map[string]*regexp.Regexp{"Server": rx(`vercel`), "X-Vercel-Id": nil}},
	{name: "Netlify", headers: map[string]*regexp.Regexp{"Server": rx(`netlify`)}},
	{name: "Kubernetes-Ingress", headers: map[string]*regexp.Regexp{"X-Kubernetes": nil}},
	{name: "Grafana", bodyRX: []*regexp.Regexp{rx(`grafana`)}, cookies: []string{"grafana_session"}},
	{name: "Kibana", bodyRX: []*regexp.Regexp{rx(`kbn-name`), rx(`kibana`)}},
	{name: "Jenkins", headers: map[string]*regexp.Regexp{"X-Jenkins": nil}, bodyRX: []*regexp.Regexp{rx(`jenkins`)}},
	{name: "GitLab", bodyRX: []*regexp.Regexp{rx(`gitlab`)}, headers: map[string]*regexp.Regexp{"X-Gitlab-Feature-Category": nil}},
	{name: "Atlassian-Jira", bodyRX: []*regexp.Regexp{rx(`jira`)}, headers: map[string]*regexp.Regexp{"X-AUSERNAME": nil}},
	{name: "WooCommerce", bodyRX: []*regexp.Regexp{rx(`woocommerce`)}},
	{name: "Magento", cookies: []string{"frontend"}, bodyRX: []*regexp.Regexp{rx(`/mage/`), rx(`Magento`)}},
}

// Detect returns the sorted list of technologies inferred from a response.
func Detect(header http.Header, body string) []string {
	found := map[string]bool{}

	server := strings.ToLower(header.Get("Server"))
	powered := strings.ToLower(header.Get("X-Powered-By"))
	cookieBlob := strings.ToLower(strings.Join(header.Values("Set-Cookie"), " "))

	for _, sig := range signatures {
		if matchSig(sig, header, server, cookieBlob, body) {
			found[sig.name] = true
		}
	}

	// Surface raw X-Powered-By tokens we don't have explicit signatures for.
	if powered != "" {
		for _, tok := range strings.FieldsFunc(powered, func(r rune) bool { return r == ',' || r == ';' }) {
			tok = strings.TrimSpace(tok)
			if tok != "" && len(tok) < 40 && !found[tok] {
				found[titleish(tok)] = true
			}
		}
	}

	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func matchSig(sig signature, header http.Header, server, cookieBlob, body string) bool {
	for _, s := range sig.serverHas {
		if strings.Contains(server, s) {
			return true
		}
	}
	for name, pat := range sig.headers {
		vals := header.Values(name)
		if len(vals) == 0 {
			continue
		}
		if pat == nil {
			return true
		}
		for _, v := range vals {
			if pat.MatchString(v) {
				return true
			}
		}
	}
	for _, c := range sig.cookies {
		if strings.Contains(cookieBlob, c) {
			return true
		}
	}
	if body != "" {
		for _, b := range sig.bodyRX {
			if b.MatchString(body) {
				return true
			}
		}
	}
	return false
}

func titleish(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
