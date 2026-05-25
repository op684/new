// Package takeover flags potential subdomain takeovers by correlating a
// host's CNAME target with a service-specific "unclaimed" response fingerprint.
package takeover

import "strings"

type rule struct {
	service     string
	cnames      []string // CNAME substrings that point at the service
	fingerprint string   // body marker indicating the resource is unclaimed
}

// rules is a curated, conservative fingerprint set (low false-positive).
var rules = []rule{
	{"GitHub Pages", []string{"github.io"}, "There isn't a GitHub Pages site here"},
	{"AWS S3", []string{"s3.amazonaws.com", "s3-website"}, "NoSuchBucket"},
	{"Heroku", []string{"herokudns.com", "herokuapp.com"}, "No such app"},
	{"Shopify", []string{"myshopify.com"}, "Sorry, this shop is currently unavailable"},
	{"Fastly", []string{"fastly.net"}, "Fastly error: unknown domain"},
	{"Tumblr", []string{"domains.tumblr.com"}, "Whatever you were looking for doesn't currently exist"},
	{"Surge.sh", []string{"surge.sh"}, "project not found"},
	{"Bitbucket", []string{"bitbucket.io"}, "Repository not found"},
	{"Ghost", []string{"ghost.io"}, "The thing you were looking for is no longer here"},
	{"Pantheon", []string{"pantheonsite.io"}, "The gods are wise"},
	{"Unbounce", []string{"unbouncepages.com"}, "The requested URL was not found on this server"},
	{"Helpjuice", []string{"helpjuice.com"}, "We could not find what you're looking for"},
	{"HelpScout", []string{"helpscoutdocs.com"}, "No settings were found for this company"},
	{"Cargo", []string{"cargocollective.com"}, "404 Not Found"},
	{"Webflow", []string{"proxy-ssl.webflow.com", "webflow.io"}, "The page you are looking for doesn't exist"},
	{"Wordpress", []string{"wordpress.com"}, "Do you want to register"},
	{"Netlify", []string{"netlify.app", "netlify.com"}, "Not Found - Request ID"},
	{"Readme.io", []string{"readme.io"}, "Project doesnt exist... yet!"},
	{"Zendesk", []string{"zendesk.com"}, "Help Center Closed"},
}

// Check returns a non-empty description if (cname, body) match a takeover rule.
func Check(cname, body string) string {
	if cname == "" {
		return ""
	}
	cl := strings.ToLower(cname)
	for _, r := range rules {
		matchedCNAME := false
		for _, c := range r.cnames {
			if strings.Contains(cl, c) {
				matchedCNAME = true
				break
			}
		}
		if !matchedCNAME {
			continue
		}
		if body != "" && strings.Contains(body, r.fingerprint) {
			return r.service + " (dangling CNAME → " + cname + ")"
		}
		// CNAME points at the service but no body to confirm: surface as a lead.
		if body == "" {
			return r.service + " (CNAME → " + cname + ", verify manually)"
		}
	}
	return ""
}
