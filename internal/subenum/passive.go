// Package subenum discovers subdomains via passive OSINT sources and active
// DNS bruteforcing.
package subenum

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Source is a named passive data provider.
type Source struct {
	Name string
	Fn   func(ctx context.Context, client *http.Client, domain string) ([]string, error)
}

// Sources is the registry of passive providers used by SPECTER. All are
// free and key-less so they work out of the box on mobile.
var Sources = []Source{
	{"crt.sh", crtsh},
	{"hackertarget", hackertarget},
	{"alienvault", alienvault},
	{"certspotter", certspotter},
	{"anubis", anubis},
	{"rapiddns", rapiddns},
}

// PassiveResult bundles a source name with what it found (for live logging).
type PassiveResult struct {
	Source string
	Subs   []string
	Err    error
}

// Passive queries every source concurrently and streams per-source results.
// The returned channel is closed when all sources finish.
func Passive(ctx context.Context, client *http.Client, domain string) <-chan PassiveResult {
	out := make(chan PassiveResult, len(Sources))
	var wg sync.WaitGroup
	for _, s := range Sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			subs, err := s.Fn(ctx, client, domain)
			out <- PassiveResult{Source: s.Name, Subs: clean(subs, domain), Err: err}
		}(s)
	}
	go func() { wg.Wait(); close(out) }()
	return out
}

func clean(in []string, domain string) []string {
	seen := map[string]bool{}
	var out []string
	suffix := "." + domain
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "*.")
		s = strings.TrimPrefix(s, ".")
		if s == "" || seen[s] {
			continue
		}
		if s == domain || strings.HasSuffix(s, suffix) {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "specter-recon")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

func crtsh(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := get(ctx, client, "https://crt.sh/?q=%25."+domain+"&output=json")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		for _, n := range strings.Split(r.NameValue, "\n") {
			out = append(out, n)
		}
	}
	return out, nil
}

func hackertarget(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := get(ctx, client, "https://api.hackertarget.com/hostsearch/?q="+domain)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ','); i > 0 {
			out = append(out, line[:i])
		}
	}
	return out, nil
}

func alienvault(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	url := "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns"
	body, err := get(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range data.PassiveDNS {
		out = append(out, p.Hostname)
	}
	return out, nil
}

func certspotter(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	url := "https://api.certspotter.com/v1/issuances?domain=" + domain +
		"&include_subdomains=true&expand=dns_names"
	body, err := get(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out, nil
}

func anubis(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := get(ctx, client, "https://jldc.me/anubis/subdomains/"+domain)
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func rapiddns(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := get(ctx, client, "https://rapiddns.io/subdomain/"+domain+"?full=1")
	if err != nil {
		return nil, err
	}
	// Lightweight scrape: subdomains appear inside <td> cells.
	var out []string
	html := string(body)
	for {
		i := strings.Index(html, "<td>")
		if i < 0 {
			break
		}
		html = html[i+4:]
		j := strings.Index(html, "</td>")
		if j < 0 {
			break
		}
		cell := strings.TrimSpace(html[:j])
		if strings.Contains(cell, domain) && !strings.Contains(cell, "<") {
			out = append(out, cell)
		}
		html = html[j+5:]
	}
	return out, nil
}
