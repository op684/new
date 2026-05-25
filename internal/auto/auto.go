// Package auto is SPECTER's fully-automated pipeline. It chains the recon,
// harvest and analyze engines into one flow and feeds the output of each stage
// into the next: recon discovers hosts/urls/endpoints, harvest mines JS/certs
// for more subdomains + secrets + cloud assets (looped back and re-probed), and
// analyze scores the combined endpoint surface (optionally probing for live
// SQLi/LFI/XSS/open-redirect).
package auto

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"specter/internal/banner"
	"specter/internal/config"
	"specter/internal/core"
	"specter/internal/epanalyze"
	"specter/internal/harvest"
	"specter/internal/recon"
	"specter/internal/report"
	"specter/internal/ui"
	"specter/internal/vector"
)

const usage = `specter auto — fully automated recon → harvest → analyze pipeline

USAGE:
  specter auto -d target.com [options]
  specter auto -l scope.txt -deep -attack -o loot/

TARGET:
  -d   string   target apex domain
  -l   string   file with domains (one per line)

PIPELINE:
  -deep         maximum coverage: + content discovery
  -attack       active vuln probing on collected endpoints (SQLi/LFI/XSS/redirect)
  -san string   SAN certificate harvesting: "same" (default), "all", or "off"
  -git          also harvest GitHub code search (needs -gt)
  -gt  string   GitHub personal access token

TUNING:
  -t   int      concurrent workers            (default 50)
  -timeout dur  per-request timeout           (default 8s)
  -o   string   output directory              (default specter-loot)

OUTPUT:
  -json         write machine-readable report.json (always on for auto)
  -nc           disable colors
  -silent       suppress banner
  -h            help

EXAMPLES:
  specter auto -d target.com
  specter auto -d target.com -deep -attack -o loot/
  specter auto -l scope.txt -san all -git -gt <token>
`

type options struct {
	domain, list string
	deep, attack bool
	san          string
	git          bool
	gitToken     string
	threads      int
	timeout      time.Duration
	out          string
	nc, silent   bool
}

// Run is the `specter auto` subcommand entry point.
func Run(args []string) {
	opt := parse(args)
	ui.Init("cyberpunk", opt.nc)
	if !opt.silent {
		banner.Print()
	}

	targets := loadTargets(opt)
	if len(targets) == 0 {
		ui.Error("no target — use -d domain or -l file")
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; ui.Warning("interrupt — flushing results"); cancel() }()

	ui.Info("auto pipeline :: %s targets · deep:%v · attack:%v · san:%s",
		ui.Bold(strconv.Itoa(len(targets))), opt.deep, opt.attack, sanLabel(opt))

	for _, t := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		runTarget(ctx, opt, t)
	}
}

func runTarget(ctx context.Context, opt options, target string) {
	start := time.Now()
	cfg := reconConfig(opt)

	// ---- STAGE 1: reconnaissance ----
	res := recon.ReconTarget(ctx, cfg, target)

	// ---- STAGE 2: SAN certificate expansion ----
	if opt.san == "same" || opt.san == "all" {
		expandSANs(ctx, opt, res)
	}

	// ---- STAGE 3: JS / secret / cloud harvesting ----
	harvestStage(ctx, opt, res, target)

	// ---- STAGE 4: resolve + probe everything newly discovered ----
	recon.ResolveAndProbe(ctx, cfg, res)

	// ---- STAGE 5: endpoint attack-surface analysis ----
	ares := analyzeStage(ctx, opt, res, target)

	// ---- STAGE 6: unified reporting ----
	writeReports(opt, res, ares, target)
	grandSummary(res, ares, target, opt.out, time.Since(start))
}

// ---- stage 2: SANs ----

func expandSANs(ctx context.Context, opt options, res *core.Result) {
	ui.Section("auto :: certificate SAN expansion")
	var seeds []string
	for _, a := range res.Assets {
		if a.Resolved {
			seeds = append(seeds, a.Host)
		}
	}
	if len(seeds) == 0 {
		seeds = res.Hosts()
	}
	sp := ui.NewSpinner(fmt.Sprintf("walking TLS certs from %d hosts…", len(seeds)))
	sp.Start()
	var found int64
	names := harvest.HarvestSANs(ctx, seeds, harvest.SANMode(opt.san), 5*time.Second, opt.threads, 4000,
		func(string) { atomic.AddInt64(&found, 1) })
	sp.Stop()
	added := 0
	for _, n := range names {
		if res.Get(n) == nil {
			res.Upsert(n, "san")
			added++
		}
	}
	ui.Success("SAN walk found %s names (%s new)", ui.Bold(strconv.FormatInt(found, 10)), ui.Bold(strconv.Itoa(added)))
}

// ---- stage 3: harvest ----

func harvestStage(ctx context.Context, opt options, res *core.Result, target string) {
	ui.Section("auto :: JS / secret / cloud harvest")

	domains := []string{harvest.RegisteredDomain(target), target}
	engine := harvest.NewEngine(harvest.BuildSubdomainRegex(domains), 3.0)
	fetcher := harvest.NewFetcher(harvest.FetcherOptions{Timeout: opt.timeout, Insecure: true})
	hres := harvest.NewResult()
	for _, a := range res.Assets {
		hres.Seed(a.Host)
	}

	var pages []string
	for _, a := range res.Assets {
		if a.HTTP != nil {
			pages = append(pages, a.HTTP.URL)
		}
	}
	if len(pages) > 200 {
		pages = pages[:200] // keep mobile runs sane
	}
	if len(pages) == 0 {
		ui.Warning("no live hosts to harvest")
		return
	}

	var scanned, maps int64
	jobs := make(chan string, opt.threads*2)
	var wg sync.WaitGroup
	for i := 0; i < opt.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for page := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				html, _, ok := fetcher.Get(ctx, page)
				if !ok {
					continue
				}
				engine.Scan(page, html, hres)
				jsURLs, _ := fetcher.DiscoverScripts(page, html)
				for _, js := range jsURLs {
					body, _, ok := fetcher.Get(ctx, js)
					if !ok {
						continue
					}
					engine.Scan(js, body, hres)
					atomic.AddInt64(&scanned, 1)
					if src := fetcher.SourceMapContent(ctx, js, body); src != "" {
						engine.Scan(js+" [sourcemap]", src, hres)
						atomic.AddInt64(&maps, 1)
					}
				}
			}
		}()
	}
	for _, p := range pages {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	if opt.git && opt.gitToken != "" {
		githubHarvest(ctx, opt, engine, hres, domains)
	}

	// Merge harvest output back into the unified result.
	newSubs := 0
	for _, s := range hres.Subdomains() {
		if res.Get(s) == nil {
			res.Upsert(s, "harvest")
			newSubs++
		}
	}
	res.Cloud = mergeUnique(res.Cloud, hres.CloudURLs())
	res.IPv4 = mergeUnique(res.IPv4, hres.IPs())
	mergeSecrets(res, hres.Secrets())

	ui.Success("harvested %s scripts (%s source maps) → %s new subs, %s cloud assets, %s secrets",
		ui.Bold(strconv.FormatInt(scanned, 10)), ui.Bold(strconv.FormatInt(maps, 10)),
		ui.Bold(strconv.Itoa(newSubs)), ui.Bold(strconv.Itoa(len(hres.CloudURLs()))),
		ui.Bold(strconv.Itoa(len(hres.Secrets()))))
}

func githubHarvest(ctx context.Context, opt options, engine *harvest.Engine, hres *harvest.Result, domains []string) {
	gh := harvest.NewGitHubClient(opt.gitToken, opt.timeout)
	for _, d := range domains {
		urls, err := gh.SearchContentURLs(ctx, d)
		if err != nil && len(urls) == 0 {
			continue
		}
		jobs := make(chan string, opt.threads*2)
		var wg sync.WaitGroup
		for i := 0; i < opt.threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for api := range jobs {
					if content, htmlURL, ok := gh.FetchContent(ctx, api); ok {
						engine.Scan(htmlURL, content, hres)
					}
				}
			}()
		}
		for _, api := range urls {
			jobs <- api
		}
		close(jobs)
		wg.Wait()
	}
}

// ---- stage 5: analyze ----

func analyzeStage(ctx context.Context, opt options, res *core.Result, target string) *epanalyze.Result {
	ui.Section("auto :: endpoint attack-surface analysis")

	lines := make([]string, 0, len(res.Endpoints)+len(res.URLs)+len(res.Assets))
	lines = append(lines, res.Endpoints...)
	lines = append(lines, res.URLs...)
	for _, a := range res.Assets {
		if a.HTTP != nil {
			lines = append(lines, a.HTTP.URL)
		}
	}
	if len(lines) == 0 {
		ui.Warning("no endpoints to analyze")
		return epanalyze.Analyze(nil, "")
	}
	ares := epanalyze.Analyze(lines, "https://"+target)
	ui.Success("analyzed %s endpoints", ui.Bold(strconv.Itoa(ares.Total)))

	if !opt.attack {
		return ares
	}

	ui.Section("auto :: active vulnerability probing")
	ui.Warning("active injection enabled — only run against authorized targets")
	pr := epanalyze.NewProber(epanalyze.ProbeOptions{
		Timeout:   opt.timeout,
		UserAgent: "Mozilla/5.0 (Linux; Android 11; SPECTER)",
		Active:    true,
		SQLi:      true,
		LFI:       true,
	})
	var targets []*epanalyze.Endpoint
	for _, e := range ares.Endpoints {
		if epanalyze.Probeable(e) {
			targets = append(targets, e)
		}
	}
	var confirmed int64
	jobs := make(chan *epanalyze.Endpoint, opt.threads*2)
	var wg sync.WaitGroup
	for i := 0; i < opt.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if r := pr.Probe(ctx, e); r != nil {
					e.Probe = r
				}
				if len(e.Confirmed) > 0 {
					atomic.AddInt64(&confirmed, int64(len(e.Confirmed)))
					vector.PrintEndpoint(e)
				}
			}
		}()
	}
	for _, e := range targets {
		jobs <- e
	}
	close(jobs)
	wg.Wait()
	ares.Sort()
	if confirmed > 0 {
		ui.Error("%s vulnerabilities CONFIRMED", ui.Bold(strconv.FormatInt(confirmed, 10)))
	} else {
		ui.Success("no vulnerabilities confirmed on %d probed endpoints", len(targets))
	}
	return ares
}

// ---- stage 6: reporting ----

func writeReports(opt options, res *core.Result, ares *epanalyze.Result, target string) {
	writer, err := report.New(opt.out, target, true)
	if err != nil {
		ui.Error("output dir: %v", err)
		return
	}
	if err := writer.Persist(res); err != nil {
		ui.Error("persist: %v", err)
	}
	dir := writer.Dir()
	vector.WriteReport(dir, ares)
	writeLines(filepath.Join(dir, "cloud-assets.txt"), res.Cloud)
	writeLines(filepath.Join(dir, "ipv4.txt"), res.IPv4)
}

func grandSummary(res *core.Result, ares *epanalyze.Result, target, outDir string, dur time.Duration) {
	var resolved, live, takeovers int
	for _, a := range res.Assets {
		if a.Resolved {
			resolved++
		}
		if a.HTTP != nil {
			live++
		}
		if a.Takeover != "" {
			takeovers++
		}
	}
	var confirmed, critical, high int
	for _, e := range ares.Endpoints {
		confirmed += len(e.Confirmed)
		switch e.MaxSev {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		}
	}

	ui.Section("AUTO RESULTS :: " + target)
	ui.KV("subdomains", ui.Bold(strconv.Itoa(len(res.Assets))))
	ui.KV("resolved", ui.Good(strconv.Itoa(resolved)))
	ui.KV("live http", ui.Good(strconv.Itoa(live)))
	ui.KV("takeovers", redFlag(takeovers))
	ui.KV("urls", ui.Bold(strconv.Itoa(len(res.URLs))))
	ui.KV("endpoints", ui.Bold(strconv.Itoa(ares.Total)))
	ui.KV("cloud assets", ui.Bold(strconv.Itoa(len(res.Cloud))))
	ui.KV("secrets", redFlag(len(res.Secrets)))
	ui.KV("crit/high eps", ui.Warn(fmt.Sprintf("%d / %d", critical, high)))
	ui.KV("CONFIRMED vulns", redFlag(confirmed))
	ui.KV("duration", ui.Accent(dur.Round(time.Millisecond).String()))
	ui.KV("output", ui.Secondary(filepath.Join(outDir, target)))
	fmt.Println()

	// Surface the most important confirmed findings inline.
	shown := 0
	for _, e := range ares.Endpoints {
		if len(e.Confirmed) > 0 && shown < 10 {
			vector.PrintEndpoint(e)
			shown++
		}
	}
}

// ---- helpers ----

func reconConfig(opt options) *config.Config {
	return &config.Config{
		Threads:   opt.threads,
		Timeout:   opt.timeout,
		Resolvers: []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},
		UserAgent: "Mozilla/5.0 (Linux; Android 11; SPECTER) recon/" + banner.Version,
		Passive:   true,
		BruteSubs: true,
		Probe:     true,
		Tech:      true,
		URLs:      true,
		JS:        true,
		Content:   opt.deep,
		Theme:     "cyberpunk",
		OutDir:    opt.out,
	}
}

func parse(args []string) options {
	var opt options
	fs := flag.NewFlagSet("auto", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	fs.StringVar(&opt.domain, "d", "", "")
	fs.StringVar(&opt.list, "l", "", "")
	fs.BoolVar(&opt.deep, "deep", false, "")
	fs.BoolVar(&opt.attack, "attack", false, "")
	fs.StringVar(&opt.san, "san", "same", "")
	fs.BoolVar(&opt.git, "git", false, "")
	fs.StringVar(&opt.gitToken, "gt", "", "")
	fs.IntVar(&opt.threads, "t", 50, "")
	fs.DurationVar(&opt.timeout, "timeout", 8*time.Second, "")
	fs.StringVar(&opt.out, "o", "specter-loot", "")
	fs.BoolVar(&opt.nc, "nc", false, "")
	fs.BoolVar(&opt.silent, "silent", false, "")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if opt.threads < 1 {
		opt.threads = 1
	}
	opt.san = strings.ToLower(strings.TrimSpace(opt.san))
	return opt
}

func loadTargets(opt options) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(strings.ToLower(s))
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimSuffix(s, "/")
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if opt.domain != "" {
		add(opt.domain)
	}
	if opt.list != "" {
		data, err := os.ReadFile(opt.list)
		if err == nil {
			for _, l := range strings.Split(string(data), "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
					add(l)
				}
			}
		}
	}
	return out
}

func mergeUnique(base, extra []string) []string {
	seen := map[string]bool{}
	for _, b := range base {
		seen[b] = true
	}
	for _, e := range extra {
		if !seen[e] {
			seen[e] = true
			base = append(base, e)
		}
	}
	sort.Strings(base)
	return base
}

func mergeSecrets(res *core.Result, secrets []harvest.Secret) {
	seen := map[string]bool{}
	for _, s := range res.Secrets {
		seen[s.Type+"|"+s.Match] = true
	}
	for _, s := range secrets {
		key := s.Type + "|" + s.Match
		if seen[key] {
			continue
		}
		seen[key] = true
		res.Secrets = append(res.Secrets, core.Secret{Type: s.Type, Match: s.Match, Source: s.Source})
	}
}

func writeLines(path string, lines []string) {
	if len(lines) == 0 {
		return
	}
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func sanLabel(opt options) string {
	if opt.san == "same" || opt.san == "all" {
		return opt.san
	}
	return "off"
}

func redFlag(n int) string {
	if n == 0 {
		return ui.Muted("0")
	}
	return ui.Bad(ui.Bold(strconv.Itoa(n)))
}
