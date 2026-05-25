// SPECTER — an advanced, modular bug bounty reconnaissance framework.
// Pure Go standard library only, so it cross-compiles cleanly for arm64/Termux.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"specter/internal/banner"
	"specter/internal/config"
	"specter/internal/content"
	"specter/internal/core"
	"specter/internal/portscan"
	"specter/internal/probe"
	"specter/internal/report"
	"specter/internal/resolver"
	"specter/internal/subenum"
	"specter/internal/ui"
	"specter/internal/urls"
	"specter/internal/wordlist"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		os.Exit(2)
	}

	ui.Init(cfg.Theme, cfg.NoColr)
	if !cfg.Silent {
		banner.Print()
	}

	// Ctrl+C cancels the whole run gracefully.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		ui.Warning("interrupt received — shutting down, flushing partial results…")
		cancel()
	}()

	if !cfg.Silent {
		printPlan(cfg)
	}

	for _, target := range cfg.Targets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		runTarget(ctx, cfg, target)
	}
}

func printPlan(cfg *config.Config) {
	enabled := func(b bool) string {
		if b {
			return ui.Good("on")
		}
		return ui.Muted("off")
	}
	ui.Info("targets:    %s", ui.Bold(fmt.Sprintf("%d", len(cfg.Targets))))
	ui.Info("modules:    passive:%s brute:%s probe:%s ports:%s tech:%s urls:%s content:%s",
		enabled(cfg.Passive), enabled(cfg.BruteSubs), enabled(cfg.Probe),
		enabled(cfg.Ports), enabled(cfg.Tech), enabled(cfg.URLs), enabled(cfg.Content))
	ui.Info("threads:    %s   timeout: %s   resolvers: %d",
		ui.Bold(fmt.Sprintf("%d", cfg.Threads)), cfg.Timeout, len(cfg.Resolvers))
}

func runTarget(ctx context.Context, cfg *config.Config, target string) {
	ui.Section("target :: " + target)
	res := core.NewResult(target)

	writer, err := report.New(cfg.OutDir, target, cfg.JSON)
	if err != nil {
		ui.Error("cannot create output dir: %v", err)
		return
	}

	httpClient := &http.Client{Timeout: cfg.Timeout}
	dns := resolver.New(cfg.Resolvers, cfg.Timeout)

	// Always include the apex itself.
	res.Upsert(target, "seed")

	if cfg.Passive {
		runPassive(ctx, cfg, httpClient, res, target)
	}
	if cfg.BruteSubs {
		runBrute(ctx, cfg, dns, res, target)
	}

	// Resolve everything we discovered (passive sources don't confirm liveness).
	resolveAll(ctx, cfg, dns, res)

	if cfg.Probe || cfg.Tech {
		runProbe(ctx, cfg, res)
	}
	if cfg.Ports {
		runPorts(ctx, cfg, res)
	}
	if cfg.URLs {
		runURLs(ctx, httpClient, res, target)
	}
	if cfg.Content {
		runContent(ctx, cfg, res)
	}

	if err := writer.Persist(res); err != nil {
		ui.Error("write results: %v", err)
	}
	report.Summary(res, writer.Dir())
}

func runPassive(ctx context.Context, cfg *config.Config, client *http.Client, res *core.Result, target string) {
	ui.Section("passive enumeration")
	sp := ui.NewSpinner("querying OSINT sources…")
	sp.Start()

	var total int
	for pr := range subenum.Passive(ctx, client, target) {
		if pr.Err != nil {
			sp.Stop()
			ui.Warning("%-13s %s", pr.Source, ui.Muted(pr.Err.Error()))
			sp = ui.NewSpinner("querying OSINT sources…")
			sp.Start()
			continue
		}
		sp.Stop()
		for _, sub := range pr.Subs {
			res.Upsert(sub, pr.Source)
		}
		total += len(pr.Subs)
		ui.Success("%-13s %s subdomains", ui.Accent(pr.Source), ui.Bold(fmt.Sprintf("%d", len(pr.Subs))))
		sp = ui.NewSpinner("querying OSINT sources…")
		sp.Start()
	}
	sp.Stop()
	ui.Info("passive total: %s unique hosts", ui.Bold(fmt.Sprintf("%d", len(res.Assets))))
}

func runBrute(ctx context.Context, cfg *config.Config, dns *resolver.Resolver, res *core.Result, target string) {
	ui.Section("dns bruteforce")
	words := wordlist.Subdomains(cfg.SubWordlist)
	ui.Info("wordlist: %s candidates", ui.Bold(fmt.Sprintf("%d", len(words))))

	var hits int64
	var lastReport int64
	subenum.Bruteforce(ctx, dns, target, words, cfg.Threads,
		func(rec *resolver.Record) {
			atomic.AddInt64(&hits, 1)
			a := res.Upsert(rec.Host, "bruteforce")
			res.Lock()
			a.Resolved = true
			a.IPs = rec.IPs
			a.CNAME = rec.CNAME
			res.Unlock()
			ui.Result("%s %s", ui.Primary(rec.Host), ui.Muted("["+joinIPs(rec.IPs)+"]"))
		},
		func(done, total int64) {
			if done-atomic.LoadInt64(&lastReport) >= 200 || done == total {
				atomic.StoreInt64(&lastReport, done)
				ui.Progress("%s %d/%d tested, %d resolved   ",
					ui.Muted("   progress:"), done, total, atomic.LoadInt64(&hits))
			}
		})
	ui.ClearLine()
	ui.Success("bruteforce found %s live subdomains", ui.Bold(fmt.Sprintf("%d", hits)))
}

func resolveAll(ctx context.Context, cfg *config.Config, dns *resolver.Resolver, res *core.Result) {
	hosts := res.Hosts()
	var pending []string
	for _, h := range hosts {
		a := res.Get(h)
		if a != nil && !a.Resolved {
			pending = append(pending, h)
		}
	}
	if len(pending) == 0 {
		return
	}
	ui.Section("dns resolution")
	sp := ui.NewSpinner(fmt.Sprintf("resolving %d hosts…", len(pending)))
	sp.Start()

	var resolved int64
	jobs := make(chan string, cfg.Threads*2)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if rec, ok := dns.Resolve(h); ok {
					a := res.Get(h)
					if a != nil {
						res.Lock()
						a.Resolved = true
						a.IPs = rec.IPs
						a.CNAME = rec.CNAME
						res.Unlock()
						atomic.AddInt64(&resolved, 1)
					}
				}
			}
		}()
	}
	for _, h := range pending {
		jobs <- h
	}
	close(jobs)
	wg.Wait()
	sp.Stop()
	ui.Success("resolved %s / %d hosts", ui.Bold(fmt.Sprintf("%d", resolved)), len(pending))
}

func runProbe(ctx context.Context, cfg *config.Config, res *core.Result) {
	ui.Section("http probing" + techNote(cfg))
	pr := probe.New(probe.Options{
		Timeout:        cfg.Timeout,
		UserAgent:      cfg.UserAgent,
		Headers:        cfg.Headers,
		FollowRedirect: cfg.FollowRedirect,
		DetectTech:     cfg.Tech,
	})

	var targets []string
	for _, a := range res.Assets {
		if a.Resolved {
			targets = append(targets, a.Host)
		}
	}
	if len(targets) == 0 {
		ui.Warning("no resolved hosts to probe")
		return
	}

	var live int64
	jobs := make(chan string, cfg.Threads*2)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				result := pr.Probe(ctx, h)
				if result == nil {
					continue
				}
				if len(cfg.MatchCodes) > 0 && !contains(cfg.MatchCodes, result.StatusCode) {
					continue
				}
				a := res.Get(h)
				if a == nil {
					continue
				}
				res.Lock()
				a.HTTP = result
				a.Technology = result.Technology
				res.Unlock()
				atomic.AddInt64(&live, 1)
				printLive(result)
			}
		}()
	}
	for _, h := range targets {
		jobs <- h
	}
	close(jobs)
	wg.Wait()
	ui.Success("%s live HTTP services", ui.Bold(fmt.Sprintf("%d", live)))
}

func runPorts(ctx context.Context, cfg *config.Config, res *core.Result) {
	ports, err := portscan.ParsePorts(cfg.PortSpec)
	if err != nil {
		ui.Error("port spec: %v", err)
		return
	}
	ui.Section(fmt.Sprintf("port scan :: %d ports", len(ports)))

	var targets []*core.Asset
	for _, a := range res.Assets {
		if a.Resolved {
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		ui.Warning("no resolved hosts to scan")
		return
	}

	// Per-host worker budget so we don't overload a phone's file descriptors.
	hostWorkers := cfg.Threads
	if hostWorkers > 200 {
		hostWorkers = 200
	}
	for _, a := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		scanTarget := a.Host
		if len(a.IPs) > 0 {
			scanTarget = a.IPs[0]
		}
		open := portscan.Scan(ctx, scanTarget, ports, hostWorkers, cfg.Timeout)
		if len(open) == 0 {
			continue
		}
		res.Lock()
		a.OpenPorts = open
		res.Unlock()
		labels := make([]string, len(open))
		for i, p := range open {
			labels[i] = portscan.Label(p)
		}
		ui.Result("%s %s", ui.Primary(a.Host), ui.Warn("→ "+join(labels)))
	}
	ui.Success("port scan complete")
}

func runURLs(ctx context.Context, client *http.Client, res *core.Result, target string) {
	ui.Section("historical url mining")
	sp := ui.NewSpinner("querying wayback + otx archives…")
	sp.Start()
	found, err := urls.Fetch(ctx, client, target)
	sp.Stop()
	if err != nil && len(found) == 0 {
		ui.Warning("url mining: %v", err)
		return
	}
	res.URLs = found
	ui.Success("collected %s archived URLs", ui.Bold(fmt.Sprintf("%d", len(found))))
	interesting := urls.Interesting(found)
	if len(interesting) > 0 {
		ui.Warning("%s URLs look interesting (params/secrets/endpoints):", ui.Bold(fmt.Sprintf("%d", len(interesting))))
		max := 15
		for i, u := range interesting {
			if i >= max {
				ui.Muted2("   …and %d more (see urls-interesting.txt)", len(interesting)-max)
				break
			}
			ui.Result("%s", ui.Accent(u))
		}
	}
}

func runContent(ctx context.Context, cfg *config.Config, res *core.Result) {
	ui.Section("content discovery")
	words := wordlist.Content(cfg.ContentWordlist)
	sc := content.New(content.Options{
		Timeout:    cfg.Timeout,
		UserAgent:  cfg.UserAgent,
		MatchCodes: cfg.MatchCodes,
	})

	var bases []string
	for _, a := range res.Assets {
		if a.HTTP != nil {
			bases = append(bases, a.HTTP.URL)
		}
	}
	if len(bases) == 0 {
		ui.Warning("no live HTTP hosts — run with -probe to enable content discovery")
		return
	}
	ui.Info("probing %d paths across %d live hosts", len(words), len(bases))

	var total int64
	for _, base := range bases {
		select {
		case <-ctx.Done():
			return
		default:
		}
		sc.Run(ctx, base, words, cfg.Threads,
			func(f core.Finding) {
				res.Lock()
				res.Findings = append(res.Findings, f)
				res.Unlock()
				atomic.AddInt64(&total, 1)
				ui.Result("%s %s %s",
					codeColor(f.StatusCode, fmt.Sprintf("%d", f.StatusCode)),
					ui.Muted(fmt.Sprintf("%7dB", f.ContentLength)),
					ui.Accent(f.URL))
			}, nil)
	}
	ui.Success("content discovery found %s endpoints", ui.Bold(fmt.Sprintf("%d", total)))
}

// ---- presentation helpers ----

func printLive(r *core.HTTPResult) {
	parts := fmt.Sprintf("%s %s", codeColor(r.StatusCode, fmt.Sprintf("[%d]", r.StatusCode)), ui.Primary(r.URL))
	if r.Title != "" {
		parts += " " + ui.Secondary("["+r.Title+"]")
	}
	if r.Server != "" {
		parts += " " + ui.Muted("["+r.Server+"]")
	}
	if len(r.Technology) > 0 {
		parts += " " + ui.Accent("["+join(r.Technology)+"]")
	}
	ui.Result("%s", parts)
}

func codeColor(code int, s string) string {
	switch {
	case code >= 200 && code < 300:
		return ui.Good(s)
	case code >= 300 && code < 400:
		return ui.Secondary(s)
	case code >= 400 && code < 500:
		return ui.Warn(s)
	default:
		return ui.Bad(s)
	}
}

func techNote(cfg *config.Config) string {
	if cfg.Tech {
		return " + fingerprint"
	}
	return ""
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

func joinIPs(ips []string) string { return join(ips) }
