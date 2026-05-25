// Package phantom is SPECTER's JS-aware subdomain, secret & cloud-asset
// harvester — a Go reimplementation and upgrade of SubDomainizer. It mines
// subdomains, secrets, cloud-storage URLs and IPv4s from inline/external
// JavaScript (plus source maps), local folders, GitHub code search, and TLS
// Subject Alternative Names.
package phantom

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"specter/internal/harvest"
	"specter/internal/ui"
)

const version = "2.1.0"

const art = `
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝`

const usage = `PHANTOM — subdomain, secret & cloud-asset harvester (SPECTER suite)
the Go reimplementation & upgrade of SubDomainizer

USAGE:
  phantom -u https://target.com
  phantom -l urls.txt -san same -o subs.txt -sop secrets.txt
  phantom -f ./source_dir -d target.com
  phantom -u https://target.com -g -gt <github_token>

INPUT (choose one of -u / -l / -f):
  -u    string   URL to harvest (inline + external JS + source maps)
  -l    string   file with URLs (one per line)
  -f    string   local folder/file to scan recursively

SCOPE / DETECTION:
  -d    string   extra domains to hunt for, comma-separated (no spaces)
  -e    float    Shannon-entropy threshold for generic secrets (default 3.0)
  -maps          mine JavaScript source maps for original source (default on)
  -san  string   harvest Subject Alternative Names: "same" or "all"

GITHUB (both required together):
  -g             scan GitHub code search for the domain
  -gt   string   GitHub personal access token

REQUEST:
  -c    string   Cookie header value
  -H    string   extra header "Name: Value" (repeatable)
  -k             skip TLS certificate verification
  -t    int      concurrent workers          (default 12)
  -timeout dur   per-request timeout          (default 20s)

OUTPUT:
  -o    string   write subdomains to file
  -cop  string   write cloud URLs to file
  -sop  string   write secrets to file
  -gop  string   write GitHub-sourced secrets to file
  -json          print full results as JSON
  -nc            disable colors
  -silent        suppress banner
  -v / -h        version / help

EXAMPLES:
  phantom -u https://target.com -san same -o subs.txt -sop secrets.txt -cop cloud.txt
  phantom -l scope.txt -d target.com,target.io -maps -t 20
  phantom -f ./js_dump -d target.com -e 3.5
`

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

type options struct {
	url, list, folder  string
	domains            string
	entropy            float64
	maps               bool
	san                string
	git                bool
	gitToken           string
	cookie             string
	headers            headerList
	insecure           bool
	threads            int
	timeout            time.Duration
	outSubs, outCloud  string
	outSecrets, outGit string
	jsonOut            bool
	nc, silent         bool
}

// Run is the `specter harvest` subcommand entry point.
func Run(args []string) {
	opt, showVer := parseFlags(args)
	if showVer {
		fmt.Printf("phantom v%s\n", version)
		return
	}
	ui.Init("cyberpunk", opt.nc)
	if !opt.silent {
		printBanner()
	}
	if err := validate(opt); err != nil {
		ui.Error("%v", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; ui.Warning("interrupt — flushing results"); cancel() }()

	res := harvest.NewResult()
	domains, urls := scopeAndURLs(opt)
	engine := harvest.NewEngine(harvest.BuildSubdomainRegex(domains), opt.entropy)
	fetcher := harvest.NewFetcher(harvest.FetcherOptions{
		Timeout:  opt.timeout,
		Insecure: opt.insecure,
		Cookie:   opt.cookie,
		Headers:  opt.headers,
	})

	switch {
	case opt.folder != "":
		scanFolder(opt.folder, engine, res)
	default:
		for _, u := range urls {
			res.Seed(harvest.HostOf(u))
			harvestURL(ctx, opt, fetcher, engine, res, u)
		}
	}

	if opt.git && opt.gitToken != "" {
		scanGitHub(ctx, opt, engine, res, domains)
	}

	if opt.san == string(harvest.SANSame) || opt.san == string(harvest.SANAll) {
		runSANs(ctx, opt, res)
	}

	if opt.jsonOut {
		emitJSON(res)
	}
	render(res)
	writeOutputs(opt, res)
}

func parseFlags(args []string) (options, bool) {
	var opt options
	var showVer bool
	fs := flag.NewFlagSet("phantom", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	fs.StringVar(&opt.url, "u", "", "")
	fs.StringVar(&opt.list, "l", "", "")
	fs.StringVar(&opt.folder, "f", "", "")
	fs.StringVar(&opt.domains, "d", "", "")
	fs.Float64Var(&opt.entropy, "e", 3.0, "")
	fs.BoolVar(&opt.maps, "maps", true, "")
	fs.StringVar(&opt.san, "san", "", "")
	fs.BoolVar(&opt.git, "g", false, "")
	fs.StringVar(&opt.gitToken, "gt", "", "")
	fs.StringVar(&opt.cookie, "c", "", "")
	fs.Var(&opt.headers, "H", "")
	fs.BoolVar(&opt.insecure, "k", false, "")
	fs.IntVar(&opt.threads, "t", 12, "")
	fs.DurationVar(&opt.timeout, "timeout", 20*time.Second, "")
	fs.StringVar(&opt.outSubs, "o", "", "")
	fs.StringVar(&opt.outCloud, "cop", "", "")
	fs.StringVar(&opt.outSecrets, "sop", "", "")
	fs.StringVar(&opt.outGit, "gop", "", "")
	fs.BoolVar(&opt.jsonOut, "json", false, "")
	fs.BoolVar(&opt.nc, "nc", false, "")
	fs.BoolVar(&opt.silent, "silent", false, "")
	fs.BoolVar(&showVer, "v", false, "")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if opt.threads < 1 {
		opt.threads = 1
	}
	return opt, showVer
}

func validate(opt options) error {
	n := 0
	for _, s := range []string{opt.url, opt.list, opt.folder} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("exactly one of -u, -l or -f is required")
	}
	if opt.git != (opt.gitToken != "") {
		return fmt.Errorf("GitHub scan needs both -g and -gt <token>")
	}
	if opt.san != "" && opt.san != "same" && opt.san != "all" {
		return fmt.Errorf("-san must be 'same' or 'all'")
	}
	return nil
}

func scopeAndURLs(opt options) (domains, urls []string) {
	seen := map[string]bool{}
	addDomain := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	if opt.url != "" {
		urls = append(urls, opt.url)
		addDomain(harvest.RegisteredDomain(harvest.HostOf(opt.url)))
	}
	if opt.list != "" {
		for _, u := range readLines(opt.list) {
			urls = append(urls, u)
			addDomain(harvest.RegisteredDomain(harvest.HostOf(u)))
		}
	}
	for _, d := range strings.Split(opt.domains, ",") {
		addDomain(d)
	}
	return domains, urls
}

func harvestURL(ctx context.Context, opt options, f *harvest.Fetcher, e *harvest.Engine, res *harvest.Result, u string) {
	ui.Section("harvest :: " + u)
	sp := ui.NewSpinner("fetching page + discovering scripts…")
	sp.Start()
	html, _, ok := f.Get(ctx, u)
	if !ok {
		sp.Stop()
		ui.Error("could not fetch %s", u)
		return
	}
	e.Scan(u, html, res) // covers inline scripts + page markup
	jsURLs, _ := f.DiscoverScripts(u, html)
	sp.Stop()
	ui.Info("found %s external scripts", ui.Bold(strconv.Itoa(len(jsURLs))))

	var fetched, withMaps int64
	var mu sync.Mutex
	jobs := make(chan string, opt.threads*2)
	var wg sync.WaitGroup
	for i := 0; i < opt.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for js := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				body, _, ok := f.Get(ctx, js)
				if !ok {
					continue
				}
				e.Scan(js, body, res)
				mu.Lock()
				fetched++
				mu.Unlock()
				if opt.maps {
					if src := f.SourceMapContent(ctx, js, body); src != "" {
						e.Scan(js+" [sourcemap]", src, res)
						mu.Lock()
						withMaps++
						mu.Unlock()
					}
				}
			}
		}()
	}
	for _, js := range jsURLs {
		jobs <- js
	}
	close(jobs)
	wg.Wait()
	ui.Success("scanned %s scripts (%s with source maps)",
		ui.Bold(strconv.FormatInt(fetched, 10)), ui.Bold(strconv.FormatInt(withMaps, 10)))
}

func scanFolder(root string, e *harvest.Engine, res *harvest.Result) {
	ui.Section("harvest :: folder " + root)
	count := 0
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil || len(data) == 0 {
			return nil
		}
		e.Scan(path, string(data), res)
		count++
		return nil
	})
	ui.Success("scanned %s files", ui.Bold(strconv.Itoa(count)))
}

func scanGitHub(ctx context.Context, opt options, e *harvest.Engine, res *harvest.Result, domains []string) {
	ui.Section("harvest :: github code search")
	gh := harvest.NewGitHubClient(opt.gitToken, opt.timeout)
	for _, d := range domains {
		select {
		case <-ctx.Done():
			return
		default:
		}
		sp := ui.NewSpinner("searching github for " + d + "…")
		sp.Start()
		urls, err := gh.SearchContentURLs(ctx, d)
		sp.Stop()
		if err != nil && len(urls) == 0 {
			ui.Warning("github search (%s): %v", d, err)
			continue
		}
		ui.Info("%s matched files for %s", ui.Bold(strconv.Itoa(len(urls))), ui.Accent(d))

		jobs := make(chan string, opt.threads*2)
		var wg sync.WaitGroup
		for i := 0; i < opt.threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for api := range jobs {
					if content, htmlURL, ok := gh.FetchContent(ctx, api); ok {
						e.Scan(htmlURL, content, res)
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
	ui.Success("github harvest complete")
}

func runSANs(ctx context.Context, opt options, res *harvest.Result) {
	ui.Section("harvest :: subject alternative names (" + opt.san + ")")
	seeds := res.Subdomains()
	if len(seeds) == 0 {
		ui.Warning("no hosts to pull certificates from")
		return
	}
	sp := ui.NewSpinner(fmt.Sprintf("walking TLS certs from %d seed hosts…", len(seeds)))
	sp.Start()
	var found int64
	names := harvest.HarvestSANs(ctx, seeds, harvest.SANMode(opt.san), 5*time.Second, opt.threads, 3000,
		func(host string) { found++ })
	sp.Stop()
	for _, n := range names {
		res.Seed(n)
	}
	ui.Success("SAN walk added %s names", ui.Bold(strconv.FormatInt(found, 10)))
}

// ---- output ----

func render(res *harvest.Result) {
	subs := res.Subdomains()
	cloud := res.CloudURLs()
	secrets := res.Secrets()
	ips := res.IPs()

	ui.Section("results")
	ui.KV("subdomains", ui.Bold(strconv.Itoa(len(subs))))
	ui.KV("cloud assets", ui.Bold(strconv.Itoa(len(cloud))))
	ui.KV("secrets", highlight(len(secrets)))
	ui.KV("ipv4", ui.Bold(strconv.Itoa(len(ips))))
	fmt.Println()

	if len(subs) > 0 {
		ui.Section(fmt.Sprintf("subdomains (%d)", len(subs)))
		for _, s := range subs {
			ui.Result("%s", ui.Primary(s))
		}
	}
	if len(cloud) > 0 {
		ui.Section(fmt.Sprintf("cloud assets (%d)", len(cloud)))
		for _, c := range cloud {
			ui.Result("%s", ui.Accent(c))
		}
	}
	if len(secrets) > 0 {
		ui.Section(fmt.Sprintf("secrets (%d — review for false positives)", len(secrets)))
		for _, s := range secrets {
			line := fmt.Sprintf("%s %s", ui.Bad("["+s.Type+"]"), ui.Warn(s.Match))
			ui.Result("%s", line)
			ui.Muted2("       ↳ %s", s.Source)
		}
	}
	if len(ips) > 0 {
		ui.Section(fmt.Sprintf("ipv4 addresses (%d)", len(ips)))
		for _, ip := range ips {
			ui.Result("%s", ui.Secondary(ip))
		}
	}
	fmt.Println()
}

func writeOutputs(opt options, res *harvest.Result) {
	if opt.outSubs != "" {
		writeLines(opt.outSubs, res.Subdomains())
		ui.Success("subdomains → %s", ui.Secondary(opt.outSubs))
	}
	if opt.outCloud != "" {
		writeLines(opt.outCloud, res.CloudURLs())
		ui.Success("cloud URLs → %s", ui.Secondary(opt.outCloud))
	}
	if opt.outSecrets != "" {
		var lines []string
		for _, s := range res.Secrets() {
			lines = append(lines, s.Match+" | "+s.Type+" | "+s.Source)
		}
		writeLines(opt.outSecrets, lines)
		ui.Success("secrets → %s", ui.Secondary(opt.outSecrets))
	}
	if opt.outGit != "" {
		var lines []string
		for _, s := range res.Secrets() {
			if strings.Contains(s.Source, "github.com") {
				lines = append(lines, s.Match+" | "+s.Type+" | "+s.Source)
			}
		}
		writeLines(opt.outGit, lines)
		ui.Success("github secrets → %s", ui.Secondary(opt.outGit))
	}
}

func emitJSON(res *harvest.Result) {
	out := map[string]any{
		"subdomains": res.Subdomains(),
		"cloud":      res.CloudURLs(),
		"secrets":    res.Secrets(),
		"ipv4":       res.IPs(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// ---- helpers ----

func printBanner() {
	for _, line := range strings.Split(art, "\n") {
		fmt.Println(ui.Gradient(line))
	}
	fmt.Println(ui.Dim(ui.Secondary("  JS subdomain / secret / cloud harvester  ·  v" + version + "  ·  SPECTER suite")))
	fmt.Println(ui.Dim(ui.Secondary("  " + strings.Repeat("─", 60))))
	fmt.Println()
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		ui.Error("opening %s: %v", path, err)
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func writeLines(path string, lines []string) {
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func highlight(n int) string {
	if n == 0 {
		return ui.Muted("0")
	}
	return ui.Bad(ui.Bold(strconv.Itoa(n)))
}
