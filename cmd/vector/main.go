// VECTOR — SPECTER's endpoint attack-surface analyzer.
//
// It ingests an endpoints list (e.g. SPECTER's endpoints.txt), classifies every
// endpoint, and flags likely vulnerability classes (SSRF, SQLi, LFI, RCE, IDOR,
// open-redirect, secrets-in-URL, sensitive files, …) ranked by risk. With
// -probe it verifies endpoints live; with -active it injects benign canaries to
// confirm reflection (XSS surface) and open redirects.
package main

import (
	"bufio"
	"context"
	"encoding/json"
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

	"specter/internal/epanalyze"
	"specter/internal/ui"
)

const version = "1.0.0"

const banner = `
 ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗
 ██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
 ██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝
 ╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
  ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
   ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝`

const usage = `VECTOR — endpoint attack-surface analyzer (SPECTER suite)

USAGE:
  vector -i endpoints.txt [options]
  cat endpoints.txt | vector
  vector -i endpoints.txt -probe -active -base https://target.com

INPUT:
  -i      string   endpoints file (one per line); reads stdin if omitted
  -base   string   prefix for relative paths (e.g. https://target.com)

LIVE VERIFICATION (authorized targets only):
  -probe           request each absolute endpoint (status, type, size, title)
  -active          inject benign canaries to confirm reflection + open redirect
  -sqli            active SQL injection probing (error-based + boolean-blind)
  -lfi             active LFI / path-traversal probing (file-content proof)
  -attack          enable ALL active tests (-active -sqli -lfi)
  -t      int      concurrent workers                       (default 40)
  -timeout dur     per-request timeout                       (default 8s)

FILTERING / OUTPUT:
  -min     string  minimum severity to display: info|low|medium|high|critical
  -cat     string  only show endpoints matching this vuln category (substring)
  -top     int     show only the top N highest-risk endpoints  (0 = all)
  -o       string  write categorized report files to this dir
  -json            print full analysis as JSON to stdout
  -nc              disable colors
  -silent          suppress banner
  -v               version
  -h               help

EXAMPLES:
  vector -i endpoints.txt -min high -top 50
  vector -i endpoints.txt -cat SSRF -o vector-out/
  vector -i endpoints.txt -base https://app.target.com -attack -json
  vector -i endpoints.txt -sqli -lfi -o loot/ -t 60
`

type options struct {
	in      string
	base    string
	probe   bool
	active  bool
	sqli    bool
	lfi     bool
	threads int
	timeout time.Duration
	minSev  string
	cat     string
	top     int
	out     string
	json    bool
	nc      bool
	silent  bool
}

func main() {
	opt, showVer := parseFlags()
	if showVer {
		fmt.Printf("vector v%s\n", version)
		return
	}

	ui.Init("cyberpunk", opt.nc)
	if !opt.silent {
		printBanner()
	}

	lines, err := readInput(opt.in)
	if err != nil {
		ui.Error("%v", err)
		os.Exit(1)
	}
	if len(lines) == 0 {
		ui.Error("no endpoints to analyze (provide -i file or pipe via stdin)")
		os.Exit(1)
	}

	ui.Info("loaded %s lines from %s", ui.Bold(strconv.Itoa(len(lines))), source(opt.in))
	sp := ui.NewSpinner("analyzing attack surface…")
	sp.Start()
	res := epanalyze.Analyze(lines, opt.base)
	sp.Stop()
	ui.Success("parsed %s unique endpoints across %s hosts",
		ui.Bold(strconv.Itoa(res.Total)), ui.Bold(strconv.Itoa(len(res.Hosts))))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; ui.Warning("interrupt — finishing up"); cancel() }()

	if opt.probe || opt.active {
		runProbe(ctx, opt, res)
	}

	if opt.json {
		printJSON(res)
		if opt.out != "" {
			writeReport(opt.out, res)
		}
		return
	}

	render(opt, res)
	if opt.out != "" {
		writeReport(opt.out, res)
	}
}

func parseFlags() (options, bool) {
	var opt options
	var showVer bool
	fs := flag.NewFlagSet("vector", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	fs.StringVar(&opt.in, "i", "", "")
	fs.StringVar(&opt.base, "base", "", "")
	var attack bool
	fs.BoolVar(&opt.probe, "probe", false, "")
	fs.BoolVar(&opt.active, "active", false, "")
	fs.BoolVar(&opt.sqli, "sqli", false, "")
	fs.BoolVar(&opt.lfi, "lfi", false, "")
	fs.BoolVar(&attack, "attack", false, "")
	fs.IntVar(&opt.threads, "t", 40, "")
	fs.DurationVar(&opt.timeout, "timeout", 8*time.Second, "")
	fs.StringVar(&opt.minSev, "min", "info", "")
	fs.StringVar(&opt.cat, "cat", "", "")
	fs.IntVar(&opt.top, "top", 0, "")
	fs.StringVar(&opt.out, "o", "", "")
	fs.BoolVar(&opt.json, "json", false, "")
	fs.BoolVar(&opt.nc, "nc", false, "")
	fs.BoolVar(&opt.silent, "silent", false, "")
	fs.BoolVar(&showVer, "v", false, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if attack {
		opt.active, opt.sqli, opt.lfi = true, true, true
	}
	if opt.active || opt.sqli || opt.lfi {
		opt.probe = true // any active test implies live requests
	}
	if opt.threads < 1 {
		opt.threads = 1
	}
	return opt, showVer
}

func printBanner() {
	for _, line := range strings.Split(banner, "\n") {
		fmt.Println(ui.Gradient(line))
	}
	fmt.Println(ui.Dim(ui.Secondary("  endpoint attack-surface analyzer  ·  v" + version + "  ·  SPECTER suite")))
	fmt.Println(ui.Dim(ui.Secondary("  " + strings.Repeat("─", 56))))
	fmt.Println()
}

func source(in string) string {
	if in == "" {
		return "stdin"
	}
	return in
}

func readInput(in string) ([]string, error) {
	var f *os.File
	if in == "" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(in)
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", in, err)
		}
		defer f.Close()
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func runProbe(ctx context.Context, opt options, res *epanalyze.Result) {
	pr := epanalyze.NewProber(epanalyze.ProbeOptions{
		Timeout:   opt.timeout,
		UserAgent: "Mozilla/5.0 (Linux; Android 11; VECTOR)",
		Active:    opt.active,
		SQLi:      opt.sqli,
		LFI:       opt.lfi,
	})

	var targets []*epanalyze.Endpoint
	for _, e := range res.Endpoints {
		if epanalyze.Probeable(e) {
			targets = append(targets, e)
		}
	}
	if len(targets) == 0 {
		ui.Warning("no absolute URLs to probe (use -base to make relative paths absolute)")
		return
	}
	var modes []string
	if opt.active {
		modes = append(modes, "reflection+redirect")
	}
	if opt.sqli {
		modes = append(modes, "SQLi")
	}
	if opt.lfi {
		modes = append(modes, "LFI")
	}
	mode := "passive GET"
	if len(modes) > 0 {
		mode = "active :: " + strings.Join(modes, " + ")
	}
	ui.Section("live verification :: " + mode)
	if pr.Injects() {
		ui.Warning("active injection enabled — only run against targets you are authorized to test")
	}
	ui.Info("probing %s endpoints with %d workers", ui.Bold(strconv.Itoa(len(targets))), opt.threads)

	var done, live, confirmed int64
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
					atomic.AddInt64(&live, 1)
					if len(e.Confirmed) > 0 {
						atomic.AddInt64(&confirmed, int64(len(e.Confirmed)))
					}
					reportProbe(e, r)
				}
				n := atomic.AddInt64(&done, 1)
				if n%50 == 0 {
					ui.Progress("%s %d/%d probed", ui.Muted("   progress:"), n, len(targets))
				}
			}
		}()
	}
	for _, e := range targets {
		jobs <- e
	}
	close(jobs)
	wg.Wait()
	ui.ClearLine()

	// Confirmed vulns escalate risk/severity — re-rank so they sit on top.
	res.Sort()

	if confirmed > 0 {
		ui.Error("%s VULNERABILITIES CONFIRMED via live injection", ui.Bold(strconv.FormatInt(confirmed, 10)))
	}
	ui.Success("%s live endpoints verified", ui.Bold(strconv.FormatInt(live, 10)))
}

func reportProbe(e *epanalyze.Endpoint, r *epanalyze.ProbeResult) {
	for _, c := range e.Confirmed {
		ui.Result("%s %s  %s",
			ui.Bad(ui.Bold("[VULNERABLE]")), ui.Bad(c.Category),
			ui.Dim("risk:"+strconv.Itoa(e.Risk)))
		ui.Result("   %s %s", ui.Muted("url    :"), ui.Primary(c.URL))
		ui.Result("   %s %s", ui.Muted("payload:"), ui.Warn(c.Payload))
		if c.Detail != "" {
			ui.Result("   %s %s", ui.Muted("detail :"), ui.Accent(c.Detail))
		}
		ui.Result("   %s %s", ui.Muted("proof  :"), ui.Accent(c.Evidence))
	}
	if r.OpenRedirect {
		ui.Result("%s %s %s",
			ui.Bad("[OPEN-REDIRECT]"), ui.Primary(e.URL),
			ui.Warn("param="+r.OpenRedirectParam))
	}
	if len(r.Reflected) > 0 {
		ui.Result("%s %s %s",
			ui.Bad("[REFLECTED]"), ui.Primary(e.URL),
			ui.Warn("params="+strings.Join(r.Reflected, ",")))
	}
}

func render(opt options, res *epanalyze.Result) {
	overview(res)

	minSev := parseSev(opt.minSev)
	var shown []*epanalyze.Endpoint
	for _, e := range res.Endpoints {
		if sevValue(e.MaxSev) < minSev {
			continue
		}
		if opt.cat != "" && !matchesCat(e, opt.cat) {
			continue
		}
		shown = append(shown, e)
	}
	if opt.top > 0 && len(shown) > opt.top {
		shown = shown[:opt.top]
	}

	ui.Section(fmt.Sprintf("prioritized endpoints :: %d shown", len(shown)))
	if len(shown) == 0 {
		ui.Muted2("   nothing matched the current filters")
	}
	for _, e := range shown {
		printEndpoint(e)
	}

	categoryBreakdown(res)
}

func overview(res *epanalyze.Result) {
	ui.Section("attack-surface overview")
	ui.KV("endpoints", ui.Bold(strconv.Itoa(res.Total)))
	ui.KV("hosts", ui.Bold(strconv.Itoa(len(res.Hosts))))
	ui.KV("unique params", ui.Bold(strconv.Itoa(len(res.ParamFreq))))

	ui.KV("categories", histogram(res.CategoryCnt, 6))
	if len(res.ExtFreq) > 0 {
		ui.KV("extensions", histogram(res.ExtFreq, 8))
	}

	// Risk tally by max severity.
	bySev := map[string]int{}
	confirmed := 0
	for _, e := range res.Endpoints {
		if len(e.Vulns) > 0 || len(e.Confirmed) > 0 {
			bySev[e.MaxSev]++
		}
		confirmed += len(e.Confirmed)
	}
	ui.KV("by severity", fmt.Sprintf("%s %s %s %s",
		ui.Bad("crit:"+strconv.Itoa(bySev["CRITICAL"])),
		ui.Warn("high:"+strconv.Itoa(bySev["HIGH"])),
		ui.Accent("med:"+strconv.Itoa(bySev["MEDIUM"])),
		ui.Muted("low:"+strconv.Itoa(bySev["LOW"]))))
	if confirmed > 0 {
		ui.KV("CONFIRMED", ui.Bad(ui.Bold(strconv.Itoa(confirmed)+" actively verified")))
	}
	fmt.Println()

	if len(res.ParamFreq) > 0 {
		ui.Info("top parameters: %s", topParams(res.ParamFreq, 12))
	}
}

func categoryBreakdown(res *epanalyze.Result) {
	if len(res.VulnCounts) == 0 {
		return
	}
	ui.Section("findings by category")
	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range res.VulnCounts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].v != sorted[j].v {
			return sorted[i].v > sorted[j].v
		}
		return sorted[i].k < sorted[j].k
	})
	for _, e := range sorted {
		ui.KV(e.k, ui.Bold(strconv.Itoa(e.v)))
	}
	fmt.Println()
}

func printEndpoint(e *epanalyze.Endpoint) {
	risk := fmt.Sprintf("%3d", e.Risk)
	head := fmt.Sprintf("%s %s %s",
		sevColor(e.MaxSev, "["+sevPad(e.MaxSev)+"]"),
		ui.Dim("risk:"+risk),
		ui.Primary(e.URL))
	ui.Result("%s", head)

	for _, c := range e.Confirmed {
		ui.Result("       %s %s", ui.Bad(ui.Bold("✓ CONFIRMED")), ui.Bad(c.Category))
		fmt.Println("          " + ui.Muted("payload: ") + ui.Warn(c.Payload))
		if c.Detail != "" {
			fmt.Println("          " + ui.Muted("detail : ") + ui.Accent(c.Detail))
		}
		fmt.Println("          " + ui.Muted("proof  : ") + ui.Accent(c.Evidence))
	}
	for _, v := range e.Vulns {
		line := fmt.Sprintf("       %s %s", sevColor(v.Severity, "•"+v.Severity), ui.Accent(v.Category))
		if len(v.Params) > 0 {
			line += ui.Muted(" [" + strings.Join(v.Params, ", ") + "]")
		}
		fmt.Println(line)
	}
	if e.Probe != nil {
		pr := e.Probe
		info := fmt.Sprintf("       %s %s %dB", ui.Dim("↳ probe:"),
			sevColor(statusSev(pr.Status), strconv.Itoa(pr.Status)), pr.Length)
		if pr.Title != "" {
			info += ui.Secondary(" [" + pr.Title + "]")
		}
		if pr.OpenRedirect {
			info += " " + ui.Bad("OPEN-REDIRECT("+pr.OpenRedirectParam+")")
		}
		if len(pr.Reflected) > 0 {
			info += " " + ui.Bad("REFLECTED("+strings.Join(pr.Reflected, ",")+")")
		}
		fmt.Println(info)
	}
}

// ---- output files ----

func writeReport(dir string, res *epanalyze.Result) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		ui.Error("output dir: %v", err)
		return
	}
	write := func(name string, lines []string) {
		if len(lines) == 0 {
			return
		}
		_ = os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	}

	byCat := map[string][]string{}
	var all, highRisk, sensitive, withParams, confirmedLines []string
	for _, e := range res.Endpoints {
		all = append(all, e.URL)
		if sevValue(e.MaxSev) >= sevValue("HIGH") {
			highRisk = append(highRisk, fmt.Sprintf("[%s risk:%d] %s", e.MaxSev, e.Risk, e.URL))
		}
		if len(e.Params) > 0 {
			withParams = append(withParams, e.URL)
		}
		for _, c := range e.Confirmed {
			confirmedLines = append(confirmedLines,
				fmt.Sprintf("[%s] risk:%d\n  url    : %s\n  payload: %s\n  detail : %s\n  proof  : %s\n",
					c.Category, e.Risk, c.URL, c.Payload, c.Detail, c.Evidence))
		}
		for _, v := range e.Vulns {
			byCat[v.Category] = append(byCat[v.Category], e.URL)
			if v.Category == "Sensitive File/Path" {
				sensitive = append(sensitive, e.URL)
			}
		}
	}
	write("all-endpoints.txt", all)
	write("CONFIRMED-VULNS.txt", confirmedLines)
	write("high-risk.txt", highRisk)
	write("sensitive.txt", uniq(sensitive))
	write("parameterized.txt", withParams)
	write("hosts.txt", res.Hosts)
	write("params.txt", sortedParams(res.ParamFreq))

	catDir := filepath.Join(dir, "by-category")
	_ = os.MkdirAll(catDir, 0o755)
	for cat, urls := range byCat {
		fname := strings.NewReplacer(" ", "_", "/", "-").Replace(strings.ToLower(cat)) + ".txt"
		_ = os.WriteFile(filepath.Join(catDir, fname), []byte(strings.Join(uniq(urls), "\n")+"\n"), 0o644)
	}
	ui.Success("report written to %s", ui.Secondary(dir))
}

// ---- helpers ----

func printJSON(res *epanalyze.Result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		ui.Error("json: %v", err)
	}
}

func histogram(m map[string]int, max int) string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].v != s[j].v {
			return s[i].v > s[j].v
		}
		return s[i].k < s[j].k
	})
	var parts []string
	for i, e := range s {
		if i >= max {
			break
		}
		parts = append(parts, fmt.Sprintf("%s:%d", e.k, e.v))
	}
	return strings.Join(parts, "  ")
}

func topParams(m map[string]int, n int) string {
	return ui.Accent(strings.ReplaceAll(histogram(m, n), "  ", "  "))
}

func sortedParams(m map[string]int) []string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].v != s[j].v {
			return s[i].v > s[j].v
		}
		return s[i].k < s[j].k
	})
	var out []string
	for _, e := range s {
		out = append(out, fmt.Sprintf("%-30s %d", e.k, e.v))
	}
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func matchesCat(e *epanalyze.Endpoint, cat string) bool {
	cat = strings.ToLower(cat)
	for _, v := range e.Vulns {
		if strings.Contains(strings.ToLower(v.Category), cat) {
			return true
		}
	}
	return false
}

func parseSev(s string) int {
	switch strings.ToLower(s) {
	case "critical", "crit":
		return 4
	case "high":
		return 3
	case "medium", "med":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func sevValue(s string) int {
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

func sevColor(sev, s string) string {
	switch sev {
	case "CRITICAL":
		return ui.Bad(ui.Bold(s))
	case "HIGH":
		return ui.Bad(s)
	case "MEDIUM":
		return ui.Warn(s)
	case "LOW":
		return ui.Accent(s)
	default:
		return ui.Muted(s)
	}
}

func sevPad(s string) string {
	if s == "" {
		return "INFO    "
	}
	return fmt.Sprintf("%-8s", s)
}

func statusSev(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "MEDIUM"
	case code >= 300 && code < 400:
		return "LOW"
	case code >= 500:
		return "HIGH"
	default:
		return "INFO"
	}
}
