package inspect

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"specter/internal/ui"
)

const version = "1.0.0"

const art = `
 ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗
 ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝
 ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║
 ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║
 ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║
 ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝`

const usage = `specter inspect — deep per-URL intelligence gatherer

Feeds on VECTOR's high-risk.txt (or any URL list) and extracts everything it
can from each URL: redirect chain, headers, security-header & cookie gaps,
CORS, allowed methods, TLS certificate, tech fingerprint, body intelligence
(secrets, endpoints, emails, internal IPs, stack traces, directory listings,
WAF), reflected parameters, GraphQL introspection and exposed backups.

USAGE:
  specter inspect -i high-risk.txt
  cat high-risk.txt | specter inspect -min high -o loot/

INPUT:
  -i    string   input file (VECTOR high-risk.txt or plain URLs); stdin if omitted

CHECKS (authorized targets only):
  -backups       probe for exposed backup/source variants     (default true)
  -reflect       canary-test query params for reflection       (default true)
  -tls           collect TLS certificate intelligence          (default true)

REQUEST:
  -t    int      concurrent workers          (default 20)
  -timeout dur   per-request timeout          (default 12s)
  -c    string   Cookie header value
  -H    string   extra header "Name: Value" (repeatable)
  -k             skip TLS verification        (default true)

OUTPUT:
  -min  string   minimum severity to show: info|low|medium|high|critical
  -o    string   write report files to this directory
  -json          print full results as JSON
  -nc            disable colors
  -silent        suppress banner
  -h             help

EXAMPLES:
  specter inspect -i loot/target.com/high-risk.txt -o loot/target.com/
  specter inspect -i high-risk.txt -min medium -t 30
  specter inspect -i high-risk.txt -backups=false -reflect=false
`

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

type cliOpts struct {
	in       string
	backups  bool
	reflect  bool
	tlsInfo  bool
	threads  int
	timeout  time.Duration
	cookie   string
	headers  headerList
	insecure bool
	minSev   string
	out      string
	jsonOut  bool
	nc       bool
	silent   bool
}

var lineRX = regexp.MustCompile(`^\s*(?:\[\s*([A-Za-z]+)\s+risk:(\d+)\s*\]\s*)?(https?://\S+)`)

// Run is the `specter inspect` subcommand entry point.
func Run(args []string) {
	opt, showVer := parse(args)
	if showVer {
		fmt.Printf("inspect v%s\n", version)
		return
	}
	ui.Init("cyberpunk", opt.nc)
	if !opt.silent {
		printBanner()
	}

	targets := readTargets(opt.in)
	if len(targets) == 0 {
		ui.Error("no URLs found in input (expects VECTOR high-risk.txt or a URL list)")
		os.Exit(1)
	}
	ui.Info("loaded %s URLs from %s", ui.Bold(strconv.Itoa(len(targets))), src(opt.in))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; ui.Warning("interrupt — flushing results"); cancel() }()

	ins := New(Options{
		Timeout:  opt.timeout,
		Cookie:   opt.cookie,
		Headers:  opt.headers,
		Insecure: opt.insecure,
		Backups:  opt.backups,
		Reflect:  opt.reflect,
		TLS:      opt.tlsInfo,
	})

	ui.Section("deep inspection")
	var done int64
	jobs := make(chan *Target, opt.threads*2)
	var wg sync.WaitGroup
	for i := 0; i < opt.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				ins.Inspect(ctx, t)
				atomic.AddInt64(&done, 1)
				ui.Progress("%s %d/%d inspected", ui.Muted("   progress:"), atomic.LoadInt64(&done), len(targets))
			}
		}()
	}
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	ui.ClearLine()

	// Highest severity first.
	sort.SliceStable(targets, func(i, j int) bool {
		ri, rj := targets[i].MaxRank(), targets[j].MaxRank()
		if ri != rj {
			return ri > rj
		}
		return targets[i].Risk > targets[j].Risk
	})

	if opt.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(targets)
	}
	render(opt, targets)
	if opt.out != "" {
		writeReports(opt.out, targets)
	}
}

func parse(args []string) (cliOpts, bool) {
	var opt cliOpts
	var showVer bool
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	fs.StringVar(&opt.in, "i", "", "")
	fs.BoolVar(&opt.backups, "backups", true, "")
	fs.BoolVar(&opt.reflect, "reflect", true, "")
	fs.BoolVar(&opt.tlsInfo, "tls", true, "")
	fs.IntVar(&opt.threads, "t", 20, "")
	fs.DurationVar(&opt.timeout, "timeout", 12*time.Second, "")
	fs.StringVar(&opt.cookie, "c", "", "")
	fs.Var(&opt.headers, "H", "")
	fs.BoolVar(&opt.insecure, "k", true, "")
	fs.StringVar(&opt.minSev, "min", "info", "")
	fs.StringVar(&opt.out, "o", "", "")
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

func readTargets(in string) []*Target {
	var f *os.File
	if in == "" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(in)
		if err != nil {
			ui.Error("opening %s: %v", in, err)
			return nil
		}
		defer f.Close()
	}
	seen := map[string]bool{}
	var out []*Target
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := lineRX.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		u := m[3]
		if seen[u] {
			continue
		}
		seen[u] = true
		risk, _ := strconv.Atoi(m[2])
		out = append(out, &Target{URL: u, Severity: strings.ToUpper(m[1]), Risk: risk})
	}
	return out
}

// ---- rendering ----

func render(opt cliOpts, targets []*Target) {
	min := sevRank(strings.ToUpper(opt.minSev))
	if opt.minSev == "" || strings.EqualFold(opt.minSev, "info") {
		min = rInfo
	}

	shown := 0
	for _, t := range targets {
		if t.MaxRank() < min {
			continue
		}
		printTarget(t)
		shown++
	}
	summary(targets, shown)
}

func printTarget(t *Target) {
	head := fmt.Sprintf("%s %s %s",
		sevColor(sevName(t.MaxRank()), "["+pad(sevName(t.MaxRank()))+"]"),
		statusColor(t.Status),
		ui.Primary(t.URL))
	ui.Result("%s", head)

	if !t.Reachable {
		ui.Muted2("       unreachable")
		return
	}
	meta := fmt.Sprintf("       %s %s · %dB · %dms", ui.Dim("↳"),
		ui.Secondary(short(t.ContentType)), t.Length, t.LatencyMS)
	if t.Title != "" {
		meta += ui.Secondary(" · " + t.Title)
	}
	if len(t.Tech) > 0 {
		meta += ui.Accent(" · " + strings.Join(t.Tech, ","))
	}
	if t.WAF != "" {
		meta += ui.Warn(" · WAF:" + t.WAF)
	}
	fmt.Println(meta)
	if len(t.RedirectChain) > 0 {
		ui.Muted2("       → %s", strings.Join(t.RedirectChain, " → "))
	}
	if t.AllowMethods != "" {
		ui.Muted2("       methods: %s", t.AllowMethods)
	}
	if t.TLS != nil {
		ui.Muted2("       tls: %s · issuer %s · %s · %dd left", t.TLS.TLSVer, t.TLS.Issuer, t.TLS.NotAfter, t.TLS.DaysLeft)
	}
	for _, f := range t.Findings {
		fmt.Printf("       %s %s%s\n", sevColor(f.Severity, "•"+pad(f.Severity)), ui.Accent(f.Title), detailStr(f.Detail))
	}
}

func summary(targets []*Target, shown int) {
	var crit, high, med, secrets, backups, reachable int
	for _, t := range targets {
		if t.Reachable {
			reachable++
		}
		secrets += len(t.Secrets)
		backups += len(t.Backups)
		for _, f := range t.Findings {
			switch f.Severity {
			case "CRITICAL":
				crit++
			case "HIGH":
				high++
			case "MEDIUM":
				med++
			}
		}
	}
	ui.Section("inspection summary")
	ui.KV("urls", ui.Bold(strconv.Itoa(len(targets))))
	ui.KV("reachable", ui.Good(strconv.Itoa(reachable)))
	ui.KV("critical findings", redFlag(crit))
	ui.KV("high findings", redFlag(high))
	ui.KV("medium findings", ui.Warn(strconv.Itoa(med)))
	ui.KV("secrets", redFlag(secrets))
	ui.KV("exposed variants", redFlag(backups))
	fmt.Println()
}

func writeReports(dir string, targets []*Target) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		ui.Error("output dir: %v", err)
		return
	}
	f, err := os.Create(filepath.Join(dir, "inspect.json"))
	if err == nil {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		_ = enc.Encode(targets)
		f.Close()
	}
	var findings, secrets, exposed []string
	for _, t := range targets {
		for _, fi := range t.Findings {
			findings = append(findings, fmt.Sprintf("[%s] %s — %s  (%s)", fi.Severity, fi.Title, fi.Detail, t.URL))
		}
		for _, s := range t.Secrets {
			secrets = append(secrets, fmt.Sprintf("[%s] %s  (%s)", s.Type, s.Match, t.URL))
		}
		exposed = append(exposed, t.Backups...)
	}
	writeLines(filepath.Join(dir, "inspect-findings.txt"), findings)
	writeLines(filepath.Join(dir, "inspect-secrets.txt"), secrets)
	writeLines(filepath.Join(dir, "inspect-exposed.txt"), exposed)
	ui.Success("report written to %s", ui.Secondary(dir))
}

// ---- small helpers ----

func printBanner() {
	for _, line := range strings.Split(art, "\n") {
		fmt.Println(ui.Gradient(line))
	}
	fmt.Println(ui.Dim(ui.Secondary("  deep per-URL intelligence gatherer  ·  v" + version + "  ·  SPECTER suite")))
	fmt.Println(ui.Dim(ui.Secondary("  " + strings.Repeat("─", 56))))
	fmt.Println()
}

func src(in string) string {
	if in == "" {
		return "stdin"
	}
	return in
}

func writeLines(path string, lines []string) {
	if len(lines) == 0 {
		return
	}
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func detailStr(d string) string {
	if d == "" {
		return ""
	}
	return ui.Muted(" — " + d)
}

func short(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		return ct[:i]
	}
	if ct == "" {
		return "?"
	}
	return ct
}

func pad(s string) string { return fmt.Sprintf("%-8s", s) }

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

func statusColor(code int) string {
	s := strconv.Itoa(code)
	switch {
	case code >= 200 && code < 300:
		return ui.Good(s)
	case code >= 300 && code < 400:
		return ui.Secondary(s)
	case code >= 400 && code < 500:
		return ui.Warn(s)
	case code >= 500:
		return ui.Bad(s)
	default:
		return ui.Muted("---")
	}
}

func redFlag(n int) string {
	if n == 0 {
		return ui.Muted("0")
	}
	return ui.Bad(ui.Bold(strconv.Itoa(n)))
}
