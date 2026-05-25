// Package config defines every runtime option SPECTER exposes and parses the CLI.
package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"specter/internal/banner"
)

// Config is the fully-resolved set of options for a run.
type Config struct {
	// Targets
	Domain  string
	ListIn  string
	Targets []string

	// Output
	OutDir string
	JSON   bool
	Silent bool
	Theme  string
	NoColr bool

	// Concurrency / timing
	Threads int
	Timeout time.Duration
	Rate    int
	Retries int

	// Networking
	UserAgent string
	Headers   []string
	Resolvers []string

	// Module toggles
	Passive   bool
	BruteSubs bool
	Probe     bool
	Tech      bool
	Content   bool
	URLs      bool
	JS        bool
	All       bool

	// Wordlists
	SubWordlist     string
	ContentWordlist string

	// Behaviour
	FollowRedirect bool
	MatchCodes     []int
}

const usageText = `SPECTER — advanced bug bounty recon framework (Termux/arm64 ready)

USAGE:
  specter -d example.com [modules] [options]
  specter -l domains.txt -all -o loot/

TARGET:
  -d   string   target apex domain (e.g. example.com)
  -l   string   file with one domain per line

MODULES (enable individually, or use -all):
  -all          run the full pipeline (passive+brute+probe+tech+urls+js)
  -passive      passive subdomain enumeration (crt.sh, OTX, hackertarget, ...)
  -brute        active DNS subdomain bruteforce
  -probe        HTTP/HTTPS probing (title, status, sec-headers, CORS, takeover)
  -tech         technology / stack fingerprinting
  -urls         historical URL mining (Wayback CDX, OTX) + param extraction
  -content      content / directory discovery on live hosts
  -js           deep JavaScript recon: endpoints, secrets, keys, paths

TUNING:
  -t    int      concurrent workers                 (default 50)
  -timeout dur   per-request timeout                 (default 8s)
  -rate int      max requests/sec (0 = unlimited)    (default 0)
  -retries int   network retry attempts              (default 1)
  -ws  string    subdomain bruteforce wordlist file (uses built-in if empty)
  -cw  string    content discovery wordlist file    (uses built-in if empty)
  -r   string    comma-separated DNS resolvers       (default 1.1.1.1,8.8.8.8)
  -ua  string    custom User-Agent
  -H   string    extra header "Name: Value" (repeatable)
  -mc  string    match these HTTP status codes (e.g. 200,301,403)
  -fr            follow HTTP redirects

OUTPUT / LOOK:
  -o     string  output directory                    (default specter-out)
  -json          also write machine-readable JSON
  -nc            disable colors
  -silent        suppress banner & decorative output
  -v             print version and exit
  -h             show this help

EXAMPLES:
  specter -d target.com -all -o loot/
  specter -d target.com -passive -probe -js -json
  specter -l scope.txt -brute -ws subs.txt -t 100 -timeout 5s
`

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// Parse reads the provided args and returns a validated Config.
func Parse(args []string) (*Config, error) {
	c := &Config{}
	var headers headerList
	var resolvers, matchCodes string
	var showVersion bool

	fs := flag.NewFlagSet("specter", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }

	fs.StringVar(&c.Domain, "d", "", "")
	fs.StringVar(&c.ListIn, "l", "", "")

	fs.BoolVar(&c.All, "all", false, "")
	fs.BoolVar(&c.Passive, "passive", false, "")
	fs.BoolVar(&c.BruteSubs, "brute", false, "")
	fs.BoolVar(&c.Probe, "probe", false, "")
	fs.BoolVar(&c.Tech, "tech", false, "")
	fs.BoolVar(&c.URLs, "urls", false, "")
	fs.BoolVar(&c.Content, "content", false, "")
	fs.BoolVar(&c.JS, "js", false, "")

	fs.IntVar(&c.Threads, "t", 50, "")
	fs.DurationVar(&c.Timeout, "timeout", 8*time.Second, "")
	fs.IntVar(&c.Rate, "rate", 0, "")
	fs.IntVar(&c.Retries, "retries", 1, "")
	fs.StringVar(&c.SubWordlist, "ws", "", "")
	fs.StringVar(&c.ContentWordlist, "cw", "", "")
	fs.StringVar(&resolvers, "r", "1.1.1.1,8.8.8.8,9.9.9.9", "")
	fs.StringVar(&c.UserAgent, "ua", "", "")
	fs.Var(&headers, "H", "")
	fs.StringVar(&matchCodes, "mc", "", "")
	fs.BoolVar(&c.FollowRedirect, "fr", false, "")

	fs.StringVar(&c.OutDir, "o", "specter-out", "")
	fs.BoolVar(&c.JSON, "json", false, "")
	fs.BoolVar(&c.NoColr, "nc", false, "")
	fs.BoolVar(&c.Silent, "silent", false, "")
	fs.BoolVar(&showVersion, "v", false, "")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if showVersion {
		fmt.Printf("specter v%s\n", banner.Version)
		os.Exit(0)
	}

	c.Headers = headers
	c.Theme = "cyberpunk"
	if c.UserAgent == "" {
		c.UserAgent = "Mozilla/5.0 (Linux; Android 11; SPECTER) recon/" + banner.Version
	}
	for _, r := range strings.Split(resolvers, ",") {
		if r = strings.TrimSpace(r); r != "" {
			if !strings.Contains(r, ":") {
				r += ":53"
			}
			c.Resolvers = append(c.Resolvers, r)
		}
	}
	for _, code := range strings.Split(matchCodes, ",") {
		if code = strings.TrimSpace(code); code != "" {
			if n, err := strconv.Atoi(code); err == nil {
				c.MatchCodes = append(c.MatchCodes, n)
			}
		}
	}

	if c.All {
		c.Passive, c.BruteSubs, c.Probe, c.Tech, c.URLs, c.JS =
			true, true, true, true, true, true
	}
	// If no module selected at all, default to a sensible passive+probe+tech sweep.
	if !c.anyModule() {
		c.Passive, c.Probe, c.Tech = true, true, true
	}

	if err := c.loadTargets(); err != nil {
		return nil, err
	}
	if len(c.Targets) == 0 {
		fs.Usage()
		return nil, fmt.Errorf("no target supplied: use -d or -l")
	}
	if c.Threads < 1 {
		c.Threads = 1
	}
	return c, nil
}

func (c *Config) anyModule() bool {
	return c.Passive || c.BruteSubs || c.Probe || c.Tech || c.URLs || c.Content || c.JS
}

func (c *Config) loadTargets() error {
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(strings.ToLower(s))
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimSuffix(s, "/")
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		c.Targets = append(c.Targets, s)
	}
	if c.Domain != "" {
		add(c.Domain)
	}
	if c.ListIn != "" {
		data, err := os.ReadFile(c.ListIn)
		if err != nil {
			return fmt.Errorf("reading -l file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				add(line)
			}
		}
	}
	return nil
}
