// Package menu is SPECTER's mobile-friendly interactive launcher. Instead of
// typing flags, you pick options by tapping a number + Enter — ideal for a
// Termux soft keyboard. It assembles the equivalent command-line args and
// dispatches to the relevant subcommand.
package menu

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"specter/internal/auto"
	"specter/internal/inspect"
	"specter/internal/phantom"
	"specter/internal/recon"
	"specter/internal/ui"
	"specter/internal/vector"
)

var in = bufio.NewReader(os.Stdin)

// skull is the menu's banner — a death's-head, no spelled-out title.
const skull = `
            ▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄█████████████████▄
       ▄█████████████████████▄
      ███████████████████████████
     █████████████████████████████
     ████╬╬╬╬╬████████████╬╬╬╬╬████
     ███╬       ╬████████╬       ╬███
     ███   ▄█▄   ████████   ▄█▄   ███
     ███   ███   ████████   ███   ███
     ███╬  ▀█▀  ╬████████╬  ▀█▀  ╬███
      ████╬╬╬╬█████  ██  █████╬╬╬████
      ███████████ ▄▄ ██ ▄▄ ███████████
       █████████  ██ ██ ██  █████████
        ████████ █▌█▌██▐█▐█ ████████
         ▀██████ █ █ ██ █ █ ██████▀
           ▀████ ▀▀ ▀▀ ▀▀ ▀ ████▀
             ▀▀████████████████▀▀
                ▀▀▀████████▀▀▀`

// printSkull renders the banner with a vertical neon-green → blood-red gradient.
func printSkull() {
	lines := strings.Split(skull, "\n")
	n := len(lines)
	for i, l := range lines {
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		r := lerp(0, 255, t)
		g := lerp(255, 0, t)
		b := lerp(120, 70, t)
		fmt.Println(ui.Color(fmt.Sprintf("%d;%d;%d", r, g, b), l))
	}
	fmt.Println(ui.Bold(ui.Color("255;0;90", "        ☠  S P E C T E R  ☠   ")) +
		ui.Dim(ui.Color("0;220;255", "all-in-one recon suite")))
	fmt.Println(ui.Dim(ui.Secondary("        " + strings.Repeat("━", 40))))
	fmt.Println()
}

func lerp(a, b int, t float64) int { return a + int(float64(b-a)*t) }

// Run starts the interactive menu loop.
func Run() {
	ui.Init("cyberpunk", false)
	for {
		ui.ClearScreen()
		printSkull()
		ui.Section("main menu")
		fmt.Println(opt("1", "Auto", "full automated pipeline — recon → harvest → analyze (recommended)"))
		fmt.Println(opt("2", "Recon", "subdomains, resolve, probe, urls, js, content"))
		fmt.Println(opt("3", "Harvest", "JS / secret / cloud / SAN / GitHub harvesting"))
		fmt.Println(opt("4", "Analyze", "endpoint attack-surface + active SQLi/LFI/XSS"))
		fmt.Println(opt("5", "Inspect", "deep intel on any URL/host list"))
		fmt.Println(opt("?", "About", "what each tool does, in detail"))
		fmt.Println(opt("0", "Quit", ""))
		switch ask("choose") {
		case "1":
			autoMenu()
		case "2":
			reconMenu()
		case "3":
			harvestMenu()
		case "4":
			analyzeMenu()
		case "5":
			inspectMenu()
		case "?", "about", "help", "h":
			aboutScreen()
		case "0", "q", "quit", "exit":
			fmt.Println(ui.Muted("  stay dangerous. ☠"))
			return
		default:
			// loop
		}
	}
}

// aboutScreen explains every tool before you run it.
func aboutScreen() {
	ui.ClearScreen()
	printSkull()
	ui.Section("what each tool does")
	for _, d := range descriptions {
		fmt.Printf("   %s %s\n", ui.Accent(ui.Bold(d.name)), ui.Muted("— "+d.tag))
		for _, l := range d.body {
			fmt.Println("       " + ui.Secondary(l))
		}
		fmt.Println()
	}
	fmt.Print(ui.Muted("  press Enter to go back…"))
	_, _ = in.ReadString('\n')
}

type toolDesc struct {
	name string
	tag  string
	body []string
}

var descriptions = []toolDesc{
	{"AUTO", "the whole pipeline in one tap", []string{
		"Runs everything in order and feeds each stage into the next:",
		"recon → SAN cert expansion → JS/secret/cloud harvest →",
		"re-probe new hosts → endpoint analysis (+ optional live vuln probing).",
		"Best starting point. Output is one merged loot folder per target."}},
	{"RECON", "map the attack surface", []string{
		"Finds subdomains (passive OSINT + DNS bruteforce), resolves them,",
		"probes live HTTP services (title/status/tech/CORS/security headers/",
		"takeover), mines wayback URLs, extracts endpoints+secrets from JS,",
		"and optionally brute-forces content (dirs/files)."}},
	{"HARVEST", "dig secrets out of JavaScript & certs", []string{
		"SubDomainizer, reborn: pulls subdomains, API keys/tokens, cloud",
		"bucket URLs and IPs from a page's inline + external JS and source",
		"maps. Also walks TLS cert SANs and (with a token) GitHub code search."}},
	{"ANALYZE", "score & probe the endpoint surface", []string{
		"Reads an endpoints list and flags likely vuln classes (SSRF, SQLi,",
		"LFI, RCE, IDOR, XSS, open-redirect, secrets-in-URL, sensitive files)",
		"ranked by risk. With active mode it confirms reflection, open",
		"redirects, and error/boolean SQL injection + LFI with proof."}},
	{"INSPECT", "deep-dive every URL in a list", []string{
		"Point it at ANY list (high-risk.txt, live.txt, subdomains, plain URLs).",
		"Per URL: redirect chain, headers, cookie/security gaps, CORS, allowed",
		"methods, TLS cert, tech, WAF, body leaks (secrets/emails/internal IPs/",
		"stack traces/dir listing), reflected params, GraphQL introspection,",
		"and exposed .bak/~/.old backups (with soft-404 calibration)."}},
}

// ---- AUTO ----

func autoMenu() {
	target := askText("target domain (e.g. example.com)")
	if target == "" {
		return
	}
	deep, attack, git := false, false, false
	gitToken := ""
	san := "same"
	threads := "50"
	out := "specter-loot"

	for {
		ui.ClearScreen()
		ui.Section("auto pipeline :: " + target)
		ui.Muted2("   recon → harvest → analyze, fully automated")
		fmt.Println(toggle("1", "Deep scan (+content discovery)", deep))
		fmt.Println(toggle("2", "Active vuln probing (SQLi/LFI/XSS)", attack))
		fmt.Println(cycleRow("3", "SAN cert harvest", san))
		fmt.Println(toggle("4", "GitHub harvest", git))
		fmt.Println(valueRow("5", "Threads", threads))
		fmt.Println(valueRow("6", "Output dir", out))
		fmt.Println(action("s", "START"))
		fmt.Println(action("b", "back"))
		switch ask("toggle / start") {
		case "1":
			deep = !deep
		case "2":
			attack = !attack
		case "3":
			san = cycle(san, "same", "all", "off")
		case "4":
			git = !git
			if git {
				gitToken = askText("GitHub token")
				if gitToken == "" {
					git = false
				}
			}
		case "5":
			threads = askText("threads")
		case "6":
			out = askText("output dir")
		case "s", "start":
			args := []string{"-d", target, "-t", threads, "-o", out}
			if deep {
				args = append(args, "-deep")
			}
			if attack {
				args = append(args, "-attack")
			}
			args = append(args, "-san", san)
			if git {
				args = append(args, "-git", "-gt", gitToken)
			}
			launch(func() { auto.Run(args) })
			return
		case "b", "back":
			return
		}
	}
}

// ---- RECON ----

func reconMenu() {
	target := askText("target domain")
	if target == "" {
		return
	}
	full := true
	threads := "50"
	out := "specter-out"
	jsonOut := false

	for {
		ui.ClearScreen()
		ui.Section("recon :: " + target)
		ui.Muted2("   subdomains · resolve · probe · urls · js · content")
		fmt.Println(toggle("1", "Full sweep (-all: brute+urls+js+content)", full))
		fmt.Println(valueRow("2", "Threads", threads))
		fmt.Println(valueRow("3", "Output dir", out))
		fmt.Println(toggle("4", "Write JSON", jsonOut))
		fmt.Println(action("s", "START"))
		fmt.Println(action("b", "back"))
		switch ask("toggle / start") {
		case "1":
			full = !full
		case "2":
			threads = askText("threads")
		case "3":
			out = askText("output dir")
		case "4":
			jsonOut = !jsonOut
		case "s", "start":
			args := []string{"-d", target, "-t", threads, "-o", out}
			if full {
				args = append(args, "-all")
			}
			if jsonOut {
				args = append(args, "-json")
			}
			launch(func() { recon.Run(args) })
			return
		case "b", "back":
			return
		}
	}
}

// ---- HARVEST ----

func harvestMenu() {
	target := askText("URL or domain (e.g. https://example.com)")
	if target == "" {
		return
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	san := "same"
	maps := true
	git := false
	gitToken := ""
	out := "specter-harvest"

	for {
		ui.ClearScreen()
		ui.Section("harvest :: " + target)
		ui.Muted2("   mine JS + source maps + certs for subs/secrets/cloud")
		fmt.Println(cycleRow("1", "SAN cert harvest", san))
		fmt.Println(toggle("2", "Source-map mining", maps))
		fmt.Println(toggle("3", "GitHub harvest", git))
		fmt.Println(valueRow("4", "Output dir", out))
		fmt.Println(action("s", "START"))
		fmt.Println(action("b", "back"))
		switch ask("toggle / start") {
		case "1":
			san = cycle(san, "same", "all", "off")
		case "2":
			maps = !maps
		case "3":
			git = !git
			if git {
				gitToken = askText("GitHub token")
				if gitToken == "" {
					git = false
				}
			}
		case "4":
			out = askText("output dir")
		case "s", "start":
			_ = os.MkdirAll(out, 0o755)
			args := []string{"-u", target,
				"-o", out + "/subdomains.txt",
				"-sop", out + "/secrets.txt",
				"-cop", out + "/cloud.txt"}
			if san == "same" || san == "all" {
				args = append(args, "-san", san)
			}
			if !maps {
				args = append(args, "-maps=false")
			}
			if git {
				args = append(args, "-g", "-gt", gitToken)
			}
			launch(func() { phantom.Run(args) })
			return
		case "b", "back":
			return
		}
	}
}

// ---- ANALYZE ----

func analyzeMenu() {
	file := askText("endpoints file (e.g. specter-out/target/endpoints.txt)")
	if file == "" {
		return
	}
	min := "info"
	attack := false
	top := "0"
	out := ""

	for {
		ui.ClearScreen()
		ui.Section("analyze :: " + file)
		ui.Muted2("   score endpoints by vuln class; active mode confirms bugs")
		fmt.Println(cycleRow("1", "Min severity", min))
		fmt.Println(toggle("2", "Active vuln probing (SQLi/LFI/XSS)", attack))
		fmt.Println(valueRow("3", "Top N (0=all)", top))
		fmt.Println(valueRow("4", "Output dir (blank=none)", out))
		fmt.Println(action("s", "START"))
		fmt.Println(action("b", "back"))
		switch ask("toggle / start") {
		case "1":
			min = cycle(min, "info", "low", "medium", "high", "critical")
		case "2":
			attack = !attack
		case "3":
			top = askText("top N")
		case "4":
			out = askText("output dir")
		case "s", "start":
			args := []string{"-i", file, "-min", min, "-top", top}
			if attack {
				args = append(args, "-attack")
			}
			if out != "" {
				args = append(args, "-o", out)
			}
			launch(func() { vector.Run(args) })
			return
		case "b", "back":
			return
		}
	}
}

// ---- INSPECT ----

func inspectMenu() {
	file := askText("URL/host list file (high-risk.txt, live.txt, subs, any list)")
	if file == "" {
		return
	}
	min := "info"
	backups := true
	reflect := true
	out := ""

	for {
		ui.ClearScreen()
		ui.Section("inspect :: " + file)
		ui.Muted2("   deep per-URL intel: headers, TLS, leaks, backups…")
		fmt.Println(cycleRow("1", "Min severity", min))
		fmt.Println(toggle("2", "Backup/variant probing", backups))
		fmt.Println(toggle("3", "Reflected-param testing", reflect))
		fmt.Println(valueRow("4", "Output dir (blank=none)", out))
		fmt.Println(action("s", "START"))
		fmt.Println(action("b", "back"))
		switch ask("toggle / start") {
		case "1":
			min = cycle(min, "info", "low", "medium", "high", "critical")
		case "2":
			backups = !backups
		case "3":
			reflect = !reflect
		case "4":
			out = askText("output dir")
		case "s", "start":
			args := []string{"-i", file, "-min", min}
			if !backups {
				args = append(args, "-backups=false")
			}
			if !reflect {
				args = append(args, "-reflect=false")
			}
			if out != "" {
				args = append(args, "-o", out)
			}
			launch(func() { inspect.Run(args) })
			return
		case "b", "back":
			return
		}
	}
}

// ---- shared helpers ----

func launch(run func()) {
	ui.ClearScreen()
	run()
	fmt.Println()
	fmt.Print(ui.Muted("  press Enter to return to the menu…"))
	_, _ = in.ReadString('\n')
}

func ask(prompt string) string {
	fmt.Printf("\n%s %s ", ui.Primary("»"), ui.Bold(prompt))
	line, _ := in.ReadString('\n')
	return strings.ToLower(strings.TrimSpace(line))
}

func askText(prompt string) string {
	fmt.Printf("\n%s %s ", ui.Primary("»"), ui.Bold(prompt+":"))
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}

func opt(key, name, desc string) string {
	row := "   " + ui.Accent("["+key+"]") + " " + ui.Bold(name)
	if desc != "" {
		row += ui.Muted("  — " + desc)
	}
	return row
}

func toggle(key, name string, on bool) string {
	state := ui.Muted("off")
	if on {
		state = ui.Good("on")
	}
	return fmt.Sprintf("   %s %-40s %s", ui.Accent("["+key+"]"), name, state)
}

func cycleRow(key, name, val string) string {
	return fmt.Sprintf("   %s %-40s %s", ui.Accent("["+key+"]"), name, ui.Warn(val))
}

func valueRow(key, name, val string) string {
	return fmt.Sprintf("   %s %-40s %s", ui.Accent("["+key+"]"), name, ui.Secondary(val))
}

func action(key, name string) string {
	c := ui.Good
	if key == "b" {
		c = ui.Muted
	}
	return "   " + c("["+key+"]") + " " + c(ui.Bold(name))
}

func cycle(cur string, vals ...string) string {
	for i, v := range vals {
		if v == cur {
			return vals[(i+1)%len(vals)]
		}
	}
	return vals[0]
}
