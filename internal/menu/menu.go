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
	"specter/internal/banner"
	"specter/internal/inspect"
	"specter/internal/phantom"
	"specter/internal/recon"
	"specter/internal/ui"
	"specter/internal/vector"
)

var in = bufio.NewReader(os.Stdin)

// Run starts the interactive menu loop.
func Run() {
	ui.Init("cyberpunk", false)
	for {
		ui.ClearScreen()
		banner.Print()
		ui.Section("main menu")
		fmt.Println(opt("1", "Auto", "full automated pipeline — recon → harvest → analyze (recommended)"))
		fmt.Println(opt("2", "Recon", "subdomains, resolve, probe, urls, js, content"))
		fmt.Println(opt("3", "Harvest", "JS / secret / cloud / SAN / GitHub harvesting"))
		fmt.Println(opt("4", "Analyze", "endpoint attack-surface + active SQLi/LFI/XSS"))
		fmt.Println(opt("5", "Inspect", "deep per-URL intel from a high-risk.txt"))
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
		case "0", "q", "quit", "exit":
			fmt.Println(ui.Muted("  bye."))
			return
		default:
			// loop
		}
	}
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
	file := askText("high-risk file (e.g. specter-out/target/high-risk.txt)")
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
