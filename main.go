// SPECTER — the all-in-one bug bounty reconnaissance suite for Termux/arm64.
//
// One binary, four modes:
//
//	specter auto     -d target.com        full automated pipeline (recon→harvest→analyze)
//	specter recon    -d target.com -all   subdomain/host/url/js reconnaissance
//	specter harvest  -u https://target    JS/secret/cloud/SAN harvesting (SubDomainizer++)
//	specter analyze  -i endpoints.txt      endpoint attack-surface analysis + active probing
//
// Pure Go standard library — cross-compiles cleanly for arm64 with no deps.
package main

import (
	"fmt"
	"os"
	"strings"

	"specter/internal/auto"
	"specter/internal/banner"
	"specter/internal/phantom"
	"specter/internal/recon"
	"specter/internal/ui"
	"specter/internal/vector"
)

func main() {
	if len(os.Args) < 2 {
		rootHelp()
		os.Exit(1)
	}
	sub := os.Args[1]
	rest := os.Args[2:]

	switch strings.ToLower(sub) {
	case "auto", "a":
		auto.Run(rest)
	case "recon", "r":
		recon.Run(rest)
	case "harvest", "h":
		phantom.Run(rest)
	case "analyze", "an", "vector":
		vector.Run(rest)
	case "version", "-v", "--version":
		fmt.Printf("specter v%s\n", banner.Version)
	case "help", "-h", "--help":
		rootHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", sub)
		rootHelp()
		os.Exit(2)
	}
}

func rootHelp() {
	ui.Init("cyberpunk", false)
	banner.Print()
	fmt.Print(`SPECTER — all-in-one bug bounty recon suite

USAGE:
  specter <command> [options]

COMMANDS:
  auto       full automated pipeline: recon → harvest → analyze, chained
             (best starting point — one command does everything)
  recon      subdomain enumeration, resolution, probing, urls, js, content
  harvest    JS/secret/cloud/SAN/GitHub harvesting (SubDomainizer, upgraded)
  analyze    endpoint attack-surface analysis + active SQLi/LFI/XSS probing
  version    print version
  help       show this help

QUICK START:
  specter auto -d target.com -o loot/          # everything, automatically
  specter auto -d target.com -deep -attack     # max coverage + active vuln probing
  specter recon -d target.com -all -json
  specter harvest -u https://target.com -san same -sop secrets.txt
  specter analyze -i loot/target.com/endpoints.txt -min high

Run 'specter <command> -h' for command-specific options.
`)
}
