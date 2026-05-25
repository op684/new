// Package banner renders SPECTER's startup art and run summary.
package banner

import (
	"fmt"
	"runtime"
	"strings"

	"specter/internal/ui"
)

// Version is the build version string.
const Version = "1.0.0"

const art = `
 ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗
 ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
 ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
 ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝`

// Print renders the full hacker-theme banner.
func Print() {
	for _, line := range strings.Split(art, "\n") {
		fmt.Println(ui.Gradient(line))
	}
	tagline := "  recon framework :: hunt the surface, own the perimeter"
	fmt.Println(ui.Dim(ui.Secondary(tagline)))
	meta := fmt.Sprintf("  v%s  ·  theme:%s  ·  %s/%s  ·  go%s",
		Version, ui.Active().Name, runtime.GOOS, runtime.GOARCH,
		strings.TrimPrefix(runtime.Version(), "go"))
	fmt.Println(ui.Muted(meta))
	fmt.Println(ui.Dim(ui.Secondary("  " + strings.Repeat("─", 56))))
	fmt.Println()
}
