// Package ui implements SPECTER's terminal styling: ANSI colors, themes,
// box drawing and status glyphs. It is dependency-free so it builds cleanly
// inside Termux on arm64.
package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI building blocks.
const (
	esc       = "\x1b["
	reset     = "\x1b[0m"
	bold      = "\x1b[1m"
	dim       = "\x1b[2m"
	italic    = "\x1b[3m"
	underline = "\x1b[4m"
)

var (
	enabled     = true
	interactive = true
	mu          sync.Mutex
	theme       = Themes["cyberpunk"]
)

// Theme is a named palette. Colors are 24-bit truecolor "r;g;b" triplets,
// which Termux renders beautifully.
type Theme struct {
	Name      string
	Primary   string
	Secondary string
	Accent    string
	Good      string
	Warn      string
	Bad       string
	Muted     string
	GradientA [3]int
	GradientB [3]int
}

// Themes is the built-in palette set. SPECTER ships a single, finely-tuned
// cyberpunk palette (neon magenta / electric cyan) for maximum terminal pop.
var Themes = map[string]Theme{
	"cyberpunk": {
		Name: "cyberpunk", Primary: "255;0;200", Secondary: "0;220;255", Accent: "255;240;120",
		Good: "0;255;170", Warn: "255;180;0", Bad: "255;40;90", Muted: "120;90;140",
		GradientA: [3]int{120, 0, 200}, GradientB: [3]int{0, 220, 255},
	},
}

// Init configures the global UI state.
func Init(themeName string, noColor bool) {
	mu.Lock()
	defer mu.Unlock()
	if t, ok := Themes[strings.ToLower(themeName)]; ok {
		theme = t
	}
	if noColor || os.Getenv("NO_COLOR") != "" {
		enabled = false
	}
	if fi, err := os.Stdout.Stat(); err == nil {
		interactive = fi.Mode()&os.ModeCharDevice != 0
	}
}

// Interactive reports whether stdout is an attached terminal.
func Interactive() bool { return interactive }

// Active returns the current theme.
func Active() Theme { return theme }

func fg(rgb string) string {
	if !enabled {
		return ""
	}
	return esc + "38;2;" + rgb + "m"
}

func clear() string {
	if !enabled {
		return ""
	}
	return reset
}

// Color wraps text in a truecolor foreground.
func Color(rgb, s string) string { return fg(rgb) + s + clear() }

// Convenience colorizers tied to the active theme.
func Primary(s string) string   { return Color(theme.Primary, s) }
func Secondary(s string) string { return Color(theme.Secondary, s) }
func Accent(s string) string    { return Color(theme.Accent, s) }
func Good(s string) string      { return Color(theme.Good, s) }
func Warn(s string) string      { return Color(theme.Warn, s) }
func Bad(s string) string       { return Color(theme.Bad, s) }
func Muted(s string) string     { return Color(theme.Muted, s) }

// Bold makes text bold (if enabled).
func Bold(s string) string {
	if !enabled {
		return s
	}
	return bold + s + reset
}

// Dim makes text dim.
func Dim(s string) string {
	if !enabled {
		return s
	}
	return dim + s + reset
}

// Gradient paints a string across the theme's two gradient anchors.
func Gradient(s string) string {
	if !enabled || len(s) == 0 {
		return s
	}
	a, b := theme.GradientA, theme.GradientB
	runes := []rune(s)
	n := len(runes)
	var sb strings.Builder
	for i, r := range runes {
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		cr := int(float64(a[0]) + (float64(b[0])-float64(a[0]))*t)
		cg := int(float64(a[1]) + (float64(b[1])-float64(a[1]))*t)
		cb := int(float64(a[2]) + (float64(b[2])-float64(a[2]))*t)
		sb.WriteString(fmt.Sprintf("%s38;2;%d;%d;%dm%c", esc, cr, cg, cb, r))
	}
	sb.WriteString(clear())
	return sb.String()
}

// Status glyphs ----------------------------------------------------------

func tag(rgb, label string) string {
	return Dim("[") + Color(rgb, label) + Dim("]")
}

// Info prints an informational line.
func Info(format string, a ...any) {
	fmt.Printf("%s %s\n", tag(theme.Secondary, "*"), fmt.Sprintf(format, a...))
}

// Good prints a success line.
func Success(format string, a ...any) {
	fmt.Printf("%s %s\n", tag(theme.Good, "+"), fmt.Sprintf(format, a...))
}

// Warning prints a warning line.
func Warning(format string, a ...any) {
	fmt.Printf("%s %s\n", tag(theme.Warn, "!"), fmt.Sprintf(format, a...))
}

// Error prints an error line.
func Error(format string, a ...any) {
	fmt.Printf("%s %s\n", tag(theme.Bad, "x"), fmt.Sprintf(format, a...))
}

// Result prints a discovery line with an arrow glyph.
func Result(format string, a ...any) {
	fmt.Printf("%s %s\n", Color(theme.Primary, " >"), fmt.Sprintf(format, a...))
}

// Section prints a stylized module header banner.
func Section(title string) {
	width := 58
	t := " " + strings.ToUpper(title) + " "
	pad := width - len([]rune(t)) - 4
	if pad < 0 {
		pad = 0
	}
	left := pad / 2
	right := pad - left
	bar := Color(theme.Secondary, "  "+strings.Repeat("=", left)+"[") +
		Bold(Gradient(t)) +
		Color(theme.Secondary, "]"+strings.Repeat("=", right))
	fmt.Println()
	fmt.Println(bar)
	fmt.Println()
}

// KV prints an aligned key/value pair.
func KV(key, value string) {
	fmt.Printf("   %s %s\n", Muted(fmt.Sprintf("%-14s", key)), value)
}

// Spinner is a lightweight animated progress indicator safe for Termux.
type Spinner struct {
	label  string
	stop   chan struct{}
	done   chan struct{}
	frames []string
}

// NewSpinner builds (but does not start) a spinner.
func NewSpinner(label string) *Spinner {
	return &Spinner{
		label:  label,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
	}
}

// Start begins animating in a goroutine. No-op when not on a TTY.
func (s *Spinner) Start() {
	if !enabled || !interactive {
		close(s.done)
		return
	}
	go func() {
		defer close(s.done)
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Print("\r\x1b[K")
				return
			default:
				fmt.Printf("\r%s %s", Color(theme.Primary, s.frames[i%len(s.frames)]), Muted(s.label))
				i++
				time.Sleep(90 * time.Millisecond)
			}
		}
	}()
}

// Stop halts the spinner and clears the line.
func (s *Spinner) Stop() {
	if !enabled || !interactive {
		return
	}
	close(s.stop)
	<-s.done
}

// Progress writes an in-place status line (only on a TTY).
func Progress(format string, a ...any) {
	if !interactive {
		return
	}
	fmt.Printf("\r%s", fmt.Sprintf(format, a...))
}

// ClearLine erases the current terminal line (only on a TTY).
func ClearLine() {
	if !interactive {
		return
	}
	fmt.Print("\r\x1b[K")
}

// Muted2 prints a full muted line (printf-style).
func Muted2(format string, a ...any) {
	fmt.Println(Muted(fmt.Sprintf(format, a...)))
}
