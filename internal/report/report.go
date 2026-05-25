// Package report persists run results to disk as plaintext and JSON, and
// renders an on-screen summary.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"specter/internal/core"
	"specter/internal/portscan"
	"specter/internal/ui"
)

// Writer manages the per-target output directory.
type Writer struct {
	dir  string
	json bool
}

// New creates the output directory for a target and returns a Writer.
func New(baseDir, target string, asJSON bool) (*Writer, error) {
	dir := filepath.Join(baseDir, target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Writer{dir: dir, json: asJSON}, nil
}

// Dir returns the output directory path.
func (w *Writer) Dir() string { return w.dir }

func (w *Writer) writeLines(name string, lines []string) {
	if len(lines) == 0 {
		return
	}
	path := filepath.Join(w.dir, name)
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// Persist writes all artifacts for a completed result.
func (w *Writer) Persist(r *core.Result) error {
	r.Sort()
	r.Duration = time.Since(r.StartedAt).Round(time.Millisecond).String()

	var subs, resolved, live, urlsInteresting, takeovers []string
	for _, a := range r.Assets {
		subs = append(subs, a.Host)
		if a.Resolved {
			line := a.Host
			if len(a.IPs) > 0 {
				line += " [" + strings.Join(a.IPs, ",") + "]"
			}
			resolved = append(resolved, line)
		}
		if a.HTTP != nil {
			line := fmt.Sprintf("%s [%d] [%s] [%s]",
				a.HTTP.URL, a.HTTP.StatusCode, a.HTTP.Title, strings.Join(a.Technology, ","))
			if a.HTTP.CORS != "" {
				line += " [CORS: " + a.HTTP.CORS + "]"
			}
			live = append(live, line)
		}
		if a.Takeover != "" {
			takeovers = append(takeovers, a.Host+" -> "+a.Takeover)
		}
	}
	w.writeLines("subdomains.txt", subs)
	w.writeLines("resolved.txt", resolved)
	w.writeLines("live.txt", live)
	w.writeLines("takeovers.txt", takeovers)
	w.writeLines("urls.txt", r.URLs)
	w.writeLines("params.txt", r.Params)
	w.writeLines("js-files.txt", r.JSFiles)
	w.writeLines("endpoints.txt", r.Endpoints)

	var secrets []string
	for _, s := range r.Secrets {
		secrets = append(secrets, fmt.Sprintf("[%s] %s  (%s)", s.Type, s.Match, s.Source))
	}
	w.writeLines("secrets.txt", secrets)

	urlsInteresting = interesting(r.URLs)
	w.writeLines("urls-interesting.txt", urlsInteresting)

	var ports []string
	for _, a := range r.Assets {
		if len(a.Ports) == 0 {
			continue
		}
		var parts []string
		for _, p := range a.Ports {
			label := portscan.Label(p.Port)
			if p.Banner != "" {
				label += " (" + p.Banner + ")"
			}
			parts = append(parts, label)
		}
		ports = append(ports, a.Host+": "+strings.Join(parts, ", "))
	}
	w.writeLines("ports.txt", ports)

	var findings []string
	for _, f := range r.Findings {
		findings = append(findings, fmt.Sprintf("%d %8d %s", f.StatusCode, f.ContentLength, f.URL))
	}
	w.writeLines("content.txt", findings)

	if w.json {
		path := filepath.Join(w.dir, "report.json")
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

func interesting(urls []string) []string {
	markers := []string{".json", ".sql", ".bak", ".env", ".config", ".yml", ".log",
		"/api/", "/admin", "/graphql", "/swagger", "token=", "key=", "redirect=", "url="}
	var out []string
	seen := map[string]bool{}
	for _, u := range urls {
		l := strings.ToLower(u)
		for _, m := range markers {
			if strings.Contains(l, m) && !seen[u] {
				seen[u] = true
				out = append(out, u)
				break
			}
		}
	}
	return out
}

// Summary prints a stylized end-of-run dashboard.
func Summary(r *core.Result, dir string) {
	var resolved, live, withPorts, takeovers, corsIssues, secHdr int
	codes := map[int]int{}
	for _, a := range r.Assets {
		if a.Resolved {
			resolved++
		}
		if len(a.Ports) > 0 {
			withPorts++
		}
		if a.Takeover != "" {
			takeovers++
		}
		if a.HTTP != nil {
			live++
			codes[a.HTTP.StatusCode]++
			if a.HTTP.CORS != "" {
				corsIssues++
			}
			secHdr += len(a.HTTP.SecurityIssues)
		}
	}

	ui.Section("recon summary :: " + r.Target)
	ui.KV("subdomains", ui.Bold(strconv.Itoa(len(r.Assets))))
	ui.KV("resolved", ui.Good(strconv.Itoa(resolved)))
	ui.KV("live http", ui.Good(strconv.Itoa(live)))
	ui.KV("with ports", ui.Warn(strconv.Itoa(withPorts)))
	ui.KV("urls", ui.Bold(strconv.Itoa(len(r.URLs))))
	ui.KV("params", ui.Bold(strconv.Itoa(len(r.Params))))
	ui.KV("js files", ui.Bold(strconv.Itoa(len(r.JSFiles))))
	ui.KV("endpoints", ui.Bold(strconv.Itoa(len(r.Endpoints))))
	ui.KV("secrets", highlight(len(r.Secrets)))
	ui.KV("takeovers", highlight(takeovers))
	ui.KV("cors issues", highlight(corsIssues))
	ui.KV("content hits", ui.Warn(strconv.Itoa(len(r.Findings))))
	if len(codes) > 0 {
		var parts []string
		for code, n := range codes {
			parts = append(parts, fmt.Sprintf("%d×%d", code, n))
		}
		ui.KV("status codes", strings.Join(parts, "  "))
	}
	ui.KV("duration", ui.Accent(time.Since(r.StartedAt).Round(time.Millisecond).String()))
	ui.KV("output", ui.Secondary(dir))
	fmt.Println()
}

// highlight shows zero as muted and any positive count as an alarming red.
func highlight(n int) string {
	if n == 0 {
		return ui.Muted("0")
	}
	return ui.Bad(ui.Bold(strconv.Itoa(n)))
}
