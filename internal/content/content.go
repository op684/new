// Package content performs concurrent content/directory discovery against a
// live base URL using a wordlist.
package content

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"specter/internal/core"
)

// Scanner probes paths under a base URL.
type Scanner struct {
	client     *http.Client
	userAgent  string
	matchCodes map[int]bool
}

// Options configures the Scanner.
type Options struct {
	Timeout    time.Duration
	UserAgent  string
	MatchCodes []int
}

// New builds a content Scanner.
func New(o Options) *Scanner {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 50,
	}
	client := &http.Client{
		Timeout:   o.Timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	mc := map[int]bool{}
	for _, c := range o.MatchCodes {
		mc[c] = true
	}
	return &Scanner{client: client, userAgent: o.UserAgent, matchCodes: mc}
}

// Run brute-forces paths under base and invokes onHit for each accepted result.
func (s *Scanner) Run(ctx context.Context, base string, words []string, workers int,
	onHit func(core.Finding), onProgress func(done, total int64)) {

	base = strings.TrimRight(base, "/")
	total := int64(len(words))
	var done int64
	jobs := make(chan string, workers*2)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if f, ok := s.check(ctx, base, path); ok {
					onHit(f)
				}
				n := atomic.AddInt64(&done, 1)
				if onProgress != nil {
					onProgress(n, total)
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, w := range words {
			select {
			case <-ctx.Done():
				return
			case jobs <- strings.TrimPrefix(w, "/"):
			}
		}
	}()

	wg.Wait()
}

func (s *Scanner) check(ctx context.Context, base, path string) (core.Finding, bool) {
	url := base + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return core.Finding{}, false
	}
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return core.Finding{}, false
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))

	if !s.accept(resp.StatusCode) {
		return core.Finding{}, false
	}
	return core.Finding{
		URL:           url,
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(data)),
		Words:         len(strings.Fields(string(data))),
		Redirect:      resp.Header.Get("Location"),
	}, true
}

func (s *Scanner) accept(code int) bool {
	if len(s.matchCodes) > 0 {
		return s.matchCodes[code]
	}
	// Default: anything that isn't a 404 / connection-level miss is worth noting.
	return code != http.StatusNotFound && code != http.StatusGone
}
