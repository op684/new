package harvest

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"
)

// SANMode controls which discovered SAN entries are kept.
type SANMode string

const (
	SANSame SANMode = "same" // only names under the same registrable domain
	SANAll  SANMode = "all"  // every name in the cert
)

// HarvestSANs walks TLS certificates breadth-first: it connects to each host on
// 443, reads the certificate's Subject Alternative Names, and recursively
// follows newly-discovered hostnames. onFound fires for each new name.
func HarvestSANs(ctx context.Context, seeds []string, mode SANMode, timeout time.Duration,
	workers, maxHosts int, onFound func(host string)) []string {

	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if maxHosts <= 0 {
		maxHosts = 2000
	}

	var mu sync.Mutex
	visited := map[string]bool{}
	found := map[string]bool{}
	queue := make([]string, 0, len(seeds))

	enqueue := func(h string) {
		h = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(h), "*."))
		if h == "" || visited[h] {
			return
		}
		visited[h] = true
		queue = append(queue, h)
	}
	for _, s := range seeds {
		enqueue(HostOf(s))
	}

	for len(queue) > 0 && len(visited) < maxHosts {
		select {
		case <-ctx.Done():
			break
		default:
		}
		// Drain current frontier and scan it concurrently.
		frontier := queue
		queue = nil

		var wg sync.WaitGroup
		sem := make(chan struct{}, workers)
		for _, host := range frontier {
			wg.Add(1)
			sem <- struct{}{}
			go func(host string) {
				defer wg.Done()
				defer func() { <-sem }()
				names := certNames(ctx, host, timeout)
				if len(names) == 0 {
					return
				}
				scope := RegisteredDomain(host)
				mu.Lock()
				for _, n := range names {
					n = strings.ToLower(strings.TrimPrefix(n, "*."))
					if n == "" {
						continue
					}
					if mode == SANSame && RegisteredDomain(n) != scope {
						// still enqueue for traversal but don't report out of scope
						if !visited[n] {
							visited[n] = true
							queue = append(queue, n)
						}
						continue
					}
					if !found[n] {
						found[n] = true
						if onFound != nil {
							onFound(n)
						}
					}
					if !visited[n] {
						visited[n] = true
						queue = append(queue, n)
					}
				}
				mu.Unlock()
			}(host)
		}
		wg.Wait()
	}

	out := make([]string, 0, len(found))
	for n := range found {
		out = append(out, n)
	}
	return out
}

func certNames(ctx context.Context, host string, timeout time.Duration) []string {
	d := net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, "443"),
		&tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		return nil
	}
	defer conn.Close()
	var names []string
	for _, cert := range conn.ConnectionState().PeerCertificates {
		names = append(names, cert.DNSNames...)
		if cert.Subject.CommonName != "" {
			names = append(names, cert.Subject.CommonName)
		}
	}
	return names
}
