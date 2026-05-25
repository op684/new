// Package resolver performs DNS lookups, optionally against user-supplied
// resolvers, with a simple round-robin across them.
package resolver

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

// Resolver resolves hostnames to IPs/CNAMEs using a rotating pool of servers.
type Resolver struct {
	servers []string
	timeout time.Duration
	rr      uint64
	def     *net.Resolver
}

// Record is the result of resolving a host.
type Record struct {
	Host  string
	IPs   []string
	CNAME string
}

// New builds a resolver. With no servers it uses the system resolver.
func New(servers []string, timeout time.Duration) *Resolver {
	return &Resolver{
		servers: servers,
		timeout: timeout,
		def:     &net.Resolver{},
	}
}

func (r *Resolver) pick() *net.Resolver {
	if len(r.servers) == 0 {
		return r.def
	}
	i := atomic.AddUint64(&r.rr, 1)
	srv := r.servers[int(i)%len(r.servers)]
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			return d.DialContext(ctx, "udp", srv)
		},
	}
}

// Resolve looks up A/AAAA records and the CNAME chain for a host.
func (r *Resolver) Resolve(host string) (*Record, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	res := r.pick()
	addrs, err := res.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, false
	}
	rec := &Record{Host: host, IPs: dedupe(addrs)}
	if cname, err := res.LookupCNAME(ctx, host); err == nil {
		cname = trimDot(cname)
		if cname != "" && cname != host {
			rec.CNAME = cname
		}
	}
	return rec, true
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func trimDot(s string) string {
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}
