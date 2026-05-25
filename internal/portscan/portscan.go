// Package portscan implements a concurrent TCP-connect scanner with port set
// parsing (top/full/custom ranges) tuned for mobile use.
package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TopPorts is a curated set of the most security-relevant TCP ports.
var TopPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445,
	465, 587, 593, 636, 873, 989, 990, 993, 995, 1080, 1433, 1521, 1723, 2049,
	2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 3000, 3128, 3306,
	3389, 4444, 4567, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6443, 7001,
	7077, 8000, 8008, 8009, 8080, 8081, 8083, 8086, 8088, 8090, 8161, 8443,
	8500, 8888, 9000, 9042, 9092, 9200, 9300, 9418, 9443, 9999, 10000, 11211,
	15672, 27017, 27018, 28017, 50070,
}

// Service maps well-known ports to a label for output.
var Service = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 143: "imap", 389: "ldap", 443: "https", 445: "smb",
	993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
	3306: "mysql", 3389: "rdp", 5432: "postgres", 5601: "kibana", 5900: "vnc",
	6379: "redis", 6443: "k8s-api", 8080: "http-alt", 8443: "https-alt",
	9200: "elastic", 11211: "memcached", 27017: "mongodb", 15672: "rabbitmq",
}

// ParsePorts turns a spec ("top", "full", "80,443,8000-8100") into a port list.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	switch spec {
	case "", "top":
		return TopPorts, nil
	case "full", "all":
		ports := make([]int, 0, 65535)
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports, nil
	}
	seen := map[int]bool{}
	var ports []int
	add := func(p int) {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("bad range %q", part)
			}
			if a > b {
				a, b = b, a
			}
			for p := a; p <= b; p++ {
				add(p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad port %q", part)
			}
			add(p)
		}
	}
	sort.Ints(ports)
	return ports, nil
}

// Scan connect-scans a target across the given ports and returns those open.
func Scan(ctx context.Context, target string, ports []int, workers int, timeout time.Duration) []int {
	jobs := make(chan int, workers*2)
	results := make(chan int, workers*2)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			for port := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				addr := net.JoinHostPort(target, strconv.Itoa(port))
				conn, err := d.DialContext(ctx, "tcp", addr)
				if err == nil {
					conn.Close()
					results <- port
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, p := range ports {
			select {
			case <-ctx.Done():
				return
			case jobs <- p:
			}
		}
	}()

	go func() { wg.Wait(); close(results) }()

	var open []int
	for p := range results {
		open = append(open, p)
	}
	sort.Ints(open)
	return open
}

// Label returns "port (service)" or just the port number.
func Label(port int) string {
	if s, ok := Service[port]; ok {
		return fmt.Sprintf("%d/%s", port, s)
	}
	return strconv.Itoa(port)
}
