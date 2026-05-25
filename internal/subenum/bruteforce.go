package subenum

import (
	"context"
	"sync"
	"sync/atomic"

	"specter/internal/resolver"
)

// BruteResult is a confirmed, resolving host found by bruteforce.
type BruteResult struct {
	Record *resolver.Record
}

// Bruteforce permutes wordlist entries against the domain and keeps only the
// ones that resolve. Progress is reported through onProgress (tested counter).
func Bruteforce(ctx context.Context, res *resolver.Resolver, domain string,
	words []string, workers int, onHit func(*resolver.Record), onProgress func(done, total int64)) {

	total := int64(len(words))
	var done int64
	jobs := make(chan string, workers*2)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				host := word + "." + domain
				if rec, ok := res.Resolve(host); ok {
					onHit(rec)
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
			case jobs <- w:
			}
		}
	}()

	wg.Wait()
}
