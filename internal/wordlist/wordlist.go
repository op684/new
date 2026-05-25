// Package wordlist provides embedded default wordlists plus a loader that
// prefers a user-supplied file when one is given.
package wordlist

import (
	_ "embed"
	"os"
	"strings"
)

//go:embed subdomains.txt
var subdomainsRaw string

//go:embed content.txt
var contentRaw string

// Subdomains returns the wordlist for DNS bruteforce. If path is non-empty and
// readable it is used; otherwise the built-in list is returned.
func Subdomains(path string) []string {
	if lines, ok := fromFile(path); ok {
		return lines
	}
	return split(subdomainsRaw)
}

// Content returns the wordlist for content discovery (built-in fallback).
func Content(path string) []string {
	if lines, ok := fromFile(path); ok {
		return lines
	}
	return split(contentRaw)
}

func fromFile(path string) ([]string, bool) {
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return split(string(data)), true
}

func split(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}
