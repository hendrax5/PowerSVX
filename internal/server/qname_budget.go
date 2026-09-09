package server

import "strings"

// Skip Unbound recursion for absurd qnames (scanner / DGA-style).
// Common CDNs and *.go.id stay well under these caps.
const (
	maxQNameLabels = 8
	maxQNameBytes  = 200
)

func qnameTooDeep(qname string) bool {
	n := strings.TrimSuffix(qname, ".")
	if n == "" || n == "." {
		return false
	}
	if len(n) > maxQNameBytes {
		return true
	}
	labels := 1
	for i := 0; i < len(n); i++ {
		if n[i] == '.' {
			labels++
			if labels > maxQNameLabels {
				return true
			}
		}
	}
	return labels > maxQNameLabels
}
