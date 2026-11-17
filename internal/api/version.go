package api

import (
	"runtime/debug"
	"strings"
)

// Set at link time (Dockerfile / go build -ldflags -X). Defaults for `go run`.
var (
	Version   = "1.7.0"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func init() {
	if GitCommit == "" || GitCommit == "unknown" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					GitCommit = shortGit(s.Value)
					break
				}
			}
		}
	}
	GitCommit = shortGit(GitCommit)
}

func shortGit(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// BuildID is stable across process restarts of the same binary (version+git).
func BuildID() string {
	if GitCommit == "" || GitCommit == "unknown" {
		return Version
	}
	return Version + "+" + GitCommit
}

func versionFields() map[string]any {
	return map[string]any{
		"version":    Version,
		"git":        GitCommit,
		"build_time": BuildTime,
		"build_id":   BuildID(),
	}
}
