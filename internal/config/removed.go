package config

import (
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// removedKeys lists the configuration keys that lost their meaning in version 2
// (ADR-0001: dnsdist is the only Dataplane, so the Go process answers only its
// Authoritative Zones). A section name removes every key under it. A file that
// still carries one of them loads normally; the key is ignored and reported once.
var removedKeys = []string{
	"cache",
	"server.dot_port",
	"server.doh_port",
	"server.doq_port",
	"server.tls",
	"server.tproxy",
	"resolver.root_hints_file",
	"resolver.qname_minimization",
	"resolver.timeout_ms",
	"resolver.max_inflight",
	"resolver.fallback_timeout_ms",
	"resolver.ecs_prefix_v4",
	"resolver.ecs_prefix_v6",
	"logging.query_log_destination",
	"rpz.hot_cache_max",
	"rpz.hot_seed_top_n",
	"plugins",
	"api.grpc_enabled",
	"api.grpc_bind",
	"metrics.otel_enabled",
}

// removedKeysIn returns the removed keys the file still sets, sorted, one entry
// per removed key (a removed section counts once).
func removedKeysIn(md toml.MetaData) []string {
	found := map[string]bool{}
	for _, k := range md.Keys() {
		name := k.String()
		for _, r := range removedKeys {
			if name == r || strings.HasPrefix(name, r+".") {
				found[r] = true
			}
		}
	}
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
