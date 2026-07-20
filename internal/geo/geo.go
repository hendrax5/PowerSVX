package geo

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// Info is a simplified geo lookup result used for GeoDNS tagging.
type Info struct {
	Country   string // ISO 3166-1 alpha-2
	Continent string // e.g. AS, EU
	City      string
	Tag       string // preferred routing tag (country or continent or default)
}

// Resolver looks up client geo. Works without MMDB via static overrides.
type Resolver struct {
	mu        sync.RWMutex
	db        *geoip2.Reader
	enabled   bool
	defaultTag string
	overrides map[string]Info // exact IP string → info
}

func New(enabled bool, dbPath, defaultTag string) (*Resolver, error) {
	if defaultTag == "" {
		defaultTag = "default"
	}
	r := &Resolver{
		enabled:    enabled,
		defaultTag: defaultTag,
		overrides:  make(map[string]Info),
	}
	if !enabled {
		return r, nil
	}
	if dbPath != "" {
		db, err := geoip2.Open(dbPath)
		if err != nil {
			// allow start without DB — overrides still work
			return r, fmt.Errorf("geoip open %s: %w", dbPath, err)
		}
		r.db = db
	}
	return r, nil
}

func (r *Resolver) Enabled() bool { return r != nil && r.enabled }

func (r *Resolver) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

func (r *Resolver) SetOverride(ip string, info Info) {
	if r == nil {
		return
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if info.Tag == "" {
		info.Tag = preferTag(info.Country, info.Continent, r.defaultTag)
	}
	r.overrides[parsed.String()] = info
}

func preferTag(country, continent, def string) string {
	if country != "" {
		return strings.ToUpper(country)
	}
	if continent != "" {
		return strings.ToUpper(continent)
	}
	return def
}

// Lookup returns geo info for IP; never fails hard — returns default tag.
func (r *Resolver) Lookup(ipStr string) Info {
	def := Info{Tag: "default"}
	if r == nil || !r.enabled {
		return def
	}
	def.Tag = r.defaultTag
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return def
	}
	key := ip.String()

	r.mu.RLock()
	if o, ok := r.overrides[key]; ok {
		r.mu.RUnlock()
		return o
	}
	db := r.db
	r.mu.RUnlock()

	if db == nil {
		return def
	}
	rec, err := db.City(ip)
	if err != nil {
		return def
	}
	info := Info{
		Country:   rec.Country.IsoCode,
		Continent: rec.Continent.Code,
		City:      "",
	}
	if name, ok := rec.City.Names["en"]; ok {
		info.City = name
	}
	info.Tag = preferTag(info.Country, info.Continent, r.defaultTag)
	return info
}
