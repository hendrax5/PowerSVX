package view

import (
	"net"
	"strings"
)

// View maps client networks to a named DNS view (split horizon).
type View struct {
	Name     string
	Networks []*net.IPNet
}

// Matcher resolves client IP → view name.
type Matcher struct {
	enabled bool
	views   []View
	def     string
}

func New(enabled bool, defaultView string, views []View) *Matcher {
	if defaultView == "" {
		defaultView = "default"
	}
	return &Matcher{enabled: enabled, views: views, def: defaultView}
}

// FromConfig builds matcher from name→CIDR lists.
func FromConfig(enabled bool, defaultView string, named map[string][]string) *Matcher {
	var views []View
	for name, cidrs := range named {
		v := View{Name: name}
		for _, c := range cidrs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				ip := net.ParseIP(c)
				if ip == nil {
					continue
				}
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
			}
			v.Networks = append(v.Networks, n)
		}
		views = append(views, v)
	}
	return New(enabled, defaultView, views)
}

func (m *Matcher) Enabled() bool { return m != nil && m.enabled }

func (m *Matcher) Match(ipStr string) string {
	if !m.Enabled() {
		return m.def
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return m.def
	}
	for _, v := range m.views {
		for _, n := range v.Networks {
			if n.Contains(ip) {
				return v.Name
			}
		}
	}
	return m.def
}

func NormalizeView(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "default"
	}
	return s
}
