package acl

import (
	"fmt"
	"net"
	"strings"
)

// List is a query ACL: deny wins; empty allow means permit all (except deny).
type List struct {
	allow []*net.IPNet
	deny  []*net.IPNet
	rawAllow []string
	rawDeny  []string
}

// Parse builds a List from CIDR or bare IP strings. Invalid entries return an error.
func Parse(allow, deny []string) (*List, error) {
	l := &List{}
	var err error
	if l.allow, l.rawAllow, err = parseCIDRs(allow); err != nil {
		return nil, err
	}
	if l.deny, l.rawDeny, err = parseCIDRs(deny); err != nil {
		return nil, err
	}
	return l, nil
}

func parseCIDRs(in []string) ([]*net.IPNet, []string, error) {
	var nets []*net.IPNet
	var raw []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			ip := net.ParseIP(c)
			if ip == nil {
				return nil, nil, fmt.Errorf("invalid IP/CIDR: %q", c)
			}
			if ip.To4() != nil {
				c = ip.String() + "/32"
			} else {
				c = ip.String() + "/128"
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid IP/CIDR: %q", c)
		}
		nets = append(nets, n)
		raw = append(raw, n.String())
	}
	return nets, raw, nil
}

// Allows reports whether clientIP may query. Empty client → deny when ACL is restrictive.
func (l *List) Allows(clientIP string) bool {
	if l == nil {
		return true
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return len(l.allow) == 0 && len(l.deny) == 0
	}
	for _, n := range l.deny {
		if n.Contains(ip) {
			return false
		}
	}
	if len(l.allow) == 0 {
		return true
	}
	for _, n := range l.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (l *List) AllowCIDRs() []string {
	if l == nil {
		return nil
	}
	out := make([]string, len(l.rawAllow))
	copy(out, l.rawAllow)
	return out
}

func (l *List) DenyCIDRs() []string {
	if l == nil {
		return nil
	}
	out := make([]string, len(l.rawDeny))
	copy(out, l.rawDeny)
	return out
}

// Open is an empty ACL (allow all).
func Open() *List { return &List{} }
