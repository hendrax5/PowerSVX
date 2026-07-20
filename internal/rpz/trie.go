package rpz

import (
	"strings"

	"github.com/powersvx/powersvx/internal/config"
)

// Hit is an RPZ match: action plus optional target (IP for redirect, FQDN for cname).
type Hit struct {
	Action Action
	Target string
}

// Compact label-reversed radix: shared suffixes (com., co.id., …) cut RAM vs map[string].
type trie struct {
	root  *tnode
	count int
}

type tnode struct {
	kids       map[string]*tnode
	term       uint8  // exact match action at this suffix
	wild       uint8  // *.suffix action (needs ≥1 label to the left)
	termTarget string // redirect IP or cname host
	wildTarget string
}

func newTrie() *trie {
	return &trie{root: &tnode{kids: make(map[string]*tnode)}}
}

func actionCode(a Action) uint8 {
	switch a {
	case ActionNODATA:
		return 2
	case ActionPass:
		return 3
	case ActionRedirect:
		return 4
	case ActionCNAME:
		return 5
	default:
		return 1 // nxdomain
	}
}

func codeAction(c uint8) Action {
	switch c {
	case 2:
		return ActionNODATA
	case 3:
		return ActionPass
	case 4:
		return ActionRedirect
	case 5:
		return ActionCNAME
	default:
		return ActionNXDOMAIN
	}
}

func (t *trie) insert(name string, action Action) {
	t.insertHit(name, Hit{Action: action})
}

func (t *trie) insertHit(name string, hit Hit) {
	if t == nil || t.root == nil {
		return
	}
	name = config.NormalizeName(name)
	code := actionCode(hit.Action)
	target := strings.TrimSpace(hit.Target)
	wild := false
	if strings.HasPrefix(name, "*.") {
		wild = true
		name = name[2:]
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) == 1 && labels[0] == "" {
		return
	}
	n := t.root
	for i := len(labels) - 1; i >= 0; i-- {
		lab := labels[i]
		if lab == "" {
			continue
		}
		child, ok := n.kids[lab]
		if !ok {
			child = &tnode{kids: make(map[string]*tnode)}
			n.kids[lab] = child
		}
		n = child
	}
	if wild {
		if n.wild == 0 {
			t.count++
		}
		n.wild = code
		n.wildTarget = target
		return
	}
	if n.term == 0 {
		t.count++
	}
	n.term = code
	n.termTarget = target
}

func (t *trie) lookup(name string) (Hit, bool) {
	if t == nil || t.root == nil {
		return Hit{Action: ActionPass}, false
	}
	name = config.NormalizeName(name)
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) == 0 {
		return Hit{Action: ActionPass}, false
	}
	n := t.root
	var wildHit uint8
	var wildTarget string
	for i := len(labels) - 1; i >= 0; i-- {
		lab := labels[i]
		child, ok := n.kids[lab]
		if !ok {
			if wildHit != 0 {
				return Hit{Action: codeAction(wildHit), Target: wildTarget}, true
			}
			return Hit{Action: ActionPass}, false
		}
		n = child
		if n.wild != 0 && i > 0 {
			wildHit = n.wild
			wildTarget = n.wildTarget
		}
	}
	if n.term != 0 {
		return Hit{Action: codeAction(n.term), Target: n.termTarget}, true
	}
	if wildHit != 0 {
		return Hit{Action: codeAction(wildHit), Target: wildTarget}, true
	}
	return Hit{Action: ActionPass}, false
}

// walk visits every exact and wild rule; name is normalized FQDN or *.fqdn.
func (t *trie) walk(fn func(name string, hit Hit)) {
	if t == nil || t.root == nil {
		return
	}
	var rec func(n *tnode, parts []string)
	rec = func(n *tnode, parts []string) {
		if n.term != 0 {
			fn(joinFQDN(parts), Hit{Action: codeAction(n.term), Target: n.termTarget})
		}
		if n.wild != 0 {
			fn("*."+joinFQDN(parts), Hit{Action: codeAction(n.wild), Target: n.wildTarget})
		}
		for lab, child := range n.kids {
			rec(child, append(parts, lab))
		}
	}
	rec(t.root, nil)
}

func joinFQDN(parts []string) string {
	if len(parts) == 0 {
		return "."
	}
	b := strings.Builder{}
	for i := len(parts) - 1; i >= 0; i-- {
		b.WriteString(parts[i])
		b.WriteByte('.')
	}
	return b.String()
}
