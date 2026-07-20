package rpz

import (
	"strings"

	"github.com/powersvx/powersvx/internal/config"
)

// Compact label-reversed radix: shared suffixes (com., co.id., …) cut RAM vs map[string].
type trie struct {
	root  *tnode
	count int
}

type tnode struct {
	kids map[string]*tnode
	term uint8 // exact match action at this suffix
	wild uint8 // *.suffix action (needs ≥1 label to the left)
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
	default:
		return ActionNXDOMAIN
	}
}

func (t *trie) insert(name string, action Action) {
	if t == nil || t.root == nil {
		return
	}
	name = config.NormalizeName(name)
	code := actionCode(action)
	wild := false
	if strings.HasPrefix(name, "*.") {
		wild = true
		name = name[2:]
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) == 1 && labels[0] == "" {
		return
	}
	// walk TLD → left
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
		return
	}
	if n.term == 0 {
		t.count++
	}
	n.term = code
}

func (t *trie) lookup(name string) (Action, bool) {
	if t == nil || t.root == nil {
		return ActionPass, false
	}
	name = config.NormalizeName(name)
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) == 0 {
		return ActionPass, false
	}
	n := t.root
	var wildHit uint8
	// Walk TLD → left. After finishing suffix S at node n, n.wild matches *.S if more labels remain.
	for i := len(labels) - 1; i >= 0; i-- {
		lab := labels[i]
		child, ok := n.kids[lab]
		if !ok {
			if wildHit != 0 {
				return codeAction(wildHit), true
			}
			return ActionPass, false
		}
		n = child
		// remaining left labels: 0..i-1 → if i > 0 there is ≥1 label under this suffix
		if n.wild != 0 && i > 0 {
			wildHit = n.wild
		}
	}
	if n.term != 0 {
		return codeAction(n.term), true
	}
	if wildHit != 0 {
		return codeAction(wildHit), true
	}
	return ActionPass, false
}

// walk visits every exact and wild rule; name is normalized FQDN or *.fqdn.
func (t *trie) walk(fn func(name string, action Action)) {
	if t == nil || t.root == nil {
		return
	}
	var rec func(n *tnode, parts []string)
	rec = func(n *tnode, parts []string) {
		if n.term != 0 {
			fn(joinFQDN(parts), codeAction(n.term))
		}
		if n.wild != 0 {
			fn("*."+joinFQDN(parts), codeAction(n.wild))
		}
		for lab, child := range n.kids {
			rec(child, append(parts, lab))
		}
	}
	rec(t.root, nil)
}

func joinFQDN(parts []string) string {
	// parts collected TLD-first; reverse for wire name
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
