package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

// Lua hook: script must define function on_query(name, qtype, client_ip) -> "continue"|"nxdomain"|"nodata"|"refused"
type luaHook struct {
	name string
	mu   sync.Mutex
	L    *lua.LState
}

func LoadLua(path string) (Hook, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	L := lua.NewState(lua.Options{SkipOpenLibs: false})
	if err := L.DoString(string(src)); err != nil {
		L.Close()
		return nil, err
	}
	fn := L.GetGlobal("on_query")
	if fn.Type() != lua.LTFunction {
		L.Close()
		return nil, fmt.Errorf("on_query function required")
	}
	return &luaHook{name: filepath.Base(path), L: L}, nil
}

func (h *luaHook) Name() string { return h.name }

func (h *luaHook) OnQuery(q QueryCtx) Decision {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn := h.L.GetGlobal("on_query")
	if err := h.L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true},
		lua.LString(q.Name),
		lua.LNumber(q.Qtype),
		lua.LString(q.ClientIP),
	); err != nil {
		return DecisionContinue
	}
	ret := h.L.Get(-1)
	h.L.Pop(1)
	return parseDecision(ret.String())
}

func parseDecision(s string) Decision {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "nxdomain", "block":
		return DecisionNXDOMAIN
	case "nodata":
		return DecisionNODATA
	case "refused":
		return DecisionRefused
	default:
		return DecisionContinue
	}
}
