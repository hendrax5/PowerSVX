package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"
)

const luaExecTimeout = 50 * time.Millisecond

// Lua hook: script must define function on_query(name, qtype, client_ip) -> "continue"|"nxdomain"|"nodata"|"refused"
type luaHook struct {
	name string
	mu   sync.Mutex
	L    *lua.LState
}

func openSafeLuaLibs(L *lua.LState) {
	for _, lib := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	} {
		L.Push(L.NewFunction(lib.fn))
		L.Push(lua.LString(lib.name))
		L.Call(1, 0)
	}
	// Strip dangerous code-loading primitives even inside base library.
	for _, sym := range []string{"dofile", "loadfile", "load", "loadstring"} {
		L.SetGlobal(sym, lua.LNil)
	}
}

func LoadLua(path string) (Hook, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	openSafeLuaLibs(L)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	L.SetContext(ctx)
	err = L.DoString(string(src))
	cancel()
	L.RemoveContext()
	if err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), luaExecTimeout)
	h.L.SetContext(ctx)
	defer func() {
		h.L.RemoveContext()
		cancel()
	}()
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
