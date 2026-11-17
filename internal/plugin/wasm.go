package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// WASM ABI: export filter(ptr, len) -> i32
//
//	0 = continue, 1 = nxdomain, 2 = nodata, 3 = refused
//
// Name bytes written by host into guest memory at ptr.
type wasmHook struct {
	name string
	mu   sync.Mutex
	r    wazero.Runtime
	mod  api.Module
}

func LoadWASM(path string) (Hook, error) {
	bin, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return nil, err
	}
	mod, err := r.Instantiate(ctx, bin)
	if err != nil {
		_ = r.Close(ctx)
		return nil, err
	}
	if mod.ExportedFunction("filter") == nil {
		_ = mod.Close(ctx)
		_ = r.Close(ctx)
		return nil, fmt.Errorf("export filter(i32,i32)->i32 required")
	}
	return &wasmHook{name: filepath.Base(path), r: r, mod: mod}, nil
}

func (h *wasmHook) Name() string { return h.name }

func (h *wasmHook) OnQuery(q QueryCtx) Decision {
	h.mu.Lock()
	defer h.mu.Unlock()
	ctx := context.Background()
	fn := h.mod.ExportedFunction("filter")
	alloc := h.mod.ExportedFunction("alloc")
	name := []byte(q.Name)
	var ptr uint64
	if alloc != nil {
		res, err := alloc.Call(ctx, uint64(len(name)))
		if err != nil || len(res) == 0 {
			return DecisionContinue
		}
		ptr = res[0]
	} else {
		// Fallback: write at offset 64 if module has memory
		ptr = 64
	}
	mem := h.mod.Memory()
	if mem == nil || !mem.Write(uint32(ptr), name) {
		return DecisionContinue
	}
	res, err := fn.Call(ctx, ptr, uint64(len(name)))
	if err != nil || len(res) == 0 {
		return DecisionContinue
	}
	switch res[0] {
	case 1:
		return DecisionNXDOMAIN
	case 2:
		return DecisionNODATA
	case 3:
		return DecisionRefused
	default:
		return DecisionContinue
	}
}
