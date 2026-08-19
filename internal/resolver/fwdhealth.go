package resolver

import (
	"sync/atomic"
	"time"
)

const (
	fwdMaxFails = 3
	fwdCooldown = 10 * time.Second
)

type fwdState struct {
	fails     atomic.Uint32
	downUntil atomic.Int64
}

func (r *Resolver) noteFwd(addr string, ok bool) {
	if r == nil || addr == "" {
		return
	}
	v, _ := r.fwdHealth.LoadOrStore(addr, &fwdState{})
	st := v.(*fwdState)
	if ok {
		st.fails.Store(0)
		st.downUntil.Store(0)
		return
	}
	if st.fails.Add(1) >= fwdMaxFails {
		st.downUntil.Store(time.Now().Add(fwdCooldown).UnixNano())
	}
}

// pickForwarders drops addresses in cooldown. If every address is down, return
// the original list so we still try (same idea as a ranked pool's unhealthy tail).
func (r *Resolver) pickForwarders(all []string) []string {
	if r == nil || len(all) <= 1 {
		return all
	}
	now := time.Now().UnixNano()
	up := make([]string, 0, len(all))
	for _, a := range all {
		v, ok := r.fwdHealth.Load(a)
		if !ok {
			up = append(up, a)
			continue
		}
		st := v.(*fwdState)
		if until := st.downUntil.Load(); until > 0 && now < until {
			continue
		}
		up = append(up, a)
	}
	if len(up) == 0 {
		return all
	}
	return up
}
