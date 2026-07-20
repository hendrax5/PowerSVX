package eventlog

import (
	"context"
	"log/slog"
)

// Handler mirrors slog records at Warn+ into the Bus (errors/warnings only).
type Handler struct {
	inner slog.Handler
	bus   *Bus
}

func NewHandler(inner slog.Handler, bus *Bus) *Handler {
	return &Handler{inner: inner, bus: bus}
}

func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn && h.bus != nil {
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		level := "warn"
		if r.Level >= slog.LevelError {
			level = "error"
		}
		kind := "log"
		if k, ok := attrs["kind"]; ok {
			kind = k
		}
		h.bus.Emit(level, kind, r.Message, attrs)
	}
	return h.inner.Handle(ctx, r)
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{inner: h.inner.WithAttrs(attrs), bus: h.bus}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{inner: h.inner.WithGroup(name), bus: h.bus}
}
