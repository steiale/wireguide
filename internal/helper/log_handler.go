package helper

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/steiale/wireguide/internal/ipc"
)

// broadcastHandler writes every record to stderr AND broadcasts it to IPC
// subscribers, so the GUI's log viewer shows the helper's activity. Both
// honour the shared, runtime-mutable level.
type broadcastHandler struct {
	levelVar  *slog.LevelVar
	stderr    slog.Handler
	broadcast func(method string, params interface{})
	attrs     []slog.Attr // from WithAttrs; immutable once built
}

func newBroadcastHandler(levelVar *slog.LevelVar, broadcast func(string, interface{})) *broadcastHandler {
	return &broadcastHandler{
		levelVar:  levelVar,
		stderr:    slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: levelVar}),
		broadcast: broadcast,
	}
}

func (h *broadcastHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.levelVar.Level()
}

func (h *broadcastHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = h.stderr.Handle(ctx, r)

	// Render as one flat line for the viewer.
	var b strings.Builder
	b.WriteString(r.Message)
	for _, a := range h.attrs {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
	}
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
		return true
	})
	h.broadcast(ipc.EventLog, ipc.LogEntry{
		Time:    r.Time.UTC().Format(time.RFC3339Nano),
		Level:   strings.ToLower(r.Level.String()),
		Source:  "helper",
		Message: b.String(),
	})
	return nil
}

func (h *broadcastHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.stderr = h.stderr.WithAttrs(attrs)
	c.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &c
}

func (h *broadcastHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.stderr = h.stderr.WithGroup(name)
	return &c
}

// parseLevel maps a user-facing string ("debug", "info", ...) to slog.Level.
// Unknown strings default to Info.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
