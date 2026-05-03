// Package history records VPN connection sessions with start/end times and
// rx/tx byte totals so the UI can show a chronological log of past tunnels.
//
// The store keeps a rolling cap of the most recent 200 sessions and persists
// to history.json in the user's config directory. Concurrent calls are safe.
package history

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxSessions caps the rolling history. Hard cap (not configurable) to keep
// the file small and the JSON parse fast.
const MaxSessions = 200

// Session represents one VPN connection session.
type Session struct {
	ID               string     `json:"id"`
	TunnelName       string     `json:"tunnel_name"`
	StartTime        time.Time  `json:"start_time"`
	EndTime          *time.Time `json:"end_time,omitempty"`
	DurationSec      int64      `json:"duration_sec"`
	RxBytes          int64      `json:"rx_bytes"`
	TxBytes          int64      `json:"tx_bytes"`
	DisconnectReason string     `json:"disconnect_reason,omitempty"`
}

// Store persists session records to disk with a rolling cap.
type Store struct {
	mu   sync.Mutex
	path string
}

// NewStore creates a Store backed by configDir/history.json.
func NewStore(configDir string) *Store {
	return &Store{path: filepath.Join(configDir, "history.json")}
}

// RecordConnect creates a new session for tunnelName, appends it, and returns
// the generated session ID. Errors are logged — callers don't need to handle
// disk failures since recording is best-effort.
func (s *Store) RecordConnect(tunnelName string) string {
	id := newID()
	now := time.Now()
	session := Session{
		ID:         id,
		TunnelName: tunnelName,
		StartTime:  now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sessions := s.loadLocked()
	sessions = append(sessions, session)
	sessions = trim(sessions)
	if err := s.saveLocked(sessions); err != nil {
		slog.Warn("history: record connect failed", "tunnel", tunnelName, "error", err)
	}
	return id
}

// RecordDisconnect closes an open session by ID, recording final byte counts
// and the disconnect reason. If the ID is unknown (e.g. file was cleared), the
// call is a no-op.
func (s *Store) RecordDisconnect(id string, rx, tx int64, reason string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sessions := s.loadLocked()
	now := time.Now()
	changed := false
	for i := range sessions {
		if sessions[i].ID == id && sessions[i].EndTime == nil {
			end := now
			sessions[i].EndTime = &end
			dur := int64(end.Sub(sessions[i].StartTime).Seconds())
			if dur < 0 {
				dur = 0
			}
			// Drop phantom sessions (0-duration, 0-byte) — they come from
			// interrupted bootstraps or helper restarts and add no value.
			if dur == 0 && rx == 0 && tx == 0 {
				sessions = append(sessions[:i], sessions[i+1:]...)
				changed = true
				break
			}
			sessions[i].EndTime = &end
			sessions[i].DurationSec = dur
			sessions[i].RxBytes = rx
			sessions[i].TxBytes = tx
			sessions[i].DisconnectReason = reason
			changed = true
			break
		}
	}
	if !changed {
		return
	}
	if err := s.saveLocked(sessions); err != nil {
		slog.Warn("history: record disconnect failed", "id", id, "error", err)
	}
}

// CloseOpenSessions closes any session that still has a nil EndTime — used at
// app shutdown so the history doesn't show phantom "still active" rows after
// a quit. rx/tx default to 0 since we don't have last-known counters here;
// callers that do should pass them via RecordDisconnect first.
func (s *Store) CloseOpenSessions(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessions := s.loadLocked()
	now := time.Now()
	changed := false
	kept := sessions[:0]
	for i := range sessions {
		if sessions[i].EndTime == nil {
			dur := int64(now.Sub(sessions[i].StartTime).Seconds())
			if dur < 0 {
				dur = 0
			}
			// Drop 0-duration open sessions — phantom rows from crashes/restarts.
			if dur == 0 {
				changed = true
				continue
			}
			end := now
			sessions[i].EndTime = &end
			sessions[i].DurationSec = dur
			sessions[i].DisconnectReason = reason
			changed = true
		}
		kept = append(kept, sessions[i])
	}
	sessions = kept
	if !changed {
		return
	}
	if err := s.saveLocked(sessions); err != nil {
		slog.Warn("history: close-open save failed", "error", err)
	}
}

// GetAll returns sessions newest-first, capped at MaxSessions.
func (s *Store) GetAll() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessions := s.loadLocked()
	// Reverse and filter: stored oldest-first, return newest-first.
	// Drop completed sessions with 0 duration and 0 bytes — phantom rows
	// from interrupted bootstraps recorded before this fix.
	var out []Session
	for i := len(sessions) - 1; i >= 0; i-- {
		s := sessions[i]
		if s.EndTime != nil && s.DurationSec == 0 && s.RxBytes == 0 && s.TxBytes == 0 {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Clear removes all stored history.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.Remove(s.path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// loadLocked reads the JSON file. Returns an empty slice on missing file or
// parse errors (logged, not surfaced — a corrupt history shouldn't break the
// app).
func (s *Store) loadLocked() []Session {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("history: read failed", "error", err)
		}
		return nil
	}
	var sessions []Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		slog.Warn("history: parse failed, starting fresh", "error", err)
		return nil
	}
	return sessions
}

// saveLocked atomically writes sessions to disk with 0600 permissions.
func (s *Store) saveLocked(sessions []Session) error {
	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".history-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// trim keeps the last MaxSessions entries (oldest first → drop from the front).
func trim(sessions []Session) []Session {
	if len(sessions) <= MaxSessions {
		return sessions
	}
	return sessions[len(sessions)-MaxSessions:]
}

// newID returns a 16-hex-char random ID. Crypto/rand failure falls back to a
// timestamp so we never return an empty ID.
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
