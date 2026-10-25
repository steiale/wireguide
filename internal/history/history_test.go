package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecordAndGetAll(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)

	a := s.RecordConnect("a")
	b := s.RecordConnect("b")
	if a == "" || a == b {
		t.Fatalf("ids %q %q", a, b)
	}
	s.RecordDisconnect(a, 100, 200, "user")

	all := s.GetAll()
	if len(all) != 2 || all[0].TunnelName != "b" || all[1].TunnelName != "a" {
		t.Fatalf("GetAll not newest-first: %+v", all)
	}
	if all[1].EndTime == nil || all[1].RxBytes != 100 || all[1].TxBytes != 200 || all[1].DisconnectReason != "user" {
		t.Errorf("disconnect not recorded: %+v", all[1])
	}
	if all[0].EndTime != nil {
		t.Error("open session closed")
	}
	fi, err := os.Stat(filepath.Join(dir, "history.json"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Errorf("history.json: %v %v", fi, err)
	}

	// Unknown and empty IDs are no-ops.
	s.RecordDisconnect("nope", 1, 1, "x")
	s.RecordDisconnect("", 1, 1, "x")
	if len(s.GetAll()) != 2 {
		t.Error("unknown id changed history")
	}

	if err := s.Clear(); err != nil || len(s.GetAll()) != 0 {
		t.Errorf("Clear: %v", err)
	}
	if err := s.Clear(); err != nil {
		t.Errorf("Clear on missing file: %v", err)
	}
}

func TestPhantomSessionsDropped(t *testing.T) {
	s := NewStore(t.TempDir())
	id := s.RecordConnect("a")
	s.RecordDisconnect(id, 0, 0, "x") // 0s, 0 bytes
	if n := len(s.GetAll()); n != 0 {
		t.Errorf("phantom kept: %d", n)
	}
	s.RecordConnect("b")
	s.CloseOpenSessions("quit") // 0s open session dropped
	if n := len(s.GetAll()); n != 0 {
		t.Errorf("0s open session kept: %d", n)
	}
}

func TestCloseOpenSessionsAndTrim(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	start := time.Now().Add(-time.Hour)
	sessions := make([]Session, MaxSessions+5)
	for i := range sessions {
		sessions[i] = Session{ID: newID(), TunnelName: "t", StartTime: start}
	}
	data, _ := json.Marshal(sessions)
	if err := os.WriteFile(filepath.Join(dir, "history.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s.CloseOpenSessions("quit")
	for _, ss := range s.GetAll() {
		if ss.EndTime == nil || ss.DisconnectReason != "quit" || ss.DurationSec < 3500 {
			t.Fatalf("not closed: %+v", ss)
		}
	}
	s.RecordConnect("new")
	if n := len(s.GetAll()); n != MaxSessions {
		t.Errorf("not trimmed to %d: %d", MaxSessions, n)
	}
}

func TestCorruptFileStartsFresh(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "history.json"), []byte("{nope"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	if len(s.GetAll()) != 0 {
		t.Error("corrupt file yielded sessions")
	}
	s.RecordConnect("a")
	if len(s.GetAll()) != 1 {
		t.Error("could not record after corruption")
	}
}
