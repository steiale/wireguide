package app

import (
	"github.com/korjwl1/wireguide/internal/history"
)

// GetConnectionHistory returns the recorded VPN sessions, newest first.
// Returns an empty slice (never nil) so the frontend doesn't have to special-case
// "no history yet" vs. "load failed".
func (s *TunnelService) GetConnectionHistory() ([]history.Session, error) {
	if s.history == nil {
		return []history.Session{}, nil
	}
	out := s.history.GetAll()
	if out == nil {
		out = []history.Session{}
	}
	return out, nil
}

// ClearConnectionHistory wipes the history file.
func (s *TunnelService) ClearConnectionHistory() error {
	if s.history == nil {
		return nil
	}
	return s.history.Clear()
}
