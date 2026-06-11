package socks

import (
	"testing"
	"time"
)

func TestPollIntervalDefault(t *testing.T) {
	s := &Server{}
	if got := s.pollInterval(); got != DefaultPollInterval {
		t.Fatalf("pollInterval = %s, want %s", got, DefaultPollInterval)
	}
}

func TestPollIntervalOverride(t *testing.T) {
	s := &Server{PollInterval: 250 * time.Millisecond}
	if got := s.pollInterval(); got != 250*time.Millisecond {
		t.Fatalf("pollInterval = %s, want 250ms", got)
	}
}

func TestPollIntervalZeroFallsBackToDefault(t *testing.T) {
	s := &Server{PollInterval: 0}
	if got := s.pollInterval(); got != DefaultPollInterval {
		t.Fatalf("pollInterval = %s, want %s", got, DefaultPollInterval)
	}
}
