package main

import "testing"

func TestParseTraceLevel(t *testing.T) {
	tests := []struct {
		name          string
		level         string
		legacyVerbose bool
		wantSummary   bool
		wantVerbose   bool
		wantErr       bool
	}{
		{name: "default off"},
		{name: "summary", level: "summary", wantSummary: true},
		{name: "verbose", level: "verbose", wantSummary: true, wantVerbose: true},
		{name: "legacy verbose", legacyVerbose: true, wantSummary: true, wantVerbose: true},
		{name: "explicit off ignores legacy", level: "off", legacyVerbose: true},
		{name: "invalid", level: "chatty", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary, verbose, err := parseTraceLevel(tt.level, tt.legacyVerbose)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if summary != tt.wantSummary || verbose != tt.wantVerbose {
				t.Fatalf("summary=%v verbose=%v, want summary=%v verbose=%v", summary, verbose, tt.wantSummary, tt.wantVerbose)
			}
		})
	}
}
