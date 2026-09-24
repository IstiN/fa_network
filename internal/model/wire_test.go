package model

import "testing"

// DedupeMentions behavior (model coverage).
func TestDedupeMentionsWire(t *testing.T) {
	got := DedupeMentions([]string{" a ", "a", "", "  ", "b", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("dedupe = %v", got)
	}
}
