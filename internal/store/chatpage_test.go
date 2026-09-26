package store

import (
	"fmt"
	"testing"

	"github.com/IstiN/fa_network/internal/model"
)

// buildChatPage trims the DESC lookahead row and reverses into ascending
// chat order; the cursor is the oldest returned item's seq.
func TestBuildChatPage(t *testing.T) {
	mk := func(id string) model.Envelope { return model.Envelope{ID: id} }
	newest := []model.Envelope{mk("e4"), mk("e3"), mk("e2"), mk("e1")}
	seqs := []int64{5, 4, 3, 2}

	page := buildChatPage(newest, seqs, 3)
	if fmt.Sprint(idSlice(page.Items)) != "[e2 e3 e4]" {
		t.Fatalf("items = %v, want [e2 e3 e4]", idSlice(page.Items))
	}
	if page.NextCursor != "3" {
		t.Fatalf("cursor = %q, want 3 (oldest returned seq)", page.NextCursor)
	}

	// Last page: no lookahead row, no cursor.
	last := buildChatPage(newest[:1], seqs[:1], 3)
	if len(last.Items) != 1 || last.NextCursor != "" {
		t.Fatalf("last page = %+v, want 1 item no cursor", last)
	}
	// Exact fit: lookahead absent → no cursor.
	fit := buildChatPage(newest[:3], seqs[:3], 3)
	if fit.NextCursor != "" {
		t.Fatalf("exact-fit cursor = %q, want empty", fit.NextCursor)
	}
}

func idSlice(items []model.Envelope) []string {
	out := make([]string, 0, len(items))
	for _, e := range items {
		out = append(out, e.ID)
	}
	return out
}
