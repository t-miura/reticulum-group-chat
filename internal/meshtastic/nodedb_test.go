package meshtastic

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNodeDBPersistenceAndLabels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshnodes.json")
	db, err := NewNodeDB(path)
	if err != nil {
		t.Fatal(err)
	}

	// Unknown node falls back to M:!last4hex.
	if got := db.FormatSenderLabel(0x1234abcd, false); got != "M:!abcd" {
		t.Errorf("unknown label = %q, want M:!abcd", got)
	}

	now := time.Now().UTC().Truncate(time.Second)
	db.UpdateUser(0x1234abcd, "AL[C]", "Alice [Node]", now)
	if got := db.FormatSenderLabel(0x1234abcd, false); got != "M:AL_C_" {
		t.Errorf("short label = %q, want M:AL_C_", got)
	}
	if got := db.FormatSenderLabel(0x1234abcd, true); got != "M:Alice _Node_" {
		t.Errorf("long label = %q, want M:Alice _Node_", got)
	}

	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}

	// Reload from disk and verify node & ban state survive.
	if _, _, err := db.Ban("!1234"); err != nil {
		t.Fatalf("Ban prefix: %v", err)
	}
	reloaded, err := NewNodeDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.IsBanned(0x1234abcd) {
		t.Error("ban did not survive reload")
	}
	if got := reloaded.FormatSenderLabel(0x1234abcd, false); got != "M:AL_C_" {
		t.Errorf("reloaded label = %q, want M:AL_C_", got)
	}

	if _, ok, err := reloaded.Unban("!1234"); err != nil || !ok {
		t.Fatalf("Unban failed: ok=%v err=%v", ok, err)
	}
	if reloaded.IsBanned(0x1234abcd) {
		t.Error("node still banned after Unban")
	}
}

func TestSyntheticLXMFHashDeterministic(t *testing.T) {
	h1 := SyntheticLXMFHash(0xdeadbeef)
	h2 := SyntheticLXMFHash(0xdeadbeef)
	if len(h1) != 16 || string(h1) != string(h2) {
		t.Errorf("unexpected hash %x vs %x", h1, h2)
	}
	if !strings.HasPrefix(string(h1), "meshtastic\x00\x00") {
		t.Errorf("unexpected prefix %q", h1)
	}
}
