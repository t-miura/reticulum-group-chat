package meshtastic

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSplitMessageShortPassthrough(t *testing.T) {
	got := SplitMessage("hello world", "chunk", 3, MaxMeshPayloadBytes)
	if len(got) != 1 || got[0] != "hello world" {
		t.Errorf("got %q, want single unmodified message", got)
	}
}

func TestSplitMessageTruncateModeUTF8Safe(t *testing.T) {
	// Multi-byte Japanese + emoji string exceeding 30 bytes.
	text := strings.Repeat("あ", 20) + "🚀"
	got := SplitMessage(text, "truncate", 3, 30)
	if len(got) != 1 {
		t.Fatalf("truncate returned %d parts, want 1", len(got))
	}
	if len(got[0]) > 30 {
		t.Errorf("truncated len = %d > 30", len(got[0]))
	}
	if !utf8.ValidString(got[0]) {
		t.Errorf("truncated string is invalid UTF-8: %x", got[0])
	}
	if !strings.HasSuffix(got[0], "…") {
		t.Errorf("expected ellipsis suffix, got %q", got[0])
	}
}

func TestSplitMessageChunksWordAndRuneSafe(t *testing.T) {
	words := strings.Repeat("alpha beta gamma delta ", 15) // ~345 bytes
	got := SplitMessage(strings.TrimSpace(words), "chunk", 3, 150)
	if len(got) != 3 {
		t.Fatalf("got %d chunks, want 3: %v", len(got), got)
	}
	for i, c := range got {
		if len(c) > 150 {
			t.Errorf("chunk %d len=%d > 150", i, len(c))
		}
		if !utf8.ValidString(c) {
			t.Errorf("chunk %d invalid UTF-8", i)
		}
		wantSuffix := []string{"(1/3)", "(2/3)", "(3/3)"}[i]
		if !strings.HasSuffix(c, wantSuffix) {
			t.Errorf("chunk %d = %q missing suffix %q", i, c, wantSuffix)
		}
	}

	// Overflow past max_chunks truncates final chunk cleanly.
	huge := strings.Repeat("👍", 100) // 400 bytes
	gotHuge := SplitMessage(huge, "chunk", 2, 100)
	if len(gotHuge) != 2 {
		t.Fatalf("got %d chunks for overflow, want 2", len(gotHuge))
	}
	for i, c := range gotHuge {
		if len(c) > 100 || !utf8.ValidString(c) {
			t.Errorf("overflow chunk %d len=%d valid=%v", i, len(c), utf8.ValidString(c))
		}
	}
	if !strings.Contains(gotHuge[1], "… (2/2)") {
		t.Errorf("final overflow chunk = %q, want truncation marker", gotHuge[1])
	}
}
