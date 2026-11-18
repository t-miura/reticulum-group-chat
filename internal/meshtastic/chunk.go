package meshtastic

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxMeshPayloadBytes leaves safe headroom below Meshtastic's 233-byte
// DATA_PAYLOAD_LEN limit for UTF-8 chat text and chunk suffixes.
const MaxMeshPayloadBytes = 220

// SplitMessage prepares text for Meshtastic transmission under maxBytes per
// packet. In "truncate" mode (or maxChunks <= 1), text exceeding maxBytes is
// rune-truncated with an ellipsis. In "chunk" mode, text is split across at
// most maxChunks rune-aligned segments with " (i/N)" suffixes, truncating the
// final segment with "…" if the message still exceeds maxChunks.
func SplitMessage(text, mode string, maxChunks, maxBytes int) []string {
	if text == "" {
		return nil
	}
	if maxBytes <= 0 {
		maxBytes = MaxMeshPayloadBytes
	}
	if len(text) <= maxBytes {
		return []string{text}
	}
	if strings.EqualFold(mode, "truncate") || maxChunks <= 1 {
		return []string{truncateUTF8(text, maxBytes, true)}
	}

	suffixReserve := len(fmt.Sprintf(" (%d/%d)", maxChunks, maxChunks))
	bodyBudget := maxBytes - suffixReserve
	if bodyBudget < 16 {
		// Degenerate tiny limit: fall back to plain truncation.
		return []string{truncateUTF8(text, maxBytes, true)}
	}

	var parts []string
	rest := text
	for len(rest) > 0 {
		if len(parts) == maxChunks-1 {
			if len(rest) <= bodyBudget {
				parts = append(parts, rest)
			} else {
				parts = append(parts, truncateUTF8(rest, bodyBudget, true))
			}
			break
		}
		if len(rest) <= bodyBudget {
			parts = append(parts, rest)
			break
		}
		splitAt, skipSpace := findChunkSplit(rest, bodyBudget)
		parts = append(parts, rest[:splitAt])
		rest = rest[splitAt:]
		if skipSpace && len(rest) > 0 && rest[0] == ' ' {
			rest = rest[1:]
		}
	}

	if len(parts) <= 1 {
		return parts
	}
	total := len(parts)
	out := make([]string, total)
	for i, p := range parts {
		out[i] = fmt.Sprintf("%s (%d/%d)", p, i+1, total)
	}
	return out
}

// findChunkSplit finds a UTF-8 rune boundary <= limit, preferring the last space
// in the second half of the budget so words stay intact where practical.
func findChunkSplit(s string, limit int) (splitAt int, skipSpace bool) {
	if len(s) <= limit {
		return len(s), false
	}
	lastRuneEnd := 0
	lastSpace := -1
	half := limit / 2
	for idx, r := range s {
		runeLen := utf8.RuneLen(r)
		if runeLen < 0 {
			runeLen = 1
		}
		end := idx + runeLen
		if end > limit {
			break
		}
		lastRuneEnd = end
		if r == ' ' && idx >= half {
			lastSpace = idx
		}
	}
	if lastSpace > 0 {
		return lastSpace, true
	}
	if lastRuneEnd == 0 {
		// Ensure progress even if limit < first rune size.
		_, size := utf8.DecodeRuneInString(s)
		return size, false
	}
	return lastRuneEnd, false
}

// TruncateUTF8 shortens s to at most maxBytes on a UTF-8 rune boundary,
// appending "…" when truncated.
func TruncateUTF8(s string, maxBytes int) string {
	return truncateUTF8(s, maxBytes, true)
}

func truncateUTF8(s string, maxBytes int, withEllipsis bool) string {
	if len(s) <= maxBytes {
		return s
	}
	const ellipsis = "…"
	budget := maxBytes
	if withEllipsis && maxBytes >= len(ellipsis) {
		budget -= len(ellipsis)
	} else {
		withEllipsis = false
	}
	end := 0
	for idx, r := range s {
		rl := utf8.RuneLen(r)
		if rl < 0 {
			rl = 1
		}
		if idx+rl > budget {
			break
		}
		end = idx + rl
	}
	if withEllipsis {
		return s[:end] + ellipsis
	}
	return s[:end]
}
