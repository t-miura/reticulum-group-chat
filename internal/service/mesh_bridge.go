package service

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/thatSFguy/reticulum-group-chat/internal/commands"
	"github.com/thatSFguy/reticulum-group-chat/internal/config"
	"github.com/thatSFguy/reticulum-group-chat/internal/history"
	"github.com/thatSFguy/reticulum-group-chat/internal/idmap"
	"github.com/thatSFguy/reticulum-group-chat/internal/meshtastic"
)

func meshNodesPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "meshnodes.json")
}

func (s *Service) initMeshtasticBridge() error {
	mCfg := s.cfg.Meshtastic
	bridgeID := mCfg.BridgeNodeID
	if mCfg.Mode != config.MeshtasticModeExternal && bridgeID == 0 {
		bridgeID = meshtastic.DeriveNodeID(s.identity.Hash())
	}
	mb, err := meshtastic.NewBridge(meshtastic.BridgeConfig{
		Mode:             mCfg.Mode,
		ChannelName:      mCfg.ChannelName,
		RawPSK:           mCfg.RawPSK,
		ExpandedKey:      mCfg.ExpandedKey,
		BridgeNodeID:     bridgeID,
		ShortName:        mCfg.ShortName,
		LongName:         mCfg.LongName,
		NodeInfoInterval: mCfg.NodeInfoInterval.Std(),
		HopLimit:         uint32(mCfg.HopLimit),
		OKToMQTT:         mCfg.OKToMQTT,
		LongNameFormat:   mCfg.NameFormat == "long",
		LongMessageMode:  mCfg.LongMessageMode,
		MaxChunks:        mCfg.MaxChunks,
		ChunkDelay:       mCfg.ChunkDelay.Std(),
		NodeDBPath:       meshNodesPath(s.cfg.Service.StatePath),
		UDPEnabled:       mCfg.UDP.Enabled,
		UDPAddr:          mCfg.UDP.Addr,
		UDPIface:         mCfg.UDP.Iface,
		MQTTEnabled:      mCfg.MQTT.Enabled,
		MQTTBroker:       mCfg.MQTT.Broker,
		MQTTUsername:     mCfg.MQTT.Username,
		MQTTPassword:     mCfg.MQTT.Password,
		MQTTRoot:         mCfg.MQTT.RootTopic,
		TCPAddr:          mCfg.TCP.Addr,
		TCPChannelIndex:  mCfg.TCP.ChannelIndex,
	}, s.onMeshReceived, s.logger)
	if err != nil {
		return err
	}
	s.mesh = mb
	s.dispatcher.MeshStatus = mb.StatusSummary
	s.dispatcher.MeshChannelName = mb.ChannelName
	s.dispatcher.MeshBan = func(spec string) (string, error) {
		_, label, err := mb.NodeDB().Ban(spec)
		return label, err
	}
	s.dispatcher.MeshUnban = func(spec string) (string, bool, error) {
		id, ok, err := mb.NodeDB().Unban(spec)
		if err != nil || !ok {
			return "", ok, err
		}
		return meshtastic.FormatNodeBang(id), true, nil
	}
	return nil
}

// onMeshReceived handles verified, decrypted broadcast messages arriving from
// the bridged Meshtastic channel and forwards them to the LXMF roster.
func (s *Service) onMeshReceived(msg meshtastic.InboundMessage) {
	if s.mesh == nil {
		return
	}
	now := s.now()
	content := sanitizeForward(strings.TrimRight(msg.Text, "\r\n"))

	// Tap-back reaction from Meshtastic -> native LXMF FIELD_REACTION (0x40).
	if msg.Emoji != 0 {
		s.handleMeshReaction(msg, content)
		return
	}

	// Ignore slash commands originating from Meshtastic so the shared RF
	// channel cannot invoke moderation or flood broadcast replies.
	if commands.IsCommand(content) {
		s.logger.Debugf("meshtastic: ignoring slash command from %s", meshtastic.FormatNodeBang(msg.From))
		return
	}

	if content == "" {
		return
	}
	if maxChars := s.cfg.Service.MaxInboundChars; maxChars > 0 && utf8.RuneCountInString(content) > maxChars {
		content = truncateRunesWithEllipsis(content, maxChars)
	}

	senderNick := s.mesh.FormatSenderLabel(msg.From)
	body := "[" + senderNick + "] " + content

	opts := forwardOpts{
		bubble: s.newBubbleForForward(),
	}
	if opts.bubble != nil && s.idmap != nil {
		opts.bubble.SetPreview(truncatePreview(body, 100))
		s.idmap.RegisterMeshID(opts.bubble, msg.PacketID)
	}

	var fwdFields map[any]any
	if msg.ReplyID != 0 && s.idmap != nil {
		if replyBubble := s.idmap.LookupMeshID(msg.ReplyID); replyBubble != nil {
			fwdFields = map[any]any{
				fieldReplyTo: make([]byte, 32),
			}
			if prev := replyBubble.Preview(); prev != "" {
				fwdFields[fieldReplyQuote] = []byte(prev)
			}
			opts.rewrite = func(recipientHex string, in map[any]any) (map[any]any, bool) {
				out := cloneFields(in)
				if rw, ok := substituteReplyHash(out, recipientHex, replyBubble); ok {
					return rw, true
				}
				return stripReplyHash(out), true
			}
		}
	}

	_ = s.forwardToRoster("", body, fwdFields, opts)
	_ = s.history.Append(history.Entry{
		At:         now,
		SenderHash: hex.EncodeToString(meshtastic.SyntheticLXMFHash(msg.From)),
		SenderNick: senderNick,
		Content:    content,
	})
}

func (s *Service) handleMeshReaction(msg meshtastic.InboundMessage, content string) {
	if msg.ReplyID == 0 || s.idmap == nil {
		return
	}
	targetBubble := s.idmap.LookupMeshID(msg.ReplyID)
	if targetBubble == nil {
		return
	}
	emojiStr := strings.TrimSpace(content)
	if emojiStr == "" && msg.Emoji > 1 {
		emojiStr = string(rune(msg.Emoji))
	}
	if emojiStr == "" {
		return
	}

	fwdFields := map[any]any{
		fieldReaction: map[any]any{
			targetIdx: make([]byte, 32),
			0x01:      []byte(emojiStr),
		},
	}
	stampReactorIdentity(fwdFields, meshtastic.SyntheticLXMFHash(msg.From))

	rewrite := func(recipientHex string, in map[any]any) (map[any]any, bool) {
		return substituteDictTarget(cloneFields(in), fieldReaction, recipientHex, targetBubble)
	}
	s.forwardToRoster("", "", fwdFields, forwardOpts{rewrite: rewrite})
}

// forwardToMeshtastic relays an LXMF group message, reply, attachment notice,
// or tap-back reaction onto the bridged Meshtastic channel.
func (s *Service) forwardToMeshtastic(content, senderNick, body string, fwdFields map[any]any, bubble *idmap.Bubble) bool {
	if s.mesh == nil {
		return false
	}

	if hasReactionField(fwdFields) {
		if s.idmap != nil {
			targetHex, emojiStr := extractReactionDetails(fwdFields)
			if targetHex != "" && emojiStr != "" {
				if tb := s.idmap.Lookup(targetHex); tb != nil {
					if meshID, ok := tb.PrimaryMeshID(); ok {
						if pktID := s.mesh.SendReaction(emojiStr, meshID); pktID != 0 {
							s.logger.Infof("meshtastic outbound reaction: from=%s target=0x%08x pkt_id=0x%08x", senderNick, meshID, pktID)
						}
					}
				}
			}
		}
		return false
	}

	var replyMeshID uint32
	if s.idmap != nil && len(fwdFields) > 0 {
		if targetHex := extractReplyTargetHex(fwdFields); targetHex != "" {
			if rb := s.idmap.Lookup(targetHex); rb != nil {
				if meshID, ok := rb.PrimaryMeshID(); ok {
					replyMeshID = meshID
				}
			}
		}
	}

	meshText := body
	if meshText == "" && isPrimaryBubble(content, fwdFields) {
		meshText = "[" + senderNick + "] [sent an attachment on LXMF]"
	}
	if meshText == "" {
		return false
	}

	ids := s.mesh.SendText(meshText, replyMeshID)
	if len(ids) > 0 {
		s.logger.Infof("meshtastic outbound text: from=%s chunks=%d pkt_id=0x%08x len=%d", senderNick, len(ids), ids[0], len(meshText))
	}
	if bubble != nil && s.idmap != nil {
		for _, id := range ids {
			s.idmap.RegisterMeshID(bubble, id)
		}
	}
	return len(ids) > 0
}

func extractReactionDetails(fields map[any]any) (targetHex, emoji string) {
	for k, v := range fields {
		ki, ok := keyAsInt(k)
		if !ok || ki != fieldReaction {
			continue
		}
		m, ok := v.(map[any]any)
		if !ok {
			continue
		}
		targetHex = extractDictTarget(m)
		for mk, mv := range m {
			ik, ok := keyAsInt(mk)
			if !ok || ik != 0x01 {
				continue
			}
			switch ev := mv.(type) {
			case []byte:
				emoji = string(ev)
			case string:
				emoji = ev
			}
		}
		return targetHex, emoji
	}
	return "", ""
}

func extractReplyTargetHex(fields map[any]any) string {
	for k, v := range fields {
		ki, ok := keyAsInt(k)
		if !ok {
			continue
		}
		switch ki {
		case fieldReplyTo:
			if raw, ok := asHashBytes(v); ok {
				return hex.EncodeToString(raw)
			}
		case fieldComment, fieldContinuation:
			if h := extractDictTarget(v); h != "" {
				return h
			}
		}
	}
	return ""
}

func truncateRunesWithEllipsis(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	count := 0
	cutAt := len(s)
	for i := range s {
		if maxRunes == 1 && count == 1 {
			return s[:i]
		}
		if count == maxRunes-1 {
			cutAt = i
		}
		if count == maxRunes {
			return s[:cutAt] + "…"
		}
		count++
	}
	return s
}

func truncatePreview(s string, maxBytes int) string {
	return meshtastic.TruncateUTF8(s, maxBytes)
}
