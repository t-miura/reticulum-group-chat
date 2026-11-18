package meshtastic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/thatSFguy/reticulum-group-chat/internal/logging"
)

// DefaultUDPAddr is Meshtastic's standard LAN multicast address and port.
const DefaultUDPAddr = "239.0.0.69:4403"

// UDPTransport sends and receives raw Meshtastic MeshPacket protobuf datagrams
// over UDP multicast (or unicast UDP in tests).
type UDPTransport struct {
	addr      string
	ifaceName string
	target    string // optional override destination for Send (tests)
	logger    *logging.Logger

	// openConns, when set (tests), overrides OS UDP socket creation.
	openConns func() (recv net.PacketConn, send net.PacketConn, dst net.Addr, err error)

	mu             sync.Mutex
	recvConn       net.PacketConn
	sendConn       net.PacketConn
	extraSendConns []net.PacketConn
	dstAddr        net.Addr
	readyCh        chan struct{}
	closed         bool
}

// NewUDPTransport constructs a UDPTransport targeting addr (e.g. "239.0.0.69:4403").
// ifaceName optionally pins multicast membership and outbound packets to a specific interface.
func NewUDPTransport(addr, ifaceName string, logger *logging.Logger) *UDPTransport {
	if addr == "" {
		addr = DefaultUDPAddr
	}
	return &UDPTransport{
		addr:      addr,
		ifaceName: ifaceName,
		logger:    logger,
		readyCh:   make(chan struct{}),
	}
}

func (u *UDPTransport) Name() string { return "udp" }

// LocalAddr returns the bound receive address once Run has opened the socket, or nil.
func (u *UDPTransport) LocalAddr() net.Addr {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.recvConn == nil {
		return nil
	}
	return u.recvConn.LocalAddr()
}

// Ready returns a channel closed once the UDP socket has bound.
func (u *UDPTransport) Ready() <-chan struct{} {
	return u.readyCh
}

// Run opens the UDP socket and reads MeshPacket datagrams until ctx is cancelled.
func (u *UDPTransport) Run(ctx context.Context, onPacket func(*MeshPacket)) error {
	var (
		recvConn       net.PacketConn
		sendConn       net.PacketConn
		extraSendConns []net.PacketConn
		dstAddr        net.Addr
		err            error
	)
	if u.openConns != nil {
		recvConn, sendConn, dstAddr, err = u.openConns()
	} else {
		recvConn, sendConn, extraSendConns, dstAddr, err = u.openOSConns()
	}
	if err != nil {
		return err
	}

	u.mu.Lock()
	u.recvConn = recvConn
	u.sendConn = sendConn
	u.extraSendConns = extraSendConns
	u.dstAddr = dstAddr
	select {
	case <-u.readyCh:
	default:
		close(u.readyCh)
	}
	u.mu.Unlock()

	if u.logger != nil {
		u.logger.Infof("meshtastic udp listening on %s (send target %s)", recvConn.LocalAddr(), dstAddr)
	}

	go func() {
		<-ctx.Done()
		u.mu.Lock()
		u.closed = true
		_ = recvConn.Close()
		_ = sendConn.Close()
		for _, ec := range extraSendConns {
			_ = ec.Close()
		}
		u.mu.Unlock()
	}()

	buf := make([]byte, 2048)
	for {
		n, _, rerr := recvConn.ReadFrom(buf)
		if rerr != nil {
			if ctx.Err() != nil || errors.Is(rerr, net.ErrClosed) {
				return nil
			}
			if u.logger != nil {
				u.logger.Warnf("meshtastic udp read: %v", rerr)
			}
			continue
		}
		if n == 0 {
			continue
		}
		pkt, uerr := UnmarshalMeshPacket(buf[:n])
		if uerr != nil {
			if u.logger != nil {
				u.logger.Debugf("meshtastic udp malformed packet (%d B): %v", n, uerr)
			}
			continue
		}
		if onPacket != nil {
			onPacket(pkt)
		}
	}
}

func (u *UDPTransport) openOSConns() (net.PacketConn, net.PacketConn, []net.PacketConn, net.Addr, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", u.addr)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("meshtastic udp resolve %q: %w", u.addr, err)
	}

	isMulticast := udpAddr.IP != nil && udpAddr.IP.IsMulticast()
	var (
		primary *net.Interface
		allIFs  []net.Interface
	)
	if isMulticast {
		primary, allIFs, err = selectMulticastInterfaces(u.ifaceName)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else if u.ifaceName != "" {
		ifi, ierr := net.InterfaceByName(u.ifaceName)
		if ierr != nil {
			return nil, nil, nil, nil, fmt.Errorf("meshtastic udp interface %q: %w", u.ifaceName, ierr)
		}
		primary = ifi
	}

	var recvConn *net.UDPConn
	if isMulticast {
		recvConn, err = net.ListenMulticastUDP("udp4", primary, udpAddr)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("meshtastic udp listen multicast %s: %w", u.addr, err)
		}
		for i := 1; i < len(allIFs); i++ {
			if jerr := joinMulticastGroup(recvConn, &allIFs[i], udpAddr.IP); jerr != nil && u.logger != nil {
				u.logger.Debugf("meshtastic udp join %s on %s: %v", udpAddr.IP, allIFs[i].Name, jerr)
			}
		}
	} else {
		recvConn, err = net.ListenUDP("udp4", udpAddr)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("meshtastic udp listen %s: %w", u.addr, err)
		}
	}

	var primaryIP net.IP
	sendLocal := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if primary != nil {
		if ip := firstUsableIPv4(primary); ip != nil {
			primaryIP = ip
			sendLocal = &net.UDPAddr{IP: ip, Port: 0}
		}
	}
	sendConn, err := net.ListenUDP("udp4", sendLocal)
	if err != nil {
		_ = recvConn.Close()
		return nil, nil, nil, nil, fmt.Errorf("meshtastic udp open sender: %w", err)
	}
	if isMulticast {
		configureMulticastSender(sendConn, primaryIP)
	}

	var extraSendConns []net.PacketConn
	var extraNames []string
	if isMulticast && len(allIFs) > 1 {
		seenIPs := make(map[string]struct{})
		if primaryIP != nil {
			seenIPs[primaryIP.String()] = struct{}{}
		}
		for i := 1; i < len(allIFs); i++ {
			ip := firstUsableIPv4(&allIFs[i])
			if ip == nil {
				continue
			}
			key := ip.String()
			if _, exists := seenIPs[key]; exists {
				continue
			}
			ec, eerr := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})
			if eerr != nil {
				if u.logger != nil {
					u.logger.Debugf("meshtastic udp open extra sender on %s (%v): %v", allIFs[i].Name, ip, eerr)
				}
				continue
			}
			configureMulticastSender(ec, ip)
			extraSendConns = append(extraSendConns, ec)
			extraNames = append(extraNames, fmt.Sprintf("%s(%v)", allIFs[i].Name, ip))
			seenIPs[key] = struct{}{}
		}
	}

	if u.logger != nil && isMulticast {
		if primary != nil {
			names := make([]string, len(allIFs))
			for i := range allIFs {
				names[i] = allIFs[i].Name
			}
			u.logger.Infof("meshtastic udp multicast interface: primary=%s (%v) joined=%v extra_tx=%v",
				primary.Name, primaryIP, names, extraNames)
		} else {
			u.logger.Warnf("meshtastic udp multicast: no non-loopback IPv4 interface found, using OS default")
		}
	}

	dstAddr := udpAddr
	if u.target != "" {
		tAddr, rerr := net.ResolveUDPAddr("udp4", u.target)
		if rerr != nil {
			_ = recvConn.Close()
			_ = sendConn.Close()
			for _, ec := range extraSendConns {
				_ = ec.Close()
			}
			return nil, nil, nil, nil, fmt.Errorf("meshtastic udp resolve target %q: %w", u.target, rerr)
		}
		dstAddr = tAddr
	} else if udpAddr.Port == 0 {
		if la, ok := recvConn.LocalAddr().(*net.UDPAddr); ok {
			dstAddr = la
		}
	}
	return recvConn, sendConn, extraSendConns, dstAddr, nil
}

// Send marshals pkt and writes it to the configured UDP destination.
func (u *UDPTransport) Send(_ context.Context, pkt *MeshPacket) error {
	if pkt == nil {
		return nil
	}
	u.mu.Lock()
	sendConn := u.sendConn
	extra := append([]net.PacketConn(nil), u.extraSendConns...)
	dstAddr := u.dstAddr
	closed := u.closed
	u.mu.Unlock()

	if closed || sendConn == nil || dstAddr == nil {
		return fmt.Errorf("meshtastic udp transport not running")
	}
	raw := pkt.Marshal()
	var firstErr error
	sentAny := false
	if _, err := sendConn.WriteTo(raw, dstAddr); err != nil {
		firstErr = fmt.Errorf("meshtastic udp write: %w", err)
	} else {
		sentAny = true
	}
	for _, ec := range extra {
		if _, err := ec.WriteTo(raw, dstAddr); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("meshtastic udp write: %w", err)
			}
		} else {
			sentAny = true
		}
	}
	if !sentAny && firstErr != nil {
		return firstErr
	}
	return nil
}

type multicastCandidate struct {
	iface net.Interface
	ip4   net.IP
}

func selectMulticastInterfaces(preferred string) (*net.Interface, []net.Interface, error) {
	if preferred != "" {
		ifi, err := net.InterfaceByName(preferred)
		if err != nil {
			return nil, nil, fmt.Errorf("meshtastic udp interface %q: %w", preferred, err)
		}
		return ifi, []net.Interface{*ifi}, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("meshtastic udp list interfaces: %w", err)
	}
	var cands []multicastCandidate
	for _, ifi := range ifaces {
		if ifi.Flags&(net.FlagUp|net.FlagMulticast) != (net.FlagUp | net.FlagMulticast) {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		ip4 := firstUsableIPv4(&ifi)
		if ip4 == nil {
			continue
		}
		cands = append(cands, multicastCandidate{iface: ifi, ip4: ip4})
	}
	return rankMulticastCandidates(cands)
}

func rankMulticastCandidates(cands []multicastCandidate) (*net.Interface, []net.Interface, error) {
	if len(cands) == 0 {
		return nil, nil, nil
	}
	sort.SliceStable(cands, func(i, j int) bool {
		pi := multicastInterfaceRank(cands[i].iface.Name)
		pj := multicastInterfaceRank(cands[j].iface.Name)
		if pi != pj {
			return pi < pj
		}
		return cands[i].iface.Index < cands[j].iface.Index
	})
	primary := cands[0].iface
	all := make([]net.Interface, len(cands))
	for i := range cands {
		all[i] = cands[i].iface
	}
	return &primary, all, nil
}

func multicastInterfaceRank(name string) int {
	lower := strings.ToLower(name)
	for _, p := range []string{"awdl", "llw", "anpi", "ap", "bridge", "docker", "br-", "veth", "virbr", "utun", "tun", "tap", "gif", "stf"} {
		if strings.HasPrefix(lower, p) {
			return 2
		}
	}
	for _, p := range []string{"en", "eth", "wlan", "wl"} {
		if strings.HasPrefix(lower, p) {
			return 0
		}
	}
	return 1
}

func firstUsableIPv4(ifi *net.Interface) net.IP {
	if ifi == nil {
		return nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
			continue
		}
		return ip4
	}
	return nil
}
