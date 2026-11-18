//go:build unix

package meshtastic

import (
	"net"
	"syscall"
)

func joinMulticastGroup(conn *net.UDPConn, ifi *net.Interface, groupIP net.IP) error {
	ip4 := groupIP.To4()
	if ip4 == nil {
		return nil
	}
	ifIP := firstUsableIPv4(ifi)
	if ifIP == nil {
		return nil
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := rc.Control(func(fd uintptr) {
		var mreq syscall.IPMreq
		copy(mreq.Multiaddr[:], ip4)
		copy(mreq.Interface[:], ifIP.To4())
		sockErr = syscall.SetsockoptIPMreq(int(fd), syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, &mreq)
	}); err != nil {
		return err
	}
	return sockErr
}

func configureMulticastSender(conn *net.UDPConn, ifIP net.IP) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var firstErr error
	if err := rc.Control(func(fd uintptr) {
		// Match Meshtastic firmware's multicast TTL (64) instead of OS default 1
		// so LAN routers, bridges, or wireless APs do not drop packets at hop 1.
		if serr := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, udpMulticastTTL); serr != nil {
			firstErr = serr
		}
		if serr := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1); serr != nil && firstErr == nil {
			firstErr = serr
		}
		if ip4 := ifIP.To4(); ip4 != nil {
			var addr [4]byte
			copy(addr[:], ip4)
			if serr := syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, addr); serr != nil && firstErr == nil {
				firstErr = serr
			}
		}
	}); err != nil {
		return err
	}
	return firstErr
}
