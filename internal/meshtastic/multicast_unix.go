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

func configureMulticastSender(conn *net.UDPConn, ifIP net.IP) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1)
		if ip4 := ifIP.To4(); ip4 != nil {
			var addr [4]byte
			copy(addr[:], ip4)
			_ = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, addr)
		}
	})
}
