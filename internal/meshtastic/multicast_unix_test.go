//go:build unix

package meshtastic

import (
	"net"
	"syscall"
	"testing"
)

func TestConfigureMulticastSenderSetsTTLAndLoop(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	if err := configureMulticastSender(conn, nil); err != nil {
		t.Fatalf("configureMulticastSender: %v", err)
	}

	rc, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var (
		gotTTL  int
		gotLoop int
		optErr  error
	)
	if err := rc.Control(func(fd uintptr) {
		gotTTL, optErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL)
		if optErr != nil {
			return
		}
		gotLoop, optErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if optErr != nil {
		t.Fatalf("GetsockoptInt: %v", optErr)
	}
	if gotTTL != udpMulticastTTL {
		t.Errorf("IP_MULTICAST_TTL = %d, want %d", gotTTL, udpMulticastTTL)
	}
	if gotLoop != 1 {
		t.Errorf("IP_MULTICAST_LOOP = %d, want 1", gotLoop)
	}
}
