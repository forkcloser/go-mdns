package transport

import (
	"strings"
	"syscall"
)

// The options that have the system say where a packet came in, and the
// kinds of what it then says. The IPv6 ones are RFC 3542's, which the
// syscall package does not name here.
const (
	optPacketInfo4  = syscall.IP_RECVPKTINFO
	optPacketInfo6  = 0x3d
	cmsgPacketInfo4 = syscall.IP_PKTINFO
	cmsgPacketInfo6 = 0x2e
)

// share lets other programs have the port too: the system's own
// responder, and any other of this kind. Here that takes both the
// address and the port said to be reused.
func share(handle uintptr) error {
	for _, option := range []int{syscall.SO_REUSEADDR, syscall.SO_REUSEPORT} {
		if err := setInt(handle, syscall.SOL_SOCKET, option, 1); err != nil {
			return err
		}
	}

	return nil
}

// skipped says whether an interface is one Multicast DNS is not spoken
// on, by its name: Apple's wireless direct links, which a packet sent
// to wakes up, and which the system's own responder handles its own
// way.
func skipped(name string) bool {
	return strings.HasPrefix(name, "awdl") || strings.HasPrefix(name, "llw")
}
