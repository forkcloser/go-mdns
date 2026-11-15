package transport

import "syscall"

// The options that have the system say where a packet came in, and the
// kinds of what it then says.
const (
	optPacketInfo4  = syscall.IP_PKTINFO
	optPacketInfo6  = syscall.IPV6_RECVPKTINFO
	cmsgPacketInfo4 = syscall.IP_PKTINFO
	cmsgPacketInfo6 = syscall.IPV6_PKTINFO
)

// share lets other programs have the port too: the system's own
// responder, and any other of this kind. For a datagram socket here,
// reusing the address is what that takes.
func share(handle uintptr) error {
	return setInt(handle, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

// skipped says whether an interface is one Multicast DNS is not spoken
// on, by its name. There is none here.
func skipped(string) bool { return false }
