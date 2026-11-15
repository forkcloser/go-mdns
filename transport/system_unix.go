//go:build linux || darwin

package transport

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
)

// controlSize is room for what the system says of a packet.
const controlSize = 128

func setInt(handle uintptr, level, option, value int) error {
	if err := syscall.SetsockoptInt(int(handle), level, option, value); err != nil { // #nosec G115 -- a descriptor
		return fmt.Errorf("setting socket option %d: %w", option, err)
	}

	return nil
}

func setAddr4(handle uintptr, level, option int, addr [4]byte) error {
	if err := syscall.SetsockoptInet4Addr(int(handle), level, option, addr); err != nil { // #nosec G115 -- a descriptor
		return fmt.Errorf("setting socket option %d: %w", option, err)
	}

	return nil
}

func setMember4(handle uintptr, option int, member *syscall.IPMreq) error {
	if err := syscall.SetsockoptIPMreq(
		int(handle),
		syscall.IPPROTO_IP,
		option,
		member,
	); err != nil { // #nosec G115 -- a descriptor
		return fmt.Errorf("setting socket option %d: %w", option, err)
	}

	return nil
}

func setMember6(handle uintptr, option int, member *syscall.IPv6Mreq) error {
	if err := syscall.SetsockoptIPv6Mreq(
		int(handle),
		syscall.IPPROTO_IPV6,
		option,
		member,
	); err != nil { // #nosec G115 -- a descriptor
		return fmt.Errorf("setting socket option %d: %w", option, err)
	}

	return nil
}

// What the system says of an IPv4 packet: the interface, an address of
// it, and the address the packet was sent to. Of an IPv6 one: the
// address it was sent to, and the interface.
const (
	info4Size  = 12
	info4Dest  = 8
	info6Size  = 20
	info6Index = 16
)

// arrival is the interface a packet came in on and the address it was
// sent to, from what the system says of it.
func arrival(family Family, oob []byte) (int, netip.Addr, bool) {
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, netip.Addr{}, false
	}

	for _, message := range messages {
		switch {
		case family == IPv4 && message.Header.Level == syscall.IPPROTO_IP && message.Header.Type == cmsgPacketInfo4 && len(message.Data) >= info4Size:
			dest, _ := netip.AddrFromSlice(message.Data[info4Dest:info4Size])

			return int(binary.NativeEndian.Uint32(message.Data)), dest, true
		case family == IPv6 && message.Header.Level == syscall.IPPROTO_IPV6 && message.Header.Type == cmsgPacketInfo6 && len(message.Data) >= info6Size:
			dest, _ := netip.AddrFromSlice(message.Data[:info6Index])

			return int(binary.NativeEndian.Uint32(message.Data[info6Index:])), dest, true
		}
	}

	return 0, netip.Addr{}, false
}
