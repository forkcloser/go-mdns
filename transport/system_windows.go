package transport

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

// controlSize is room for what the system says of a packet.
const controlSize = 128

// The option that has the system say where a packet came in, which is
// also the kind of what it then says, for both families.
const (
	optPacketInfo4  = 19
	optPacketInfo6  = 19
	cmsgPacketInfo4 = 19
	cmsgPacketInfo6 = 19
)

// skipped says whether an interface is one Multicast DNS is not spoken
// on, by its name. There is none here.
func skipped(string) bool { return false }

// share lets other programs have the port too.
func share(handle uintptr) error {
	return setInt(handle, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

func setInt(handle uintptr, level, option, value int) error {
	if err := syscall.SetsockoptInt(syscall.Handle(handle), level, option, value); err != nil {
		return fmt.Errorf("setting socket option %d: %w", option, err)
	}

	return nil
}

func setAddr4(handle uintptr, level, option int, addr [4]byte) error {
	if err := syscall.SetsockoptInet4Addr(syscall.Handle(handle), level, option, addr); err != nil {
		return fmt.Errorf("setting socket option %d: %w", option, err)
	}

	return nil
}

func setMember4(handle uintptr, option int, member *syscall.IPMreq) error {
	if err := syscall.SetsockoptIPMreq(syscall.Handle(handle), syscall.IPPROTO_IP, option, member); err != nil {
		return fmt.Errorf("setting socket option %d: %w", option, err)
	}

	return nil
}

func setMember6(handle uintptr, option int, member *syscall.IPv6Mreq) error {
	if err := syscall.SetsockoptIPv6Mreq(syscall.Handle(handle), syscall.IPPROTO_IPV6, option, member); err != nil {
		return fmt.Errorf("setting socket option %d: %w", option, err)
	}

	return nil
}

// What the system says of a packet is a header, a length the size of a
// pointer and then a level and a kind, and after it, where a pointer
// would be aligned, the address the packet was sent to and the
// interface: four bytes of address for IPv4, sixteen for IPv6.
const (
	word       = int(unsafe.Sizeof(uintptr(0)))
	headerSize = word + 8
	addr4Size  = 4
	addr6Size  = 16
	indexSize  = 4
)

// arrival is the interface a packet came in on and the address it was
// sent to, from what the system says of it.
func arrival(family Family, oob []byte) (int, netip.Addr, bool) {
	level, kind, size := uint32(syscall.IPPROTO_IP), uint32(cmsgPacketInfo4), addr4Size
	if family == IPv6 {
		level, kind, size = syscall.IPPROTO_IPV6, cmsgPacketInfo6, addr6Size
	}

	for len(oob) >= headerSize {
		length := int(
			binary.NativeEndian.Uint64(append(oob[:word:word], make([]byte, 8-word)...)),
		) // #nosec G115 -- a length within oob, checked below
		if length < headerSize || length > len(oob) {
			return 0, netip.Addr{}, false
		}

		data := oob[headerSize:length]

		if binary.NativeEndian.Uint32(oob[word:]) == level && binary.NativeEndian.Uint32(oob[word+4:]) == kind &&
			len(data) >= size+indexSize {
			dest, _ := netip.AddrFromSlice(data[:size])

			return int(binary.NativeEndian.Uint32(data[size:])), dest, true
		}

		// The next begins where a pointer would be aligned.
		oob = oob[min(len(oob), (length+word-1)/word*word):]
	}

	return 0, netip.Addr{}, false
}
