// Package transport is where a peer's packets go and come from: the
// links of a host, one for each of its interfaces and each of IPv4 and
// IPv6, and nothing above them. Package mdns speaks the protocol over
// whatever Network it is given; System is the host's own, and a program
// that has a network stack of its own, in user space or in a test,
// brings another.
//
// A Link is the answer to the one question the protocol cannot do
// without: which interface did this packet come in on, and which does
// that one go out on. A packet read from a link came in on it; a packet
// written to a link goes out on it. How that is had is the Network's
// affair, and is not the same on every system.
package transport

import (
	"context"
	"net/netip"

	"github.com/forkcloser/go-mdns/internal/todo"
)

// Family is IPv4 or IPv6.
type Family uint8

// The families. As a set, in a configuration, none is both.
const (
	IPv4 Family = 1 << iota
	IPv6
)

// Interface names a network interface of the host, as the host does.
type Interface struct {
	// Index is the host's number for it, above zero.
	Index int
	// Name is the host's name for it: "en0", "eth0".
	Name string
}

// Port is the port Multicast DNS is spoken on.
const Port = 5353

// Group is the group Multicast DNS is spoken to, for a family:
// 224.0.0.251 for IPv4, ff02::fb for IPv6. For anything but one of the
// two it is the zero address.
func Group(family Family) netip.Addr {
	switch family {
	case IPv4:
		return netip.MustParseAddr("224.0.0.251")
	case IPv6:
		return netip.MustParseAddr("ff02::fb")
	default:
		return netip.Addr{}
	}
}

// MaxPacket is the largest packet Multicast DNS allows, its IP and UDP
// headers included (RFC 6762, section 17). A buffer of this size holds
// any message there is to read. What may be sent is less: the headers
// are part of it, and a message of more than one record keeps to the
// link's MTU.
const MaxPacket = 9000

// Network is a host's links, as they come and go.
type Network interface {
	// Watch tells handle first every link there is, each as up, and then
	// every link that comes up, changes its addresses or goes down, for
	// as long as ctx lasts. Events come one at a time. It returns ctx's
	// error when ctx ends, or sooner with why the links can no longer be
	// told of.
	Watch(ctx context.Context, handle func(Event)) error
}

// Event is a link come up, changed or gone down.
type Event struct {
	// Link is the link. Once it is told of as down it has been closed.
	Link Link
	// Change is what happened to it.
	Change Change
}

// Change is what happened to a link.
type Change uint8

// The changes.
const (
	// Up: the link is there, and can be read and written.
	Up Change = iota + 1
	// Changed: its addresses are no longer what they were.
	Changed
	// Down: the link is gone.
	Down
)

// Link is one interface of the host, for one family: where Multicast DNS
// is heard and said on it. Its methods may be called from several
// goroutines.
//
//nolint:interfacebloat // what a link is, where it is and what it does: none of the eight is another's
type Link interface {
	// Interface is the interface the link is on.
	Interface() Interface
	// Family is the family it carries: one of IPv4 and IPv6.
	Family() Family
	// Addrs is the interface's addresses of that family, each with the
	// prefix it is on: what the host can be reached at on this link, and
	// what tells a neighbour from a stranger. A prefix holds no zone:
	// that of an IPv6 link-local address is the link's own interface.
	Addrs() []netip.Prefix
	// MTU is the largest IP packet the interface carries whole, headers
	// included: what a message of more than one record has to fit in.
	MTU() int
	// Read waits for the next packet sent to port 5353 on this link and
	// copies it into p, which holds MaxPacket bytes. It says who sent
	// it, and from which port; and whether it was sent to the group or
	// to this host alone. After Close it returns an error.
	Read(p []byte) (n int, from netip.AddrPort, group bool, err error)
	// Multicast sends p to the family's group, on this link, from port
	// 5353, with an IP TTL or hop limit of 255: older listeners drop
	// anything else.
	Multicast(p []byte) error
	// Unicast sends p to one address and port on this link, from port
	// 5353, with an IP TTL or hop limit of 255.
	Unicast(p []byte, to netip.AddrPort) error
	// Close gives the link up. A Read under way returns.
	Close() error
}

// System is the host's own network: every interface that is up and
// carries multicast, the loopback aside, for each family it has an
// address of. It shares port 5353 with the system's own responder, when
// there is one.
func System() Network {
	_ = todo.ImplementMe()

	return nil
}
