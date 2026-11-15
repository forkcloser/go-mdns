// Package mdnstest is a network for tests of code that speaks Multicast
// DNS: hosts and the wires between them, in the test's process, on which
// peers find each other as they would on a real one, and on which a test
// can cut a wire and pull a plug.
//
// With testing/synctest, a test of several seconds of protocol, a probe
// or a record running out, takes no time at all.
package mdnstest

import (
	"context"
	"net/netip"

	"github.com/forkcloser/go-mdns/internal/todo"
	"github.com/forkcloser/go-mdns/transport"
)

// Network is wires, and the hosts on them. The zero Network is empty and
// ready.
type Network struct{}

// Port is one interface of a host, on a wire.
type Port struct {
	// Interface is the host's name for it: "en0".
	Interface string
	// Wire is the wire it is on: hosts on the same wire hear each other.
	Wire string
	// Addrs is the interface's addresses, each with its prefix. Empty is
	// one IPv4 and one IPv6 link-local address of the network's making.
	Addrs []netip.Prefix
	// MTU is the largest packet it carries. Zero is 1500.
	MTU int
}

// Host puts a host on the network, with the interfaces given, and
// returns its network: what a Peer is opened with.
func (n *Network) Host(ports ...Port) *Host {
	_ = todo.ImplementMe(n, ports)

	return nil
}

// Cut cuts a wire: nothing sent on it arrives, until Mend.
func (n *Network) Cut(wire string) {
	_ = todo.ImplementMe(n, wire)
}

// Mend mends a wire that was cut.
func (n *Network) Mend(wire string) {
	_ = todo.ImplementMe(n, wire)
}

// Host is a host of a Network: a transport.Network.
type Host struct{}

// Watch is transport.Network's.
func (h *Host) Watch(ctx context.Context, handle func(transport.Event)) error {
	return todo.ImplementMe(h, ctx, handle)
}

// Plug gives the host one more interface, or puts one it has on another
// wire.
func (h *Host) Plug(port Port) {
	_ = todo.ImplementMe(h, port)
}

// Unplug takes an interface from the host.
func (h *Host) Unplug(name string) {
	_ = todo.ImplementMe(h, name)
}

var _ transport.Network = (*Host)(nil)
