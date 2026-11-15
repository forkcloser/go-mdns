// Package mdnstest is a network for tests of code that speaks Multicast
// DNS: hosts and the wires between them, in the test's process, on which
// peers find each other as they would on a real one, and on which a test
// can cut a wire and pull a plug.
//
// With testing/synctest, a test of several seconds of protocol, a probe
// or a record running out, takes no time at all.
//
// It is a network as Multicast DNS sees one, and no more: what is sent
// to the group reaches every other listener on the wire, of the same
// family; what is sent to an address reaches port 5353 there, and the
// first to listen on it, as a system hands a packet to the first socket
// bound; and nothing is lost but on a wire that is cut.
package mdnstest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/forkcloser/go-mdns/transport"
)

// Network is wires, and the hosts on them. The zero Network is empty and
// ready.
type Network struct {
	mu    sync.Mutex
	cut   map[string]bool
	hosts []*Host
	// made counts the addresses made for ports that came with none.
	made int
}

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
	host := &Host{network: n}

	n.mu.Lock()
	defer n.mu.Unlock()

	n.hosts = append(n.hosts, host)

	for _, port := range ports {
		host.attach(port)
	}

	return host
}

// Cut cuts a wire: nothing sent on it arrives, until Mend.
func (n *Network) Cut(wire string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.cut == nil {
		n.cut = map[string]bool{}
	}

	n.cut[wire] = true
}

// Mend mends a wire that was cut.
func (n *Network) Mend(wire string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	delete(n.cut, wire)
}

// Host is a host of a Network: a transport.Network.
type Host struct {
	network *Network
	// What follows is the network's, under its lock.
	ports   []*port
	indexes int
	watches []*watch
}

var _ transport.Network = (*Host)(nil)

// Watch is transport.Network's. Each Watch has links of its own, as each
// program on a host has sockets of its own: all of them hear what is
// sent to the group, and the first to watch what is sent to the host
// alone.
func (h *Host) Watch(ctx context.Context, handle func(transport.Event)) error {
	watching := &watch{more: make(chan struct{}, 1)}

	h.network.mu.Lock()
	h.watches = append(h.watches, watching)

	for _, port := range h.ports {
		port.open(watching)
	}
	h.network.mu.Unlock()

	defer h.unwatch(watching)

	for {
		for _, event := range watching.take(&h.network.mu) {
			handle(event)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("watching the links: %w", context.Cause(ctx))
		case <-watching.more:
		}
	}
}

// Plug gives the host one more interface, or puts one it has on another
// wire, or gives it other addresses.
func (h *Host) Plug(port Port) {
	h.network.mu.Lock()
	defer h.network.mu.Unlock()

	h.attach(port)
}

// Unplug takes an interface from the host.
func (h *Host) Unplug(name string) {
	h.network.mu.Lock()
	defer h.network.mu.Unlock()

	found := slices.IndexFunc(h.ports, func(one *port) bool { return one.name == name })
	if found < 0 {
		return
	}

	h.ports[found].down()
	h.ports = slices.Delete(h.ports, found, found+1)
}

// attach is Plug, under the network's lock.
func (h *Host) attach(wanted Port) {
	addrs := wanted.Addrs
	if len(addrs) == 0 {
		addrs = h.network.addresses()
	}

	mtu := wanted.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	found := slices.IndexFunc(h.ports, func(one *port) bool { return one.name == wanted.Interface })
	if found < 0 {
		h.indexes++
		h.ports = append(h.ports, &port{host: h, index: h.indexes, name: wanted.Interface})
		found = len(h.ports) - 1
	}

	plugged := h.ports[found]

	// A cable moved is a link gone and another come; addresses that
	// change leave the link where it is.
	if plugged.wire != wanted.Wire {
		plugged.down()
	}

	plugged.wire, plugged.addrs, plugged.mtu = wanted.Wire, slices.Clone(addrs), mtu

	for _, watching := range h.watches {
		plugged.open(watching)
	}
}

func (h *Host) unwatch(watching *watch) {
	h.network.mu.Lock()
	defer h.network.mu.Unlock()

	h.watches = slices.DeleteFunc(h.watches, func(one *watch) bool { return one == watching })

	for _, port := range h.ports {
		port.links = slices.DeleteFunc(port.links, func(one *link) bool {
			if one.watch == watching {
				one.shut()
			}

			return one.watch == watching
		})
	}
}

// What a network is made of when a test does not say.
const (
	defaultMTU = 1500
	// queued is how many packets wait for a reader before the next is
	// lost, as a socket's buffer loses them.
	queued = 1024
	// The link-local prefixes addresses are made in.
	ipv4Bits = 16
	ipv6Bits = 64
	octet    = 256
)

// addresses makes one IPv4 and one IPv6 link-local address, no two the
// same on the network.
func (n *Network) addresses() []netip.Prefix {
	n.made++

	high, low := byte(n.made/octet%octet), byte(n.made%octet) // #nosec G115 -- under octet, each

	ipv4 := netip.MustParseAddr("169.254.1.0").As4()
	ipv4[2] += high
	ipv4[3] = low

	ipv6 := netip.MustParseAddr("fe80::").As16()
	ipv6[14], ipv6[15] = high, low

	return []netip.Prefix{
		netip.PrefixFrom(netip.AddrFrom4(ipv4), ipv4Bits),
		netip.PrefixFrom(netip.AddrFrom16(ipv6), ipv6Bits),
	}
}

// watch is one Watch under way: what it has yet to be told.
type watch struct {
	events []transport.Event
	more   chan struct{}
}

// tell queues an event, under the network's lock.
func (w *watch) tell(link *link, change transport.Change) {
	w.events = append(w.events, transport.Event{Link: link, Change: change})

	select {
	case w.more <- struct{}{}:
	default:
	}
}

func (w *watch) take(mu *sync.Mutex) []transport.Event {
	mu.Lock()
	defer mu.Unlock()

	events := w.events
	w.events = nil

	return events
}

// port is an interface of a host.
type port struct {
	host  *Host
	index int
	name  string
	wire  string
	addrs []netip.Prefix
	mtu   int
	// links is the links open on it, the first to open first.
	links []*link
}

// open brings a watch's links on the port to what the port now is, under
// the network's lock: one for each family it has an address of.
func (p *port) open(watching *watch) {
	for _, family := range []transport.Family{transport.IPv4, transport.IPv6} {
		found := slices.IndexFunc(
			p.links,
			func(one *link) bool { return one.watch == watching && one.family == family },
		)
		has := slices.ContainsFunc(p.addrs, func(addr netip.Prefix) bool { return familyOf(addr.Addr()) == family })

		switch {
		case has && found < 0:
			opened := &link{
				port:   p,
				watch:  watching,
				family: family,
				more:   make(chan struct{}, 1),
				closed: make(chan struct{}),
			}
			p.links = append(p.links, opened)
			watching.tell(opened, transport.Up)
		case has:
			watching.tell(p.links[found], transport.Changed)
		case found >= 0:
			p.links[found].shut()
			watching.tell(p.links[found], transport.Down)
			p.links = slices.Delete(p.links, found, found+1)
		}
	}
}

// down closes every link on the port and tells their watches, under the
// network's lock.
func (p *port) down() {
	for _, one := range p.links {
		one.shut()
		one.watch.tell(one, transport.Down)
	}

	p.links = nil
}

func familyOf(addr netip.Addr) transport.Family {
	if addr.Is4() {
		return transport.IPv4
	}

	return transport.IPv6
}

// packet is a packet on its way to a link.
type packet struct {
	bytes []byte
	from  netip.AddrPort
	group bool
}

// link is a transport.Link on a port, for one Watch and one family.
type link struct {
	port   *port
	watch  *watch
	family transport.Family
	// What follows is the network's, under its lock.
	queue []packet
	shutd bool
	more  chan struct{}
	// closed is closed when the link is.
	closed chan struct{}
}

var _ transport.Link = (*link)(nil)

func (l *link) Interface() transport.Interface {
	return transport.Interface{Index: l.port.index, Name: l.port.name}
}

func (l *link) Family() transport.Family { return l.family }

func (l *link) Addrs() []netip.Prefix {
	l.network().mu.Lock()
	defer l.network().mu.Unlock()

	var addrs []netip.Prefix

	for _, addr := range l.port.addrs {
		if familyOf(addr.Addr()) == l.family {
			addrs = append(addrs, addr)
		}
	}

	return addrs
}

func (l *link) MTU() int {
	l.network().mu.Lock()
	defer l.network().mu.Unlock()

	return l.port.mtu
}

//revive:disable-next-line:function-result-limit // transport.Link's Read, which says who sent and how
func (l *link) Read(p []byte) (int, netip.AddrPort, bool, error) {
	for {
		l.network().mu.Lock()

		// A link that is closed reads nothing, whatever had arrived.
		if l.shutd {
			l.network().mu.Unlock()

			return 0, netip.AddrPort{}, false, fmt.Errorf("reading from %s: %w", l.port.name, net.ErrClosed)
		}

		if len(l.queue) > 0 {
			next := l.queue[0]
			l.queue = l.queue[1:]

			// Another reader may be waiting for what is left.
			if len(l.queue) > 0 {
				signal(l.more)
			}

			l.network().mu.Unlock()

			return copy(p, next.bytes), next.from, next.group, nil
		}

		l.network().mu.Unlock()

		select {
		case <-l.closed:
		case <-l.more:
		}
	}
}

// signal lets a reader know there is something to read, if it does not
// know already.
func signal(more chan struct{}) {
	select {
	case more <- struct{}{}:
	default:
	}
}

func (l *link) Multicast(p []byte) error {
	return l.send(p, true, func(other *link) bool { return other != l })
}

func (l *link) Unicast(p []byte, dest netip.AddrPort) error {
	// A link carries one family: an address of the other is nowhere it
	// can send to.
	if familyOf(dest.Addr()) != l.family {
		return fmt.Errorf("sending on %s: %w: %s", l.port.name, errOtherFamily, dest.Addr())
	}

	taken := false

	return l.send(p, false, func(other *link) bool {
		// Nothing listens on another port, and a packet goes to the first
		// that listens on this one.
		if taken || dest.Port() != transport.Port || !other.port.has(dest.Addr()) {
			return false
		}

		taken = true

		return true
	})
}

func (l *link) Close() error {
	l.network().mu.Lock()
	defer l.network().mu.Unlock()

	l.shut()
	l.port.links = slices.DeleteFunc(l.port.links, func(one *link) bool { return one == l })

	return nil
}

func (l *link) network() *Network { return l.port.host.network }

// shut closes the link, under the network's lock.
func (l *link) shut() {
	if !l.shutd {
		l.shutd = true
		close(l.closed)
	}
}

// The headers a packet travels under.
const (
	ipv4Headers = 28
	ipv6Headers = 48
)

// errOtherFamily is an address of the family a link does not carry.
var errOtherFamily = errors.New("an address of the other family")

// errTooLarge is a packet over what Multicast DNS allows.
var errTooLarge = errors.New("a packet too large")

// send hands a packet to the links on the same wire, of the same family,
// that are chosen; to none of them when the wire is cut.
func (l *link) send(p []byte, group bool, chosen func(*link) bool) error {
	network := l.network()

	network.mu.Lock()
	defer network.mu.Unlock()

	headers := ipv4Headers
	if l.family == transport.IPv6 {
		headers = ipv6Headers
	}

	switch {
	case l.shutd:
		return fmt.Errorf("sending on %s: %w", l.port.name, net.ErrClosed)
	case len(p)+headers > transport.MaxPacket:
		return fmt.Errorf(
			"sending on %s: %w: %d bytes, over %d with its headers",
			l.port.name,
			errTooLarge,
			len(p),
			transport.MaxPacket,
		)
	case network.cut[l.port.wire]:
		return nil
	}

	for _, other := range network.on(l.port.wire, l.family) {
		if chosen(other) {
			other.receive(packet{bytes: slices.Clone(p), from: l.source(other.port.name), group: group})
		}
	}

	return nil
}

// on is the links open on a wire, of a family, under the network's
// lock: host by host, and on each port the first to open first.
func (n *Network) on(wire string, family transport.Family) []*link {
	var links []*link

	for _, host := range n.hosts {
		for _, port := range host.ports {
			if port.wire != wire {
				continue
			}

			for _, other := range port.links {
				if other.family == family {
					links = append(links, other)
				}
			}
		}
	}

	return links
}

// receive queues a packet for the link's reader, under the network's
// lock.
func (l *link) receive(arrived packet) {
	if len(l.queue) >= queued {
		return
	}

	l.queue = append(l.queue, arrived)
	signal(l.more)
}

// source is the address a packet from the link is seen to come from, on
// the interface it arrives on.
func (l *link) source(arrives string) netip.AddrPort {
	for _, addr := range l.port.addrs {
		if familyOf(addr.Addr()) == l.family {
			return netip.AddrPortFrom(zoned(addr.Addr(), arrives), transport.Port)
		}
	}

	return netip.AddrPort{}
}

// has says whether an address is one of the port's, whatever zone it is
// written with.
func (p *port) has(addr netip.Addr) bool {
	return slices.ContainsFunc(p.addrs, func(own netip.Prefix) bool { return own.Addr() == addr.WithZone("") })
}

// zoned gives an IPv6 link-local address the zone it is good in: the
// interface it is seen on.
func zoned(addr netip.Addr, name string) netip.Addr {
	if addr.Is6() && addr.IsLinkLocalUnicast() {
		return addr.WithZone(name)
	}

	return addr
}
