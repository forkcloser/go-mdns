//go:build linux || darwin || windows

package transport

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"
)

// System is the host's own network: every interface that is up and
// carries multicast, the loopback aside, for each family it has an
// address of. It shares port 5353 with the system's own responder, when
// there is one.
//
// It looks at the host's interfaces every two seconds: one that comes,
// goes or changes its addresses is told of within that time.
//
//nolint:iface // a Network, whatever it is made of on each system: the API's word for it
func System() Network { return system{} }

type system struct{}

// How the host's network is looked at.
const (
	// every is how often the interfaces are looked at.
	every = 2 * time.Second
	// waiting is how many packets wait for a link's reader before the
	// next is lost.
	waiting = 256
	// recently is how long a packet a link sent is known for its own
	// when it comes back, and remembered how many of them are.
	recently   = 2 * time.Second
	remembered = 64
	// readAgain is how long a socket that gave an error is left alone.
	readAgain = 100 * time.Millisecond
	// hops is the IP TTL and the hop limit everything is sent with: RFC
	// 6762 section 11.
	hops = 255
)

// errNoSocket is a host on which no socket could be opened on the port.
var errNoSocket = errors.New("no socket on the Multicast DNS port")

// Watch is Network's. Each Watch has sockets of its own.
func (system) Watch(ctx context.Context, handle func(Event)) error {
	watched := &watch{handle: handle, sockets: map[Family]*socket{}, links: map[where]*hostLink{}}

	var opening error

	for _, family := range []Family{IPv4, IPv6} {
		opened, err := open(ctx, family)
		if err != nil {
			opening = errors.Join(opening, err)

			continue
		}

		watched.sockets[family] = opened
		watched.reading.Go(func() { watched.read(opened) })
	}

	if len(watched.sockets) == 0 {
		return fmt.Errorf("%w: %w", errNoSocket, opening)
	}

	defer watched.end()

	look := time.NewTicker(every)
	defer look.Stop()

	for {
		watched.look()

		select {
		case <-ctx.Done():
			return fmt.Errorf("watching the host's links: %w", context.Cause(ctx))
		case <-look.C:
		}
	}
}

// where is what makes a link: an interface and a family.
type where struct {
	index  int
	family Family
}

// watch is one Watch under way.
type watch struct {
	handle  func(Event)
	sockets map[Family]*socket
	reading sync.WaitGroup
	// mu guards links, which the readers look packets up in.
	mu    sync.RWMutex
	links map[where]*hostLink
}

// end closes the sockets, which ends the readers, and the links.
func (w *watch) end() {
	for _, opened := range w.sockets {
		_ = opened.conn.Close()
	}

	w.reading.Wait()

	w.mu.Lock()
	defer w.mu.Unlock()

	for _, link := range w.links {
		link.end()
	}
}

// found is an interface as it is found, for one family.
type found struct {
	iface Interface
	addrs []netip.Prefix
	mtu   int
}

// look brings the links to what the host's interfaces now are, and
// tells of each that came, changed or went.
func (w *watch) look() {
	now := interfaces()

	w.mu.Lock()

	var events []Event

	for place, link := range w.links {
		shape, still := now[place]

		switch {
		case !still || shape.iface != link.iface || w.sockets[place.family] == nil:
			link.end()
			delete(w.links, place)

			events = append(events, Event{Link: link, Change: Down})
		case link.readdress(shape):
			events = append(events, Event{Link: link, Change: Changed})
		}
	}

	for place, shape := range now {
		opened := w.sockets[place.family]
		if w.links[place] != nil || opened == nil {
			continue
		}

		link := &hostLink{
			socket: opened, iface: shape.iface, family: place.family, addrs: shape.addrs, mtu: shape.mtu,
			queue: make(chan packet, waiting), closed: make(chan struct{}),
		}

		// An interface that cannot be joined now is looked at again.
		if link.join() != nil {
			continue
		}

		w.links[place] = link

		events = append(events, Event{Link: link, Change: Up})
	}

	w.mu.Unlock()

	// In the order of the interfaces, those that went first.
	slices.SortStableFunc(events, func(one, other Event) int {
		if one.Change == Down || other.Change == Down {
			return int(other.Change) - int(one.Change)
		}

		return one.Link.Interface().Index - other.Link.Interface().Index
	})

	for _, event := range events {
		w.handle(event)
	}
}

// interfaces is the host's interfaces that Multicast DNS is spoken on,
// each for the families it has an address of.
func interfaces() map[where]found {
	usable := map[where]found{}

	all, err := net.Interfaces()
	if err != nil {
		return usable
	}

	for _, one := range all {
		const wanted, unwanted = net.FlagUp | net.FlagMulticast, net.FlagLoopback | net.FlagPointToPoint

		if one.Flags&wanted != wanted || one.Flags&unwanted != 0 || skipped(one.Name) {
			continue
		}

		for _, prefix := range prefixes(&one) {
			place := where{index: one.Index, family: IPv6}
			if prefix.Addr().Is4() {
				place.family = IPv4
			}

			shape := usable[place]
			shape.iface, shape.mtu = Interface{Index: one.Index, Name: one.Name}, one.MTU
			shape.addrs = append(shape.addrs, prefix)
			usable[place] = shape
		}
	}

	return usable
}

// prefixes is an interface's addresses, each with the prefix it is on.
func prefixes(one *net.Interface) []netip.Prefix {
	addrs, err := one.Addrs()
	if err != nil {
		return nil
	}

	var found []netip.Prefix

	for _, addr := range addrs {
		network, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if host, ok := netip.AddrFromSlice(network.IP); ok {
			ones, _ := network.Mask.Size()
			found = append(found, netip.PrefixFrom(host.Unmap(), ones))
		}
	}

	return found
}

// read hands each packet a socket receives to the link of the interface
// it came in on.
func (w *watch) read(from *socket) {
	buf := make([]byte, MaxPacket)
	oob := make([]byte, controlSize)

	for {
		size, received, _, source, err := from.conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			// An error that stays is not to be read in a spin.
			time.Sleep(readAgain)

			continue
		}

		index, dest, ok := arrival(from.family, oob[:received])
		if !ok {
			continue
		}

		w.mu.RLock()
		link := w.links[where{index: index, family: from.family}]
		w.mu.RUnlock()

		if link == nil {
			continue
		}

		arrived := packet{
			bytes: slices.Clone(buf[:size]),
			from:  netip.AddrPortFrom(source.Addr().Unmap(), source.Port()),
			group: dest.IsMulticast(),
		}

		// A link does not read what it sent itself, which the system
		// hands back to it so that other programs on the host hear it.
		if link.sent(arrived) {
			continue
		}

		select {
		case link.queue <- arrived:
		default:
		}
	}
}

// packet is a packet on its way to a link's reader.
type packet struct {
	bytes []byte
	from  netip.AddrPort
	group bool
}

// hostLink is a Link on one of the host's interfaces.
type hostLink struct {
	socket *socket
	iface  Interface
	family Family
	queue  chan packet
	closed chan struct{}
	once   sync.Once

	// mu guards what follows: the addresses, and what was sent of late.
	mu     sync.Mutex
	addrs  []netip.Prefix
	mtu    int
	joined netip.Addr
	sends  []sending
}

// sending is a packet the link sent: what it hashes to, and when.
type sending struct {
	sum  uint64
	when time.Time
}

var _ Link = (*hostLink)(nil)

var seed = maphash.MakeSeed() //nolint:gochecknoglobals // one seed for the process, as maphash means it

func (l *hostLink) Interface() Interface { return l.iface }
func (l *hostLink) Family() Family       { return l.family }

func (l *hostLink) Addrs() []netip.Prefix {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.addrs)
}

func (l *hostLink) MTU() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.mtu
}

//revive:disable-next-line:function-result-limit // Link's Read, which says who sent and how
func (l *hostLink) Read(p []byte) (int, netip.AddrPort, bool, error) {
	// A link that is closed reads nothing, whatever had arrived.
	if !l.shutDown() {
		select {
		case arrived := <-l.queue:
			return copy(p, arrived.bytes), arrived.from, arrived.group, nil
		case <-l.closed:
		}
	}

	return 0, netip.AddrPort{}, false, fmt.Errorf("reading from %s: %w", l.iface.Name, net.ErrClosed)
}

func (l *hostLink) Multicast(p []byte) error {
	l.mu.Lock()

	// Decided under the lock a link ends under: an IPv4 link sends from
	// the address it joined with, and one with none has nowhere to send
	// from, closed or left without an address.
	if l.shutDown() || l.family == IPv4 && !l.joined.IsValid() {
		l.mu.Unlock()

		return fmt.Errorf("sending on %s: %w", l.iface.Name, net.ErrClosed)
	}

	source := l.joined
	l.sends = append(l.sends, sending{sum: maphash.Bytes(seed, p), when: time.Now()})
	l.sends = l.sends[max(0, len(l.sends)-remembered):]
	l.mu.Unlock()

	return l.socket.multicast(p, l.iface, source)
}

func (l *hostLink) Unicast(p []byte, dest netip.AddrPort) error {
	if l.shutDown() {
		return fmt.Errorf("sending on %s: %w", l.iface.Name, net.ErrClosed)
	}

	// A link-local address is good on one link: this one.
	addr := dest.Addr()
	if addr.Is6() && addr.IsLinkLocalUnicast() {
		addr = addr.WithZone(l.iface.Name)
	}

	_, err := l.socket.conn.WriteToUDPAddrPort(p, netip.AddrPortFrom(addr, dest.Port()))
	if err != nil {
		return fmt.Errorf("sending on %s: %w", l.iface.Name, err)
	}

	return nil
}

func (l *hostLink) Close() error {
	l.end()

	return nil
}

// end leaves the group, when the link had joined it, and closes the
// link, as one: a link is never seen out of the group and not closed.
func (l *hostLink) end() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.joined.IsValid() {
		_ = l.socket.member(l.iface, l.joined, false)
		l.joined = netip.Addr{}
	}

	l.once.Do(func() { close(l.closed) })
}

func (l *hostLink) shutDown() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

// first is the link's first address: the one it joins the group with
// and sends from, for IPv4.
func first(addrs []netip.Prefix) netip.Addr {
	if len(addrs) == 0 {
		return netip.Addr{}
	}

	return addrs[0].Addr()
}

// join joins the group on the link's interface.
func (l *hostLink) join() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.joined = first(l.addrs)

	return l.socket.member(l.iface, l.joined, true)
}

// readdress takes the addresses an interface now has, and says whether
// they are not what the link had. An IPv4 link joins the group by its
// address: it joins again when that one went.
func (l *hostLink) readdress(shape found) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.mtu = shape.mtu

	if slices.Equal(l.addrs, shape.addrs) {
		return false
	}

	l.addrs = shape.addrs

	if l.family == IPv4 && l.joined != first(shape.addrs) {
		_ = l.socket.member(l.iface, l.joined, false)
		l.joined = first(shape.addrs)
		_ = l.socket.member(l.iface, l.joined, true)
	}

	return true
}

// sent says whether a packet is one the link sent a moment ago, come
// back: from one of its own addresses and the port, with the bytes of
// one it sent. A program on the host that says the very same within
// two seconds is taken for the link itself, which costs nothing: it
// said what the link had just said.
func (l *hostLink) sent(arrived packet) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	own := func(prefix netip.Prefix) bool { return prefix.Addr() == arrived.from.Addr().WithZone("") }
	if arrived.from.Port() != Port || !slices.ContainsFunc(l.addrs, own) {
		return false
	}

	sum, now := maphash.Bytes(seed, arrived.bytes), time.Now()

	return slices.ContainsFunc(
		l.sends,
		func(one sending) bool { return one.sum == sum && now.Sub(one.when) < recently },
	)
}

// socket is a socket on the port, for one family and every interface.
type socket struct {
	family Family
	conn   *net.UDPConn
	// sending is held while a packet goes to the group: which interface
	// it leaves by is the socket's to say, one packet at a time.
	sending sync.Mutex
}

// open opens a socket on the port that other programs can share, and
// has it say, for each packet, which interface it came in on.
func open(ctx context.Context, family Family) (*socket, error) {
	network, address := "udp4", "0.0.0.0"
	if family == IPv6 {
		network, address = "udp6", "[::]"
	}

	sharing := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { return control(raw, share) }}

	listening, err := sharing.ListenPacket(ctx, network, fmt.Sprintf("%s:%d", address, Port))
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", network, err)
	}

	conn, ok := listening.(*net.UDPConn)
	if !ok {
		_ = listening.Close()

		return nil, fmt.Errorf("listening on %s: %w", network, errNoSocket)
	}

	opened := &socket{family: family, conn: conn}

	if err = opened.configure(); err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("configuring the %s socket: %w", network, err)
	}

	return opened, nil
}

// configure has the socket say where packets come in, and send with the
// TTL the protocol asks for, to the group on the host itself as well.
func (s *socket) configure() error {
	raw, err := s.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("reaching the socket: %w", err)
	}

	return control(raw, func(handle uintptr) error {
		options := map[int]int{
			optPacketInfo4:            1,
			syscall.IP_TTL:            hops,
			syscall.IP_MULTICAST_TTL:  hops,
			syscall.IP_MULTICAST_LOOP: 1,
		}
		level := syscall.IPPROTO_IP

		if s.family == IPv6 {
			options = map[int]int{
				optPacketInfo6:              1,
				syscall.IPV6_UNICAST_HOPS:   hops,
				syscall.IPV6_MULTICAST_HOPS: hops,
				syscall.IPV6_MULTICAST_LOOP: 1,
			}
			level = syscall.IPPROTO_IPV6
		}

		for option, value := range options {
			if err := setInt(handle, level, option, value); err != nil {
				return err
			}
		}

		return nil
	})
}

// member joins the group on an interface, or leaves it. An IPv4
// interface is named by one of its addresses, an IPv6 one by its index.
func (s *socket) member(iface Interface, addr netip.Addr, join bool) error {
	raw, err := s.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("reaching the socket: %w", err)
	}

	return control(raw, func(handle uintptr) error {
		if s.family == IPv4 {
			option := syscall.IP_DROP_MEMBERSHIP
			if join {
				option = syscall.IP_ADD_MEMBERSHIP
			}

			return setMember4(handle, option, &syscall.IPMreq{Multiaddr: Group(IPv4).As4(), Interface: addr.As4()})
		}

		option := syscall.IPV6_LEAVE_GROUP
		if join {
			option = syscall.IPV6_JOIN_GROUP
		}

		member := &syscall.IPv6Mreq{
			Multiaddr: Group(IPv6).As16(),
			Interface: uint32(iface.Index),
		} // #nosec G115 -- an interface's index

		return setMember6(handle, option, member)
	})
}

// multicast sends a packet to the group by one interface.
func (s *socket) multicast(p []byte, iface Interface, source netip.Addr) error {
	raw, err := s.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("reaching the socket: %w", err)
	}

	s.sending.Lock()
	defer s.sending.Unlock()

	dest := netip.AddrPortFrom(Group(s.family), Port)

	err = control(raw, func(handle uintptr) error {
		if s.family == IPv4 {
			return setAddr4(handle, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, source.As4())
		}

		return setInt(handle, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, iface.Index)
	})
	if err != nil {
		return fmt.Errorf("sending on %s: %w", iface.Name, err)
	}

	if s.family == IPv6 {
		dest = netip.AddrPortFrom(dest.Addr().WithZone(iface.Name), Port)
	}

	if _, err = s.conn.WriteToUDPAddrPort(p, dest); err != nil {
		return fmt.Errorf("sending on %s: %w", iface.Name, err)
	}

	return nil
}

// control does something to a socket's descriptor.
func control(raw syscall.RawConn, do func(handle uintptr) error) error {
	var done error

	if err := raw.Control(func(handle uintptr) { done = do(handle) }); err != nil {
		return fmt.Errorf("reaching the socket: %w", err)
	}

	return done
}
