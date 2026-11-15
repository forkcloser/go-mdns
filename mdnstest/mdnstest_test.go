package mdnstest_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

// watching is a host being watched: its events, as they come.
type watching struct {
	events chan transport.Event
	ended  chan error
	stop   context.CancelFunc
}

func watch(t *testing.T, host *mdnstest.Host) *watching {
	t.Helper()

	ctx, stop := context.WithCancel(t.Context())
	watched := &watching{events: make(chan transport.Event, 64), ended: make(chan error, 1), stop: stop}

	go func() {
		watched.ended <- host.Watch(ctx, func(event transport.Event) { watched.events <- event })
	}()

	t.Cleanup(stop)

	return watched
}

// next is the next event, which has to be the change given.
func (w *watching) next(t *testing.T, change transport.Change) transport.Link {
	t.Helper()

	select {
	case event := <-w.events:
		if event.Change != change {
			t.Fatalf("change %d on %s, want %d", event.Change, event.Link.Interface().Name, change)
		}

		return event.Link
	case <-time.After(5 * time.Second):
		t.Fatalf("no event, waiting for change %d", change)

		return nil
	}
}

// links is the links of a host of one port, as it comes up: IPv4 then
// IPv6.
func (w *watching) links(t *testing.T) []transport.Link {
	t.Helper()

	return []transport.Link{w.next(t, transport.Up), w.next(t, transport.Up)}
}

// packet is what a link reads.
type packet struct {
	bytes string
	from  netip.AddrPort
	group bool
}

func read(t *testing.T, link transport.Link) packet {
	t.Helper()

	buf := make([]byte, transport.MaxPacket)

	size, from, group, err := link.Read(buf)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	return packet{bytes: string(buf[:size]), from: from, group: group}
}

// quiet says that links on a wire have nothing waiting to be read: a
// host that joins the wire says a word to all, and that word is the
// next thing each of them reads.
func quiet(t *testing.T, network *mdnstest.Network, wire string, links ...transport.Link) {
	t.Helper()

	marker := watch(t, network.Host(mdnstest.Port{Interface: "marker", Wire: wire})).links(t)

	for _, from := range marker {
		if err := from.Multicast([]byte("nothing before this")); err != nil {
			t.Fatal(err)
		}
	}

	for _, link := range links {
		if got := read(t, link); got.bytes != "nothing before this" {
			t.Errorf("%q was waiting on %s", got.bytes, link.Interface().Name)
		}
	}
}

func TestWhatIsSaidToTheGroupReachesTheWire(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	one := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)
	two := watch(t, network.Host(mdnstest.Port{Interface: "eth0", Wire: "lan"})).links(t)
	far := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "elsewhere"})).links(t)

	for index, family := range []transport.Family{transport.IPv4, transport.IPv6} {
		if one[index].Family() != family || one[index].Interface() != (transport.Interface{Index: 1, Name: "en0"}) ||
			one[index].MTU() != 1500 {
			t.Fatalf("link %d is %d on %+v", index, one[index].Family(), one[index].Interface())
		}

		if err := one[index].Multicast([]byte("hello")); err != nil {
			t.Fatal(err)
		}

		// From the sender's address of that family, as it is known on the
		// interface it arrives on.
		got := read(t, two[index])
		sender := one[index].Addrs()[0].Addr()

		if got.bytes != "hello" || !got.group || got.from.Port() != transport.Port ||
			got.from.Addr().WithZone("") != sender {
			t.Errorf("read %+v, want hello from %s", got, sender)
		}

		if family == transport.IPv6 && got.from.Addr().Zone() != "eth0" {
			t.Errorf("from %s: the zone is not the interface it arrived on", got.from)
		}
	}

	// Not the sender, not the other family, not another wire.
	quiet(t, &network, "lan", append(one, two...)...)
	quiet(t, &network, "elsewhere", far...)
}

func TestAddressesOfTheNetworksMaking(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	seen := map[netip.Addr]bool{}

	for range 3 {
		for _, link := range watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t) {
			addrs := link.Addrs()
			if len(addrs) != 1 || !addrs[0].Addr().IsLinkLocalUnicast() || seen[addrs[0].Addr()] {
				t.Fatalf("addresses %v", addrs)
			}

			seen[addrs[0].Addr()] = true

			if addr := addrs[0].Addr(); addr.Is6() != (link.Family() == transport.IPv6) {
				t.Errorf("%s on a link of family %d", addr, link.Family())
			}
		}
	}
}

func TestWhatIsSaidToOneReachesIt(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	host := network.Host(mdnstest.Port{
		Interface: "en0", Wire: "lan",
		Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.7/24")}, MTU: 9000,
	})

	// Two programs on the host: both listen, the first is handed what
	// comes for the host alone.
	first := watch(t, host).next(t, transport.Up)
	second := watch(t, host).next(t, transport.Up)
	other := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)
	sender := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)[0]

	if first.MTU() != 9000 || len(first.Addrs()) != 1 {
		t.Fatalf("an MTU of %d, addresses %v", first.MTU(), first.Addrs())
	}

	to := netip.MustParseAddrPort("192.0.2.7:5353")

	for _, send := range []func() error{
		func() error { return sender.Unicast([]byte("for you"), to) },
		// Nothing listens on another port, and no one is at another address.
		func() error { return sender.Unicast([]byte("lost"), netip.AddrPortFrom(to.Addr(), 49152)) },
		func() error { return sender.Unicast([]byte("lost"), netip.MustParseAddrPort("192.0.2.8:5353")) },
		func() error { return sender.Multicast([]byte("for all")) },
	} {
		if err := send(); err != nil {
			t.Fatal(err)
		}
	}

	if got := read(t, first); got.bytes != "for you" || got.group {
		t.Errorf("the first read %+v", got)
	}

	for _, link := range []transport.Link{first, second, other[0]} {
		if got := read(t, link); got.bytes != "for all" || !got.group {
			t.Errorf("read %+v, want what was said to all", got)
		}
	}

	quiet(t, &network, "lan", append(other, first, second, sender)...)
}

func TestAWireCutAndMended(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	one := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)[0]
	two := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)[0]

	network.Cut("lan")

	if err := one.Multicast([]byte("lost")); err != nil {
		t.Fatal(err)
	}

	network.Mend("lan")

	if err := one.Multicast([]byte("heard")); err != nil {
		t.Fatal(err)
	}

	if got := read(t, two); got.bytes != "heard" {
		t.Errorf("read %+v: what was sent on a cut wire arrived", got)
	}
}

func TestInterfacesComeChangeAndGo(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	host := network.Host()
	watched := watch(t, host)
	other := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)[0]

	host.Plug(mdnstest.Port{Interface: "en0", Wire: "lan"})

	ipv4, ipv6 := watched.next(t, transport.Up), watched.next(t, transport.Up)

	// Other addresses on the same wire: the links stay, and say so. With
	// no IPv6 address left, that link goes.
	host.Plug(
		mdnstest.Port{Interface: "en0", Wire: "lan", Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.9/24")}},
	)

	if watched.next(t, transport.Changed) != ipv4 || watched.next(t, transport.Down) != ipv6 {
		t.Error("not the links that were up")
	}

	if got := ipv4.Addrs(); len(got) != 1 || got[0] != netip.MustParsePrefix("192.0.2.9/24") {
		t.Errorf("addresses %v", got)
	}

	if err := ipv6.Multicast([]byte("gone")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("sending on a link that is down: %v", err)
	}

	// Another wire: the link goes, and another comes, which no longer
	// reaches the first wire.
	host.Plug(mdnstest.Port{Interface: "en0", Wire: "elsewhere"})

	if watched.next(t, transport.Down) != ipv4 {
		t.Error("not the link that was up")
	}

	moved := watched.next(t, transport.Up)
	_ = watched.next(t, transport.Up)

	if moved == ipv4 || moved.Interface() != ipv4.Interface() {
		t.Errorf("the link on the other wire is %+v", moved.Interface())
	}

	if err := moved.Multicast([]byte("elsewhere")); err != nil {
		t.Fatal(err)
	}

	// A second interface has the next index; one unplugged goes down.
	host.Plug(
		mdnstest.Port{Interface: "en1", Wire: "lan", Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}},
	)

	if second := watched.next(t, transport.Up); second.Interface() != (transport.Interface{Index: 2, Name: "en1"}) {
		t.Errorf("the second interface is %+v", second.Interface())
	}

	host.Unplug("en0")
	host.Unplug("nothing")

	if watched.next(t, transport.Down) != moved {
		t.Error("not the link that was up")
	}

	_ = watched.next(t, transport.Down)

	quiet(t, &network, "lan", other)
}

func TestAWatchEnds(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	host := network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})
	watched := watch(t, host)
	link := watched.links(t)[0]

	// A read under way comes back when the watch ends, the links with it.
	read := make(chan error, 1)

	go func() {
		_, _, _, err := link.Read(make([]byte, transport.MaxPacket))
		read <- err
	}()

	watched.stop()

	if err := <-watched.ended; !errors.Is(err, context.Canceled) {
		t.Errorf("the watch ended with %v", err)
	}

	if err := <-read; !errors.Is(err, net.ErrClosed) {
		t.Errorf("the read ended with %v", err)
	}

	// And the next watch has links of its own.
	if again := watch(t, host).links(t)[0]; again == link {
		t.Error("a link that was closed was handed out again")
	}
}

func TestAPacketTooLarge(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	links := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)

	// 9000 bytes with the headers, and not one more.
	for index, headers := range []int{28, 48} {
		if err := links[index].Multicast(make([]byte, transport.MaxPacket-headers)); err != nil {
			t.Errorf("a packet of 9000 bytes with its headers: %v", err)
		}

		if err := links[index].Multicast(
			make([]byte, transport.MaxPacket-headers+1),
		); err == nil ||
			!strings.Contains(err.Error(), "over 9000") {
			t.Errorf("a packet of 9001 bytes with its headers: %v", err)
		}
	}
}

// What the package is for: in a bubble an hour of waiting on the network
// is no time at all, a read that waits being one the bubble knows to be
// waiting.
func TestAnHourOnTheNetworkTakesNoTime(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		sender := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"}))
		reader := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"}))
		from, to := sender.links(t)[0], reader.links(t)[0]
		start := time.Now()

		go func() {
			time.Sleep(time.Hour)

			_ = from.Multicast([]byte("an hour later"))
		}()

		if got := read(t, to); got.bytes != "an hour later" || time.Since(start) != time.Hour {
			t.Errorf("read %+v after %s", got, time.Since(start))
		}

		// A bubble ends when every goroutine in it has.
		for _, watched := range []*watching{sender, reader} {
			watched.stop()

			if err := <-watched.ended; !errors.Is(err, context.Canceled) {
				t.Errorf("the watch ended with %v", err)
			}
		}
	})
}

// A link that is closed reads nothing, whatever had arrived; and one
// told of as down has been closed, however it went down.
func TestALinkThatIsClosedOrDown(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	host := network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"}, mdnstest.Port{Interface: "en1", Wire: "lan"})
	watched := watch(t, host)
	links := []transport.Link{
		watched.next(t, transport.Up),
		watched.next(t, transport.Up),
		watched.next(t, transport.Up),
		watched.next(t, transport.Up),
	}
	other := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)[0]

	if err := other.Multicast([]byte("waiting")); err != nil {
		t.Fatal(err)
	}

	if err := links[0].Close(); err != nil {
		t.Fatal(err)
	}

	if size, _, _, err := links[0].Read(make([]byte, transport.MaxPacket)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a closed link read %d bytes, %v", size, err)
	}

	// Unplugged, and moved to another wire: each is down, and closed.
	host.Unplug("en0")
	host.Plug(mdnstest.Port{Interface: "en1", Wire: "elsewhere"})

	for range 3 {
		if down := watched.next(t, transport.Down); !errors.Is(down.Multicast([]byte("gone")), net.ErrClosed) {
			t.Errorf("a link on %s that is down still sends", down.Interface().Name)
		}
	}
}

// What a link reads is what was sent, as it was when it was sent; 1024
// of them wait for a reader, and the next is lost; and two who read one
// link each get what is there.
func TestWhatWaitsForAReader(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	sender := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)[0]
	reader := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)[0]

	said := []byte("first")
	if err := sender.Multicast(said); err != nil {
		t.Fatal(err)
	}

	copy(said, "other")

	if got := read(t, reader); got.bytes != "first" {
		t.Errorf("read %q: what was sent changed after it was", got.bytes)
	}

	for index := range 1025 {
		if err := sender.Multicast(fmt.Appendf(nil, "%04d", index)); err != nil {
			t.Fatal(err)
		}
	}

	// Two readers, each taking what is there until the last.
	got := make(chan string, 1024)

	for range 2 {
		go func() {
			for {
				buf := make([]byte, transport.MaxPacket)

				size, _, _, err := reader.Read(buf)
				if err != nil {
					return
				}

				got <- string(buf[:size])
			}
		}()
	}

	seen := map[string]bool{}
	for range 1024 {
		seen[<-got] = true
	}

	if len(seen) != 1024 || seen["1024"] {
		t.Errorf("read %d of the first 1024, and the one after them: %t", len(seen), seen["1024"])
	}

	if err := sender.Multicast([]byte("after")); err != nil {
		t.Fatal(err)
	}

	if next := <-got; next != "after" {
		t.Errorf("read %q after the 1024 that waited", next)
	}
}

// An answer goes back to where a question came from, as it is written
// there, zone and all; and a link sends to its own family alone.
func TestAnAnswerToWhereAPacketCameFrom(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	asker := watch(t, network.Host(mdnstest.Port{Interface: "en0", Wire: "lan"})).links(t)
	answerer := watch(t, network.Host(mdnstest.Port{Interface: "eth0", Wire: "lan"})).links(t)

	for index := range asker {
		if err := asker[index].Multicast([]byte("question")); err != nil {
			t.Fatal(err)
		}

		from := read(t, answerer[index]).from

		if err := answerer[index].Unicast([]byte("answer"), from); err != nil {
			t.Fatal(err)
		}

		if got := read(t, asker[index]); got.bytes != "answer" || got.group {
			t.Errorf("read %+v", got)
		}

		// To the address of the other family: nowhere this link sends.
		other := read1(t, asker[1-index], answerer[1-index])

		if err := answerer[index].Unicast([]byte("astray"), other); err == nil {
			t.Errorf("a link of family %d sent to %s", answerer[index].Family(), other)
		}
	}

	quiet(t, &network, "lan", append(asker, answerer...)...)
}

// read1 has one link say a word to the group and another read it, and
// is where the word came from.
func read1(t *testing.T, from, to transport.Link) netip.AddrPort {
	t.Helper()

	if err := from.Multicast([]byte("where from")); err != nil {
		t.Fatal(err)
	}

	return read(t, to).from
}

// A resolver that is not a Multicast DNS one asks from another port, and
// is answered there.
func TestASocketOnAnotherPort(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	resolver := network.Host(
		mdnstest.Port{Interface: "en0", Wire: "lan", Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.7/24")}},
	)
	listener := watch(
		t,
		network.Host(
			mdnstest.Port{Interface: "en0", Wire: "lan", Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.8/24")}},
		),
	).next(t, transport.Up)
	local := netip.MustParseAddrPort("192.0.2.7:49152")

	for what, refused := range map[string]netip.AddrPort{
		"an address that is not the host's": netip.MustParseAddrPort("192.0.2.9:49152"),
		"the port of Multicast DNS":         netip.MustParseAddrPort("192.0.2.7:5353"),
		"no port":                           netip.MustParseAddrPort("192.0.2.7:0"),
	} {
		if _, err := resolver.Socket(refused); err == nil {
			t.Errorf("a socket at %s was opened", what)
		}
	}

	socket, err := resolver.Socket(local)
	if err != nil {
		t.Fatal(err)
	}

	if err = socket.Multicast([]byte("to all")); err != nil {
		t.Fatal(err)
	}

	if err = socket.Unicast([]byte("to one"), netip.MustParseAddr("192.0.2.8")); err != nil {
		t.Fatal(err)
	}

	for _, want := range []packet{{bytes: "to all", from: local, group: true}, {bytes: "to one", from: local}} {
		if got := read(t, listener); got != want {
			t.Errorf("read %+v, want %+v", got, want)
		}
	}

	// Answered at its port, and nowhere else.
	for _, dest := range []netip.AddrPort{local, netip.MustParseAddrPort("192.0.2.7:49153")} {
		if err = listener.Unicast([]byte("answer"), dest); err != nil {
			t.Fatal(err)
		}
	}

	buf := make([]byte, transport.MaxPacket)

	size, from, err := socket.Read(buf)
	if err != nil || string(buf[:size]) != "answer" || from != netip.MustParseAddrPort("192.0.2.8:5353") {
		t.Errorf("read %q from %s, %v", buf[:size], from, err)
	}

	// To an address of the other family: nowhere it sends.
	if err = socket.Unicast([]byte("astray"), netip.MustParseAddr("fe80::8")); err == nil {
		t.Error("a socket at an IPv4 address sent to an IPv6 one")
	}

	// Closed, it reads nothing, whatever had arrived.
	if err = listener.Unicast([]byte("too late"), local); err != nil {
		t.Fatal(err)
	}

	if err = socket.Close(); err != nil {
		t.Fatal(err)
	}

	if size, _, err = socket.Read(buf); !errors.Is(err, net.ErrClosed) {
		t.Errorf("%d bytes were waiting, %v", size, err)
	}

	if err = socket.Multicast(nil); !errors.Is(err, net.ErrClosed) {
		t.Errorf("sending from a socket that is closed: %v", err)
	}
}
