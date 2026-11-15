//go:build linux || darwin || windows

package transport_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/transport"
)

// program is the host's network as one program sees it: its links, by
// interface and family.
type program struct {
	// later is what the host tells of after it said that was all.
	later chan transport.Event
	links map[where]transport.Link
	ended chan error
	stop  context.CancelFunc
}

type where struct {
	index  int
	family transport.Family
}

// run watches the host's own network as a program of its own, and
// waits for its links to be told of.
func run(t *testing.T) *program {
	t.Helper()

	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	events := make(chan transport.Event, 256)
	running := &program{links: map[where]transport.Link{}, ended: make(chan error, 1), stop: stop}

	go func() {
		running.ended <- transport.System().Watch(ctx, func(event transport.Event) { events <- event })
	}()

	t.Cleanup(func() {
		stop()

		if err := <-running.ended; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("the watch ended with %v", err)
		}
	})

	// The host's links, until it says that is all of them.
	for {
		select {
		case event := <-events:
			switch event.Change {
			case transport.Up:
				running.links[where{event.Link.Interface().Index, event.Link.Family()}] = event.Link
			case transport.Settled:
				running.later = events

				return running
			case transport.Changed, transport.Down:
			}
		case err := <-running.ended:
			t.Fatalf("watching the host's network: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("the host never said that was all its links")
		}
	}
}

// question is a question no host has an answer to: a packet that can go
// out on a real network and that no one will mind.
func question(t *testing.T) []byte {
	t.Helper()

	unique := make([]byte, 8)
	if _, err := rand.Read(unique); err != nil {
		t.Fatal(err)
	}

	message := wire.NewBuilder(nil, wire.Header{}, wire.Options{})

	name := []string{"_go-mdns-test-" + hex.EncodeToString(unique), "_udp", "local"}
	if err := message.Question(wire.Question{Name: name, Type: wire.TypePTR, Class: wire.ClassIN}); err != nil {
		t.Fatal(err)
	}

	return message.Bytes()
}

// reading is a packet a link read: who sent it, and whether to all.
type reading struct {
	from  netip.AddrPort
	group bool
}

// heard reads a link until it reads a packet, among whatever else the
// network has to say, or a time has passed.
func heard(link transport.Link, packet []byte, within time.Duration) (reading, bool) {
	got := make(chan reading, 1)
	done := make(chan struct{})

	defer close(done)

	go func() {
		buf := make([]byte, transport.MaxPacket)

		for {
			size, from, group, err := link.Read(buf)
			if err != nil {
				return
			}

			if bytes.Equal(buf[:size], packet) {
				got <- reading{from: from, group: group}

				return
			}

			select {
			case <-done:
				return
			default:
			}
		}
	}()

	select {
	case found := <-got:
		return found, true
	case <-time.After(within):
		return reading{}, false
	}
}

// The host's own interfaces, as links: each on an interface that has a
// name and a number, for one family, with addresses of that family and
// room for a packet. They go when the watch does.
func TestTheHostsOwnLinks(t *testing.T) {
	t.Parallel()

	running := run(t)

	for at, link := range running.links {
		addrs := link.Addrs()

		if link.Interface().Index != at.index || link.Interface().Name == "" || link.Family() != at.family ||
			link.MTU() < 576 ||
			len(addrs) == 0 {
			t.Errorf(
				"a link on %+v, of family %d, carrying %d bytes, at %v",
				link.Interface(),
				link.Family(),
				link.MTU(),
				addrs,
			)
		}

		for _, addr := range addrs {
			if addr.Addr().Is4() != (at.family == transport.IPv4) || addr.Addr().Zone() != "" ||
				addr.Addr().IsLoopback() {
				t.Errorf("a link of family %d on %s at %s", at.family, link.Interface().Name, addr)
			}
		}
	}

	// That was all of them: the next look, two seconds later, finds no
	// link that was there and not told of.
	select {
	case event := <-running.later:
		t.Errorf("told of a link on %s after the host said that was all", event.Link.Interface().Name)
	case <-time.After(2500 * time.Millisecond):
	}

	running.stop()

	if err := <-running.ended; !errors.Is(err, context.Canceled) {
		t.Errorf("the watch ended with %v", err)
	}

	running.ended <- nil

	for _, link := range running.links {
		if _, _, _, err := link.Read(make([]byte, transport.MaxPacket)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("reading from a link of a watch that ended: %v", err)
		}

		if err := link.Multicast(question(t)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("sending on a link of a watch that ended: %v", err)
		}
	}
}

// Two programs on the host share the port: what one says to the group
// on an interface the other hears on that interface, from the first's
// address there and as said to all; and the one that said it does not
// hear itself.
func TestTwoProgramsOnTheHost(t *testing.T) {
	t.Parallel()

	one, other := run(t), run(t)

	if len(one.links) == 0 {
		unablef(t, "the host has no interface that carries multicast")
	}

	for at, link := range one.links {
		listener, has := other.links[at]
		if !has {
			t.Errorf("the second program has no link on %s for family %d", link.Interface().Name, at.family)

			continue
		}

		said := question(t)

		err := link.Multicast(said)
		refused(t, err)

		if err != nil {
			t.Errorf("sending on %s for family %d: %v", link.Interface().Name, at.family, err)

			continue
		}

		read, got := heard(listener, said, 3*time.Second)
		own := slices.ContainsFunc(
			link.Addrs(),
			func(addr netip.Prefix) bool { return addr.Addr() == read.from.Addr().WithZone("") },
		)

		if !got || !read.group || read.from.Port() != transport.Port || !own {
			t.Errorf(
				"on %s for family %d: heard %t, to all %t, from %s",
				link.Interface().Name,
				at.family,
				got,
				read.group,
				read.from,
			)
		}

		// Its own word does not come back to it.
		if _, got = heard(link, said, 300*time.Millisecond); got {
			t.Errorf("on %s for family %d: a link heard itself", link.Interface().Name, at.family)
		}
	}
}

// refused leaves the test when the environment is what refused a
// packet to the group.
func refused(t *testing.T, err error) {
	t.Helper()

	if errors.Is(err, os.ErrPermission) {
		unablef(t, "this environment does not let a program send to the group: %v", err)
	}

	// macOS 15 keeps a program it was not told to trust off the local
	// network, and says there is no route: GitHub's runners are such,
	// and nothing in a workflow grants it
	// (https://github.com/actions/runner-images/issues/10924). Skipped
	// under CI too: failing there would fail every run.
	if runtime.GOOS == "darwin" && errors.Is(err, syscall.EHOSTUNREACH) {
		t.Skipf("macOS keeps this program off the local network: %v", err)
	}
}

// unablef leaves a test that cannot be run where it is; and fails it
// under CI, where a leg that skips has run nothing of its system's code.
func unablef(t *testing.T, format string, args ...any) {
	t.Helper()

	if os.Getenv("CI") != "" {
		t.Fatalf(format, args...)
	}

	t.Skipf(format, args...)
}
