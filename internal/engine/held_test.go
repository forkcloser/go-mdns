package engine_test

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

// info is a record of another type under the host's name, the host's
// alone.
func info() wire.Record {
	return wire.Record{
		Name: hostName(), Class: wire.ClassIN, TTL: 120, Flush: true,
		Data: wire.Opaque{Kind: 13, Bytes: []byte("\x03ARM")},
	}
}

// A record an Engine holds for this host alone is taken, for another
// set of the same Engine as for another host: said at once, with no
// asking, since no one on the network would answer for it. It is one
// record by its name, its type and the link: another type of the name,
// a record others may say too, and the same on another link are free,
// and so is the record itself once it is given up.
func TestARecordTheEngineAlreadyHolds(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var wires mdnstest.Network

		opened := open(t, engine.Config{Network: wires.Host(port("en0", lan, 1), port("en1", wifi, 2))})
		one := func(records ...wire.Record) engine.Set { return engine.Set{Records: records} }

		held, err := opened.Publish(t.Context(), one(address(1, true)))
		if err != nil {
			t.Fatal(err)
		}

		began := time.Now()

		if _, err = opened.Publish(t.Context(), one(address(2, true))); !errors.Is(err, engine.ErrConflict) ||
			time.Since(began) != 0 {
			t.Errorf("a record already held: %v, after %s", err, time.Since(began))
		}

		// The host's own addresses are records of that name and type too.
		if _, err = opened.Publish(t.Context(), engine.Set{Host: hostName()}); !errors.Is(err, engine.ErrConflict) {
			t.Errorf("a host of a name whose address is held: %v", err)
		}

		for what, free := range map[string]engine.Set{
			"another type of the name":    one(info()),
			"a record others may say too": one(address(2, false)),
		} {
			published, refused := opened.Publish(t.Context(), free)
			if refused != nil {
				t.Errorf("%s: %v", what, refused)

				continue
			}

			_ = published.Close()
		}

		_ = held.Close()

		// The other order: the other type first, then the address.
		first, err := opened.Publish(t.Context(), one(info()))
		if err != nil {
			t.Fatal(err)
		}

		again, err := opened.Publish(t.Context(), one(address(2, true)))
		if err != nil {
			t.Fatalf("a record given up, beside another type of its name: %v", err)
		}

		_, _ = first.Close(), again.Close()

		// A name on two links, with on each the address it has there.
		here, err := opened.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(1, true)}, Interfaces: only("en0")},
		)
		if err != nil {
			t.Fatal(err)
		}

		there, err := opened.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(2, true)}, Interfaces: only("en1")},
		)
		if err != nil {
			t.Fatalf("the same record on another link: %v", err)
		}

		if _, err = opened.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(3, true)}, Interfaces: only("en1")},
		); !errors.Is(err, engine.ErrConflict) {
			t.Errorf("the same record on a link where it is held: %v", err)
		}

		_ = there.Close()

		// Refused for the link where it is held, a set stands on no other:
		// what it wanted there is free.
		if _, err = opened.Publish(t.Context(), one(address(3, true))); !errors.Is(err, engine.ErrConflict) {
			t.Errorf("a record held on one of two links: %v", err)
		}

		there, err = opened.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(2, true)}, Interfaces: only("en1")},
		)
		if err != nil {
			t.Fatalf("a record on a link where a refused set wanted it: %v", err)
		}

		_, _ = here.Close(), there.Close()

		// What others may say too holds nothing, whichever came first.
		shared, err := opened.Publish(t.Context(), one(address(1, false)))
		if err != nil {
			t.Fatal(err)
		}

		alone, err := opened.Publish(t.Context(), one(address(2, true)))
		if err != nil {
			t.Fatalf("a record beside one others may say too: %v", err)
		}

		_, _ = shared.Close(), alone.Close()

		// Two at once: one of them has it, whichever.
		var (
			asking sync.WaitGroup
			failed [2]error
		)

		for index := range failed {
			asking.Go(func() {
				_, failed[index] = opened.Publish(t.Context(), one(address(byte(index+4), true)))
			})
		}

		asking.Wait()

		if (failed[0] == nil) == (failed[1] == nil) || !errors.Is(errors.Join(failed[:]...), engine.ErrConflict) {
			t.Errorf("two sets of one record at once: %v and %v", failed[0], failed[1])
		}
	})
}

// A link that comes up later, where two sets then want one record: the
// one published first keeps it, and the other is lost, as it would be
// to another host. What was published after them is put on the link as
// if neither had been.
func TestARecordHeldOnALinkThatComesUp(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var wires mdnstest.Network

		host := wires.Host(port("en0", lan, 1))
		opened := open(t, engine.Config{Network: host})
		other := join(t, &wires, port("en1", wifi, 9))

		there := func(record wire.Record) *engine.Publication {
			published, err := opened.Publish(
				t.Context(),
				engine.Set{Records: []wire.Record{record}, Interfaces: only("en1")},
			)
			if err != nil {
				t.Fatalf("a record wanted where there is no link yet: %v", err)
			}

			return published
		}

		first, second := there(address(1, true)), there(address(2, true))
		third, fourth := there(named("third", 120)), there(named("fourth", 120))

		host.Plug(port("en1", wifi, 2))
		time.Sleep(5 * time.Second)
		synctest.Wait()

		select {
		case <-second.Done():
			if !errors.Is(second.Err(), engine.ErrConflict) {
				t.Errorf("the second set ended with %v", second.Err())
			}
		default:
			t.Error("the second set still stands")
		}

		said := map[string]bool{}

		for len(other.heard) > 0 {
			for _, answer := range (<-other.heard).Answers {
				said[answer.Name[0]] = true
			}
		}

		for index, kept := range []*engine.Publication{first, third, fourth} {
			select {
			case <-kept.Done():
				t.Errorf("set %d of those kept ended with %v", index+1, kept.Err())
			default:
			}
		}

		if !said["kitchen"] || !said["third"] || !said["fourth"] {
			t.Errorf("said on the link that came up: %v", said)
		}
	})
}

// A set that changes what it says to a record another set holds is
// refused the change, and stays as it was; one that changes to what no
// one holds is not.
func TestARecordHeldWhenASetChanges(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var wires mdnstest.Network

		machine := wires.Host(port("en0", lan, 1))
		opened := open(t, engine.Config{Network: machine})
		other := join(t, &wires, port("en0", lan, 9))
		later := join(t, &wires, port("en1", wifi, 9))

		if _, err := opened.Publish(t.Context(), engine.Set{Records: []wire.Record{address(1, true)}}); err != nil {
			t.Fatal(err)
		}

		beside, err := opened.Publish(t.Context(), engine.Set{Records: []wire.Record{info()}})
		if err != nil {
			t.Fatal(err)
		}

		if err = beside.Update([]wire.Record{address(2, true)}); !errors.Is(err, engine.ErrConflict) {
			t.Errorf("a set changed to a record that is held: %v", err)
		}

		time.Sleep(10 * time.Second)
		synctest.Wait()

		other.drain()

		// It still says what it said, and the address is said once.
		other.ask(t, wire.Question{Name: hostName(), Type: wire.TypeANY, Class: wire.ClassIN})
		time.Sleep(time.Second)
		synctest.Wait()

		kinds := map[uint16]int{}

		for len(other.heard) > 0 {
			for _, answer := range (<-other.heard).Answers {
				kinds[answer.Type()]++
			}
		}

		if kinds[13] != 1 || kinds[wire.TypeA] != 1 {
			t.Errorf("after the refused change, said %v", kinds)
		}

		// On a link that comes up after the refusal too: the set is what
		// it was, not what it was refused.
		machine.Plug(port("en1", wifi, 2))
		time.Sleep(10 * time.Second)
		synctest.Wait()

		kinds = map[uint16]int{}

		for len(later.heard) > 0 {
			for _, answer := range (<-later.heard).Answers {
				if answer.Data == address(2, true).Data {
					t.Errorf("the refused record is said on a link that came up: %+v", answer)
				}

				kinds[answer.Type()]++
			}
		}

		if kinds[13] == 0 || kinds[wire.TypeA] == 0 {
			t.Errorf("on the link that came up, said %v", kinds)
		}

		changed := info()
		changed.Data = wire.Opaque{Kind: 13, Bytes: []byte("\x03X86")}

		if err = beside.Update([]wire.Record{changed}); err != nil {
			t.Errorf("a set changed to what no one holds: %v", err)
		}

		// What others may say too holds nothing and is held by nothing.
		if err = beside.Update([]wire.Record{changed, address(2, false)}); err != nil {
			t.Errorf("a set changed to a record others may say too: %v", err)
		}
	})
}

// An interface that gains an address of a type the host did not say,
// where one set is the host's and another holds a record of that type
// under the host's name: the set published first keeps the name, the
// other is lost, and one of them only answers for it. Whether the
// address comes with a link, the family being new to the interface, or
// on a link that was there, the family having been kept from the
// host's set by its choice of addresses.
func TestARecordHeldWhenAnInterfaceGainsAnAddress(t *testing.T) {
	t.Parallel()

	six := wire.Record{
		Name: hostName(), Class: wire.ClassIN, TTL: 120, Flush: true,
		Data: wire.Address{Addr: netip.MustParseAddr("2001:db8::77")},
	}
	four := netip.MustParsePrefix("192.0.2.1/24")
	local := netip.MustParsePrefix("fe80::1/64")
	global := netip.MustParsePrefix("2001:db8::1/64")
	routed := func(_ transport.Interface, addr netip.Addr) bool { return !addr.IsLinkLocalUnicast() }

	for what, row := range map[string]struct {
		before    []netip.Prefix
		hostFirst bool
	}{
		"with a link, the host first":       {before: []netip.Prefix{four}, hostFirst: true},
		"with a link, the record first":     {before: []netip.Prefix{four}},
		"on a link there, the host first":   {before: []netip.Prefix{four, local}, hostFirst: true},
		"on a link there, the record first": {before: []netip.Prefix{four, local}},
	} {
		synctest.Test(t, func(t *testing.T) {
			var wires mdnstest.Network

			machine := wires.Host(mdnstest.Port{Interface: "en0", Wire: lan, Addrs: row.before})
			opened := open(t, engine.Config{Network: machine})
			other := join(t, &wires, port("en0", lan, 9))
			sets := []engine.Set{{Host: hostName(), Addresses: routed}, {Records: []wire.Record{six}}}

			if !row.hostFirst {
				slices.Reverse(sets)
			}

			var published []*engine.Publication

			for _, set := range sets {
				one, err := opened.Publish(t.Context(), set)
				if err != nil {
					t.Fatalf("%s: %v", what, err)
				}

				published = append(published, one)
			}

			machine.Plug(mdnstest.Port{Interface: "en0", Wire: lan, Addrs: append(slices.Clone(row.before), global)})
			time.Sleep(10 * time.Second)
			synctest.Wait()

			select {
			case <-published[0].Done():
				t.Errorf("%s: the set published first ended with %v", what, published[0].Err())
			default:
			}

			select {
			case <-published[1].Done():
				if !errors.Is(published[1].Err(), engine.ErrConflict) {
					t.Errorf("%s: the set published second ended with %v", what, published[1].Err())
				}
			default:
				t.Errorf("%s: the set published second still stands", what)
			}

			// A host's set that lost says nothing of the address it gained,
			// goodbye included: it never had it.
			for len(other.heard) > 0 {
				for _, answer := range (<-other.heard).Answers {
					if address, is := answer.Data.(wire.Address); is && !row.hostFirst &&
						address.Addr == global.Addr() {
						t.Errorf("%s: the set that lost said %+v", what, answer)
					}
				}
			}

			// One address of that type is answered with, the keeper's.
			other.ask(t, wire.Question{Name: hostName(), Type: wire.TypeAAAA, Class: wire.ClassIN})
			time.Sleep(time.Second)
			synctest.Wait()

			var said []netip.Addr

			for len(other.heard) > 0 {
				for _, answer := range (<-other.heard).Answers {
					if address, is := answer.Data.(wire.Address); is && answer.TTL > 0 {
						said = append(said, address.Addr)
					}
				}
			}

			want := netip.MustParseAddr("2001:db8::77")
			if row.hostFirst {
				want = global.Addr()
			}

			if !slices.Equal(said, []netip.Addr{want}) {
				t.Errorf("%s: answered with %v, not %v", what, said, want)
			}
		})
	}
}

// Two hosts' sets, the second of which also holds a record under the
// first's name: when the first gains an address of that type the second
// ends, and its ending is not the first's.
func TestARecordHeldBetweenTwoHosts(t *testing.T) {
	t.Parallel()

	six := wire.Record{
		Name: hostName(), Class: wire.ClassIN, TTL: 120, Flush: true,
		Data: wire.Address{Addr: netip.MustParseAddr("2001:db8::77")},
	}
	routed := func(_ transport.Interface, addr netip.Addr) bool { return !addr.IsLinkLocalUnicast() }
	before := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("fe80::1/64")}

	for what, kitchenFirst := range map[string]bool{"the host first": true, "the other host first": false} {
		synctest.Test(t, func(t *testing.T) {
			var wires mdnstest.Network

			machine := wires.Host(mdnstest.Port{Interface: "en0", Wire: lan, Addrs: before})
			opened := open(t, engine.Config{Network: machine})
			sets := []engine.Set{
				{Host: hostName(), Addresses: routed},
				{Host: []string{"pantry", "local"}, Addresses: routed, Records: []wire.Record{six}},
			}

			if !kitchenFirst {
				slices.Reverse(sets)
			}

			var published []*engine.Publication

			for _, set := range sets {
				one, err := opened.Publish(t.Context(), set)
				if err != nil {
					t.Fatalf("%s: %v", what, err)
				}

				published = append(published, one)
			}

			machine.Plug(mdnstest.Port{
				Interface: "en0", Wire: lan,
				Addrs: append(slices.Clone(before), netip.MustParsePrefix("2001:db8::1/64")),
			})
			time.Sleep(10 * time.Second)
			synctest.Wait()

			select {
			case <-published[0].Done():
				t.Errorf("%s: the set published first ended with %v", what, published[0].Err())
			default:
			}

			select {
			case <-published[1].Done():
			default:
				t.Errorf("%s: the set published second still stands", what)
			}
		})
	}
}

// What a host's set says that others may say too is no one's alone,
// when its addresses change as when it was published: a set that holds
// a record of that name and type is not lost for it, nor is the host's.
func TestARecordOthersMaySayWhenAnAddressChanges(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var wires mdnstest.Network

		machine := wires.Host(port("en0", lan, 1))
		opened := open(t, engine.Config{Network: machine})

		shared := info()
		shared.Flush = false

		host, err := opened.Publish(t.Context(), engine.Set{Host: hostName(), Records: []wire.Record{shared}})
		if err != nil {
			t.Fatal(err)
		}

		alone, err := opened.Publish(t.Context(), engine.Set{Records: []wire.Record{info()}})
		if err != nil {
			t.Fatal(err)
		}

		machine.Plug(mdnstest.Port{Interface: "en0", Wire: lan, Addrs: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("192.0.2.5/24"),
		}})
		time.Sleep(10 * time.Second)
		synctest.Wait()

		for what, kept := range map[string]*engine.Publication{"the host's set": host, "the other": alone} {
			select {
			case <-kept.Done():
				t.Errorf("%s ended with %v", what, kept.Err())
			default:
			}
		}
	})
}
