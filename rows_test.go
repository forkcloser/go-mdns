package mdns_test

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

// station is a host that speaks for itself: it says what a test has it
// say, and keeps the questions it hears.
type station struct {
	links map[string]transport.Link
	asked chan wire.Question
	told  chan wire.Record
}

func stationed(t *testing.T, network *mdnstest.Network, ports ...mdnstest.Port) *station {
	t.Helper()

	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	placed := &station{
		links: map[string]transport.Link{},
		asked: make(chan wire.Question, 4096),
		told:  make(chan wire.Record, 4096),
	}
	up := make(chan transport.Link, len(ports))

	var running sync.WaitGroup

	running.Go(func() {
		_ = network.Host(ports...).Watch(ctx, func(event transport.Event) {
			if event.Change == transport.Up {
				up <- event.Link
			}
		})
	})

	for range ports {
		link := <-up
		placed.links[link.Interface().Name] = link

		running.Go(func() {
			buf := make([]byte, transport.MaxPacket)

			for {
				size, _, _, err := link.Read(buf)
				if err != nil {
					return
				}

				message, err := wire.Parse(buf[:size])
				if err != nil {
					continue
				}

				if message.Header.Response {
					for _, answer := range message.Answers {
						placed.told <- answer
					}

					continue
				}

				for _, question := range message.Questions {
					placed.asked <- question
				}
			}
		})
	}

	t.Cleanup(func() {
		stop()
		running.Wait()
	})

	return placed
}

// say says records to everyone on one of the station's wires.
func (s *station) say(t *testing.T, on string, records ...wire.Record) {
	t.Helper()

	link, has := s.links[on]
	if !has {
		t.Fatalf("the station has no interface %s", on)
	}

	say(t, link, records...)
}

// questions is the types of the questions the station hears in a while,
// each once, in order.
func (s *station) questions(during time.Duration) []uint16 {
	time.Sleep(during)
	synctest.Wait()

	var kinds []uint16

	for len(s.asked) > 0 {
		if question := <-s.asked; !slices.Contains(kinds, question.Type) {
			kinds = append(kinds, question.Type)
		}
	}

	slices.Sort(kinds)

	return kinds
}

// answers is how many records of one type the station hears in a while.
func (s *station) answers(during time.Duration, kind uint16) int {
	time.Sleep(during)
	synctest.Wait()

	count := 0

	for len(s.told) > 0 {
		if record := <-s.told; record.Data.Type() == kind {
			count++
		}
	}

	return count
}

func of(name []string, ttl uint32, flush bool, data wire.Data) wire.Record {
	return wire.Record{Name: name, Class: wire.ClassIN, TTL: ttl, Flush: flush, Data: data}
}

func typed() []string    { return []string{"_http", "_tcp", "local"} }
func instance() []string { return []string{"Kitchen", "_http", "_tcp", "local"} }
func hosted() []string   { return []string{"oven", "local"} }

// A name that has no room for a number makes room: it stays a label,
// and text.
func TestANumberedNameFits(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		long := strings.Repeat("é", 31) + "x"
		service := mdns.Service{Name: long, Type: "_http._tcp", Port: 80}

		if _, err := peer(t, &network, "first", wired("en0", "lan", "1")).Announce(t.Context(), service); err != nil {
			t.Fatal(err)
		}

		second, err := peer(t, &network, "second", wired("en0", "lan", "2")).Announce(t.Context(), service)
		if err != nil {
			t.Fatal(err)
		}

		if got := second.Name(); len(got) > 63 || !utf8.ValidString(got) || !strings.HasSuffix(got, " (2)") ||
			!strings.HasPrefix(long, strings.TrimSuffix(got, " (2)")) ||
			len(got) < 60 {
			t.Errorf("renamed to %q, %d bytes", got, len(got))
		}
	})
}

// The host's name is asked for once, for all its services; and an
// Announce that is given up while it is asked for is given up.
func TestTheHostsNameIsTakenOnce(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))

		if _, err := kitchen.Announce(
			timeout(t, 100*time.Millisecond),
			mdns.Service{Type: "_http._tcp", Port: 80},
		); !errors.Is(
			err,
			context.DeadlineExceeded,
		) {
			t.Fatalf("an Announce given up: %v", err)
		}

		if _, err := kitchen.Announce(t.Context(), mdns.Service{Type: "_http._tcp", Port: 80}); err != nil {
			t.Fatal(err)
		}

		// A second service: its own name to ask for, a second at most,
		// and not the host's again.
		began := time.Now()

		if _, err := kitchen.Announce(
			t.Context(),
			mdns.Service{Name: "Second", Type: "_http._tcp", Port: 81},
		); err != nil ||
			time.Since(began) > time.Second {
			t.Errorf("announced after %s, %v", time.Since(began), err)
		}
	})
}

// A host that turns up later with this host's name: another is taken,
// and the host's own services say they are there. One announced for
// another host stays where it was.
func TestAHostRenamedLater(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"))
		other := stationed(t, &network, wired("en0", "lan", "9"))
		found := browse(t, browser, mdns.Query{Type: "_http._tcp"})

		for _, service := range []mdns.Service{
			{Name: "Own", Type: "_http._tcp", Port: 80},
			{Name: "Other", Type: "_http._tcp", Port: 81, Host: "garden", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.40")}},
		} {
			if _, err := kitchen.Announce(t.Context(), service); err != nil {
				t.Fatal(err)
			}
		}

		time.Sleep(5 * time.Second)

		if got := found.stands(t); got["Own"].Host != "kitchen.local" || got["Other"].Host != "garden.local" {
			t.Fatalf("found %+v", got)
		}

		theirs := of([]string{"kitchen", "local"}, 120, true, wire.Address{Addr: netip.MustParseAddr("192.0.2.9")})

		other.say(t, "en0", theirs)
		time.Sleep(300 * time.Millisecond)
		other.say(t, "en0", theirs)
		time.Sleep(5 * time.Second)

		got := found.stands(t)
		if kitchen.Hostname() != "kitchen-2.local" || got["Own"].Host != "kitchen-2.local" ||
			got["Other"].Host != "garden.local" ||
			!reflect.DeepEqual(got["Own"].Addrs, []netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
			t.Errorf("the host is %q, and found %+v", kitchen.Hostname(), got)
		}
	})
}

// A host announced for a service is that host's name alone, on the
// interfaces of the service, for as long as the service is announced.
func TestAHostAnnouncedForAService(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		beside := peer(t, &network, "beside", wired("en0", "lan", "1"), wired("en1", "wifi", "11"))
		rival := peer(t, &network, "rival", wired("en0", "lan", "2"))
		wire := peer(t, &network, "wire", wired("en0", "lan", "3"))
		air := peer(t, &network, "air", wired("en0", "wifi", "13"))

		camera := mdns.Service{
			Name:  "Camera",
			Type:  "_rtsp._tcp",
			Port:  554,
			Host:  "garden",
			Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.40")},
		}
		if _, err := beside.Announce(t.Context(), camera); err != nil {
			t.Fatal(err)
		}

		// Another host cannot say the garden is somewhere else.
		theirs := camera
		theirs.Name, theirs.Addrs = "Theirs", []netip.Addr{netip.MustParseAddr("192.0.2.41")}

		if _, err := rival.Announce(t.Context(), theirs); !errors.Is(err, mdns.ErrConflict) {
			t.Errorf("a host that is another's, at other addresses: %v", err)
		}

		// A service that is not announced leaves its host unannounced.
		taken := mdns.Service{
			Name:   "Camera",
			Type:   "_rtsp._tcp",
			Port:   554,
			Host:   "shed",
			Addrs:  camera.Addrs,
			Rename: mdns.Never,
		}
		if _, err := rival.Announce(t.Context(), taken); !errors.Is(err, mdns.ErrConflict) {
			t.Errorf("a name that is taken: %v", err)
		}

		// A second after the goodbye that took it back.
		time.Sleep(2 * time.Second)

		if _, err := wire.LookupHost(timeout(t, 3*time.Second), "shed"); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("the host of a service that was not announced: %v", err)
		}

		// On the interfaces of the service, and no other.
		attic := mdns.Service{
			Name:       "Attic",
			Type:       "_rtsp._tcp",
			Port:       554,
			Host:       "attic",
			Addrs:      camera.Addrs,
			Interfaces: mdns.On("en1"),
		}
		if _, err := beside.Announce(t.Context(), attic); err != nil {
			t.Fatal(err)
		}

		if _, err := wire.LookupHost(timeout(t, 3*time.Second), "attic"); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("on the wire, a host announced over the air: %v", err)
		}

		if got, err := air.LookupHost(t.Context(), "attic"); err != nil || !reflect.DeepEqual(got, camera.Addrs) {
			t.Errorf("over the air: %v, %v", got, err)
		}
	})
}

// A service says for how long it may be remembered, for every record of
// it; not for less than a second.
func TestHowLongAServiceIsRemembered(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"))

		for name, row := range map[string]struct{ asked, want time.Duration }{
			"Ten":   {10 * time.Second, 10 * time.Second},
			"Short": {time.Millisecond, time.Second},
		} {
			if _, err := kitchen.Announce(
				t.Context(),
				mdns.Service{Name: name, Type: "_http._tcp", Port: 80, TTL: row.asked},
			); err != nil {
				t.Fatal(err)
			}

			ctx, stop := context.WithCancel(t.Context())
			seen := 0

			_ = browser.Ask(
				ctx,
				mdns.Question{Name: mdns.Name{name, "_http", "_tcp", "local"}, Type: mdns.TypeANY},
				func(_ mdns.Change, answer mdns.Answer) {
					if answer.Record.TTL != row.want {
						t.Errorf("%s: a record good for %s, want %s", name, answer.Record.TTL, row.want)
					}

					seen++

					if seen == 2 {
						stop()
					}
				},
			)
		}
	})
}

// What a browser takes for an instance: a name under its type, on the
// interfaces its type lists it on, once its text is known; with the
// addresses it has when they come, an IPv6 link-local one saying which
// interface it is good on. And Resolve waits for an address.
func TestWhatABrowserTakesForAnInstance(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := stationed(t, &network, wired("eth0", "lan", "9"), wired("eth1", "wifi", "19"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"), wired("en1", "wifi", "12"))
		found := browse(t, browser, mdns.Query{Type: "_http._tcp"})
		listed := browse(t, browser, mdns.Query{Type: "_http._tcp", Unresolved: true})

		// Listed under the type, and not an instance of it.
		other.say(t, "eth0",
			of(typed(), 4500, false, wire.Pointer{}),
			of(typed(), 4500, false, wire.Pointer{Target: []string{"x", "local"}}),
			of(typed(), 4500, false, wire.Pointer{Target: []string{"Other", "_ipp", "_tcp", "local"}}),
			of(typed(), 4500, false, wire.Pointer{Target: []string{"Deep", "er", "_http", "_tcp", "local"}}),
		)
		found.nothing(t)
		listed.nothing(t)

		resolved := make(chan mdns.Instance, 1)

		go func() {
			got, err := browser.Resolve(t.Context(), "Kitchen", "_http._tcp")
			if err != nil {
				t.Error(err)
			}

			resolved <- got
		}()

		// Listed on the wire; where it is said on both; no text yet.
		where := of(instance(), 120, true, wire.Service{Port: 80, Target: hosted()})

		other.say(t, "eth0", of(typed(), 4500, false, wire.Pointer{Target: instance()}), where)
		other.say(t, "eth1", where)
		found.nothing(t)

		text := of(instance(), 4500, true, wire.Text{})
		other.say(t, "eth0", text)
		other.say(t, "eth1", text)

		want := mdns.Instance{
			Name:       "Kitchen",
			Type:       "_http._tcp",
			Interfaces: []mdns.Interface{en(1, "en0")},
			Host:       "oven.local",
			Port:       80,
			Text:       mdns.TXT{},
		}

		if got := found.stands(t); !reflect.DeepEqual(got, map[string]mdns.Instance{"Kitchen": want}) {
			t.Errorf("found\n%+v\nwant\n%+v", got, want)
		}

		select {
		case got := <-resolved:
			t.Fatalf("resolved with no address: %+v", got)
		default:
		}

		other.say(t, "eth0", of(hosted(), 120, true, wire.Address{Addr: netip.MustParseAddr("fe80::9")}))

		want.Addrs = []netip.Addr{netip.MustParseAddr("fe80::9%en0")}

		if got := found.stands(t); !reflect.DeepEqual(got, map[string]mdns.Instance{"Kitchen": want}) {
			t.Errorf("found\n%+v\nwant\n%+v", got, want)
		}

		// By name, it is wherever it is heard: no type lists it.
		want.Interfaces = []mdns.Interface{en(1, "en0"), en(2, "en1")}

		if got := <-resolved; !reflect.DeepEqual(got, want) {
			t.Errorf("resolved\n%+v\nwant\n%+v", got, want)
		}

		// Among the types there are: a type, and not any name.
		ctx, stop := context.WithCancel(t.Context())
		enumeration := []string{"_services", "_dns-sd", "_udp", "local"}

		other.say(t, "eth0", of(enumeration, 4500, false, wire.Pointer{Target: []string{"x", "local"}}))
		synctest.Wait()
		other.say(t, "eth0", of(enumeration, 4500, false, wire.Pointer{Target: typed()}))

		_ = browser.ServiceTypes(ctx, func(_ mdns.Change, kind mdns.ServiceType) {
			if kind.Type != "_http._tcp" {
				t.Errorf("told of the type %q", kind.Type)
			}

			stop()
		})
	})
}

// A browser asks for what it needs and no more: nothing but the list
// when that is all that is wanted, and nothing of an instance or of its
// host once the instance is gone.
func TestWhatABrowserAsks(t *testing.T) {
	t.Parallel()

	records := func() []wire.Record {
		return []wire.Record{
			of(typed(), 4500, false, wire.Pointer{Target: instance()}),
			of(instance(), 120, true, wire.Service{Port: 80, Target: hosted()}),
			of(instance(), 4500, true, wire.Text{}),
			of(hosted(), 120, true, wire.Address{Addr: netip.MustParseAddr("192.0.2.9")}),
		}
	}

	gone := func(record wire.Record) wire.Record {
		record.TTL, record.Flush = 0, false

		return record
	}

	for what, row := range map[string]struct {
		query mdns.Query
		// goes is the record said goodbye to once the instance is found,
		// and asks the types asked for after: the list alone.
		goes int
		asks []uint16
	}{
		"only the list":                  {query: mdns.Query{Type: "_http._tcp", Unresolved: true}, goes: -1, asks: []uint16{wire.TypePTR}},
		"an instance no longer listed":   {query: mdns.Query{Type: "_http._tcp"}, goes: 0, asks: []uint16{wire.TypePTR}},
		"an instance no longer anywhere": {query: mdns.Query{Type: "_http._tcp"}, goes: 1, asks: []uint16{wire.TypePTR, wire.TypeTXT, wire.TypeSRV}},
		"an instance that stays":         {query: mdns.Query{Type: "_http._tcp"}, goes: -1, asks: []uint16{wire.TypeA, wire.TypePTR, wire.TypeTXT, wire.TypeAAAA, wire.TypeSRV}},
	} {
		t.Run(what, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var network mdnstest.Network

				other := stationed(t, &network, wired("eth0", "lan", "9"))
				found := browse(t, peer(t, &network, "browser", wired("en0", "lan", "2")), row.query)

				other.say(t, "eth0", records()...)
				found.next(t, mdns.Found)

				if row.goes >= 0 {
					other.say(t, "eth0", gone(records()[row.goes]))
					found.next(t, mdns.Lost)
				}

				other.questions(time.Minute)

				if got := other.questions(3 * time.Hour); !reflect.DeepEqual(got, row.asks) {
					t.Errorf("asked for the types %v, want %v", got, row.asks)
				}
			})
		})
	}
}

// What is told as a change: other addresses, and a text entry that had
// no value and has an empty one.
func TestWhatChangesAnInstance(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		machine := network.Host(wired("en0", "lan", "1"))

		kitchen, err := mdns.Open(t.Context(), mdns.Config{Network: machine, Hostname: "kitchen"})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = kitchen.Close() }()

		synctest.Wait()

		found := browse(t, peer(t, &network, "browser", wired("en0", "lan", "2")), mdns.Query{Type: "_http._tcp"})

		announced, err := kitchen.Announce(
			t.Context(),
			mdns.Service{Name: "Kitchen", Type: "_http._tcp", Port: 80, Text: mdns.TXT{{Key: "flag"}}},
		)
		if err != nil {
			t.Fatal(err)
		}

		found.next(t, mdns.Found)
		time.Sleep(5 * time.Second)

		if err = announced.Update(t.Context(), mdns.TXT{{Key: "flag", Value: []byte{}}}); err != nil {
			t.Fatal(err)
		}

		if got := found.next(t, mdns.Changed).instance.Text; len(got) != 1 || got[0].Value == nil {
			t.Errorf("changed to the text %+v", got)
		}

		// Later: what was heard within a second of what takes its place
		// is not taken for replaced (RFC 6762 section 10.2).
		time.Sleep(5 * time.Second)
		machine.Plug(wired("en0", "lan", "5"))
		time.Sleep(2 * time.Second)

		if got := found.stands(t)["Kitchen"].Addrs; !reflect.DeepEqual(
			got,
			[]netip.Addr{netip.MustParseAddr("192.0.2.5")},
		) {
			t.Errorf("the addresses are %v", got)
		}
	})
}

// LookupHost gives a host a moment to say all its addresses, and says
// them in the order of their families each time.
func TestAHostsAddressesAMomentApart(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := stationed(t, &network, wired("eth0", "lan", "9"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"))
		ipv4, ipv6 := netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9")

		go func() {
			<-other.asked
			other.say(t, "eth0", of(hosted(), 120, true, wire.Address{Addr: ipv6}))
			time.Sleep(50 * time.Millisecond)
			other.say(t, "eth0", of(hosted(), 120, true, wire.Address{Addr: ipv4}))
		}()

		began := time.Now()

		got, err := browser.LookupHost(t.Context(), "oven")
		if err != nil || !reflect.DeepEqual(got, []netip.Addr{ipv6, ipv4}) || time.Since(began) > 300*time.Millisecond {
			t.Errorf("the host is at %v after %s, %v", got, time.Since(began), err)
		}

		// Both known: in the order of their families, every time.
		for range 20 {
			if got, err = browser.LookupHost(
				t.Context(),
				"oven",
			); err != nil ||
				!reflect.DeepEqual(got, []netip.Addr{ipv4, ipv6}) {
				t.Fatalf("the host is at %v, %v", got, err)
			}
		}
	})
}

// A service announced while the host is losing its name is pointed at
// the name the host ends up with, whichever of the two comes first.
func TestAServiceAnnouncedAsTheHostIsRenamed(t *testing.T) {
	t.Parallel()

	for _, before := range []time.Duration{5 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 150 * time.Millisecond, 200 * time.Millisecond} {
		// How long the host takes to ask for its next name is drawn, so
		// one round may miss what twenty do not.
		for range 20 {
			renamedWhileAnnouncing(t, before)
		}
	}
}

func renamedWhileAnnouncing(t *testing.T, before time.Duration) {
	t.Helper()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"))
		other := stationed(t, &network, wired("en0", "lan", "9"))
		found := browse(t, browser, mdns.Query{Type: "_http._tcp"})

		if _, err := kitchen.Announce(
			t.Context(),
			mdns.Service{Name: "Own", Type: "_http._tcp", Port: 80},
		); err != nil {
			t.Fatal(err)
		}

		time.Sleep(5 * time.Second)

		theirs := of([]string{"kitchen", "local"}, 120, true, wire.Address{Addr: netip.MustParseAddr("192.0.2.9")})
		other.say(t, "en0", theirs)

		late := make(chan error, 1)

		go func() {
			time.Sleep(300*time.Millisecond - before)

			_, err := kitchen.Announce(t.Context(), mdns.Service{Name: "Late", Type: "_http._tcp", Port: 81})
			late <- err
		}()

		time.Sleep(300 * time.Millisecond)
		other.say(t, "en0", theirs)

		if err := <-late; err != nil {
			t.Fatalf("%s before: %v", before, err)
		}

		time.Sleep(20 * time.Second)

		got := found.stands(t)
		if kitchen.Hostname() != "kitchen-2.local" || got["Own"].Host != "kitchen-2.local" ||
			got["Late"].Host != "kitchen-2.local" {
			t.Errorf(
				"%s before: the host is %q, Own on %q, Late on %q at %v",
				before,
				kitchen.Hostname(),
				got["Own"].Host,
				got["Late"].Host,
				got["Late"].Addrs,
			)
		}
	})
}

// A service is announced three times, as RFC 6762 section 8.3 allows,
// and no more than that for having been pointed at the host it already was on.
func TestAServiceIsAnnouncedOnce(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		other := stationed(t, &network, wired("en0", "lan", "9"))

		time.Sleep(10 * time.Second)
		other.answers(0, wire.TypeSRV)

		if _, err := kitchen.Announce(
			t.Context(),
			mdns.Service{Name: "Own", Type: "_http._tcp", Port: 80},
		); err != nil {
			t.Fatal(err)
		}

		if got := other.answers(30*time.Second, wire.TypeSRV); got != 3 {
			t.Errorf("the service was said %d times, not 3", got)
		}
	})
}

// A service that does not say how long it is to be remembered is given
// what RFC 6762 section 10 recommends, record by record.
func TestHowLongAServiceIsRememberedByDefault(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"))

		if _, err := kitchen.Announce(
			t.Context(),
			mdns.Service{Name: "Kitchen", Type: "_http._tcp", Port: 80},
		); err != nil {
			t.Fatal(err)
		}

		lives := map[mdns.Type]time.Duration{}

		for name, kind := range map[string]mdns.Type{"Kitchen._http._tcp.local": mdns.TypeANY, "_http._tcp.local": mdns.TypePTR} {
			parsed, err := mdns.ParseName(name)
			if err != nil {
				t.Fatal(err)
			}

			ctx, stop := context.WithTimeout(t.Context(), time.Second)

			_ = browser.Ask(ctx, mdns.Question{Name: parsed, Type: kind}, func(_ mdns.Change, answer mdns.Answer) {
				lives[answer.Record.Data.Type()] = answer.Record.TTL
			})

			stop()
		}

		want := map[mdns.Type]time.Duration{
			mdns.TypeSRV: 2 * time.Minute,
			mdns.TypeTXT: 75 * time.Minute,
			mdns.TypePTR: 75 * time.Minute,
		}
		if !reflect.DeepEqual(lives, want) {
			t.Errorf("remembered for %v, want %v", lives, want)
		}
	})
}

// A service that goes and comes back is found again.
func TestAServiceThatComesBack(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		found := browse(t, peer(t, &network, "browser", wired("en0", "lan", "2")), mdns.Query{Type: "_http._tcp"})

		for range 2 {
			announced, err := kitchen.Announce(t.Context(), mdns.Service{Name: "Kitchen", Type: "_http._tcp", Port: 80})
			if err != nil {
				t.Fatal(err)
			}

			found.next(t, mdns.Found)

			_ = announced.Close()

			found.next(t, mdns.Lost)
		}
	})
}

// Which of an interface's addresses the host is announced at is the
// configuration's to say.
func TestTheAddressesAHostIsAnnouncedAt(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		both := mdnstest.Port{Interface: "en0", Wire: "lan", Addrs: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("192.0.2.9/24"),
		}}
		chosen := netip.MustParseAddr("192.0.2.9")

		kitchen, err := mdns.Open(t.Context(), mdns.Config{
			Network: network.Host(both), Hostname: "kitchen",
			Addresses: func(_ mdns.Interface, addr netip.Addr) bool { return addr == chosen },
		})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = kitchen.Close() }()

		if _, err = kitchen.Announce(t.Context(), mdns.Service{Type: "_http._tcp", Port: 80}); err != nil {
			t.Fatal(err)
		}

		got, err := peer(t, &network, "browser", wired("en0", "lan", "2")).LookupHost(t.Context(), "kitchen")
		if err != nil || !reflect.DeepEqual(got, []netip.Addr{chosen}) {
			t.Errorf("the host is at %v, %v", got, err)
		}
	})
}
