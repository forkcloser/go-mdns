package mdns_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// wired is an interface on a wire, at 192.0.2.last.
func wired(name, cable, last string) mdnstest.Port {
	return mdnstest.Port{
		Interface: name,
		Wire:      cable,
		Addrs:     []netip.Prefix{netip.MustParsePrefix("192.0.2." + last + "/24")},
	}
}

// peer opens a Peer for a host of a name, closed with the test, its
// links up.
func peer(t *testing.T, network *mdnstest.Network, hostname string, ports ...mdnstest.Port) *mdns.Peer {
	t.Helper()

	opened, err := mdns.Open(t.Context(), mdns.Config{Network: network.Host(ports...), Hostname: hostname})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = opened.Close() })
	synctest.Wait()

	return opened
}

// seen is what a Browse told its handler.
type seen struct {
	change   mdns.Change
	instance mdns.Instance
	at       time.Time
}

// browsing is a Browse under way.
type browsing struct {
	seen  chan seen
	ended chan error
	stop  context.CancelFunc
	// known is the instances stands has gathered.
	known map[string]mdns.Instance
}

func browse(t *testing.T, on *mdns.Peer, query mdns.Query) *browsing {
	t.Helper()

	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	started := &browsing{seen: make(chan seen, 64), ended: make(chan error, 1), stop: stop}

	go func() {
		started.ended <- on.Browse(ctx, query, func(change mdns.Change, instance mdns.Instance) {
			started.seen <- seen{change: change, instance: instance, at: time.Now()}
		})
	}()

	t.Cleanup(func() {
		stop()

		if err := <-started.ended; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, mdns.ErrClosed) {
			t.Errorf("a Browse ended with %v", err)
		}
	})

	synctest.Wait()

	return started
}

// next is the next thing the Browse tells, which has to be the change
// given.
func (b *browsing) next(t *testing.T, change mdns.Change) seen {
	t.Helper()

	// In a bubble time costs nothing, and the Peers' own timers keep it
	// going: what is never told is said so here, not waited for.
	var got seen

	select {
	case got = <-b.seen:
	case <-time.After(time.Hour):
		t.Fatalf("told nothing in an hour, waiting to be told %s", change)
	}

	if got.change != change {
		t.Fatalf("told %s of %+v, want %s", got.change, got.instance, change)
	}

	b.note(t, got)

	return got
}

// nothing says the Browse has nothing more to tell for now.
func (b *browsing) nothing(t *testing.T) {
	t.Helper()

	synctest.Wait()

	select {
	case got := <-b.seen:
		t.Fatalf("told %s of %+v, want nothing", got.change, got.instance)
	default:
	}
}

// note keeps what the Browse told: an instance is one by its name, its
// host and its port.
func (b *browsing) note(t *testing.T, told seen) {
	t.Helper()

	if b.known == nil {
		b.known = map[string]mdns.Instance{}
	}

	ident := fmt.Sprintf("%s at %s:%d", told.instance.Name, told.instance.Host, told.instance.Port)

	switch _, known := b.known[ident]; {
	case told.change == mdns.Found && known, told.change != mdns.Found && !known:
		t.Errorf("told %s of %q, known %t", told.change, ident, known)
	case told.change == mdns.Lost:
		delete(b.known, ident)
	default:
		b.known[ident] = told.instance
	}
}

// stands is the instances as the Browse has told of them so far, by
// name, now that everything that could happen without time passing
// has: where things stand, whatever steps they took.
func (b *browsing) stands(t *testing.T) map[string]mdns.Instance {
	t.Helper()

	synctest.Wait()

	for len(b.seen) > 0 {
		b.note(t, <-b.seen)
	}

	named := map[string]mdns.Instance{}
	for _, instance := range b.known {
		named[instance.Name] = instance
	}

	return named
}

func en(index int, name string) mdns.Interface { return mdns.Interface{Index: index, Name: name} }

// A service announced by one Peer is found by another, whole: its
// name, where it is and what it says; under its subtype and not under
// another; among the types there are; by its name alone; and its host
// by its name. Its text changes, and it goes.
func TestAServiceIsAnnouncedAndFound(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("eth0", "lan", "2"))

		all := browse(t, browser, mdns.Query{Type: "_http._tcp"})
		printers := browse(t, browser, mdns.Query{Type: "_http._tcp.", Subtype: "_printer"})
		scanners := browse(t, browser, mdns.Query{Type: "_http._tcp", Subtype: "_scanner"})

		announced, err := kitchen.Announce(t.Context(), mdns.Service{
			Name: "Kitchen display 2.4GHz", Type: "_http._tcp", Subtypes: []string{"_printer"}, Port: 8080,
			Text: mdns.TXT{{Key: "path", Value: []byte("/")}, {Key: "secure"}}, Priority: 1, Weight: 2,
		})
		if err != nil {
			t.Fatal(err)
		}

		want := mdns.Instance{
			Name: "Kitchen display 2.4GHz", Type: "_http._tcp", Interfaces: []mdns.Interface{en(1, "eth0")},
			Host: "kitchen.local", Port: 8080, Priority: 1, Weight: 2,
			Text:  mdns.TXT{{Key: "path", Value: []byte("/")}, {Key: "secure"}},
			Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		}

		for _, found := range []*browsing{all, printers} {
			if got := found.next(t, mdns.Found); !reflect.DeepEqual(got.instance, want) {
				t.Errorf("found\n%+v\nwant\n%+v", got.instance, want)
			}

			found.nothing(t)
		}

		scanners.nothing(t)

		if announced.Name() != want.Name || kitchen.Hostname() != "kitchen.local" || announced.Err() != nil {
			t.Errorf("announced as %q on %q, %v", announced.Name(), kitchen.Hostname(), announced.Err())
		}

		// Among the types there are.
		ctx, stop := context.WithCancel(t.Context())

		err = browser.ServiceTypes(ctx, func(change mdns.Change, kind mdns.ServiceType) {
			if want := (mdns.ServiceType{Type: "_http._tcp", Interfaces: []mdns.Interface{en(1, "eth0")}}); change != mdns.Found ||
				!reflect.DeepEqual(kind, want) {
				t.Errorf("told %s of the type %+v", change, kind)
			}

			stop()
		})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the types: %v", err)
		}

		// By its name, and its host by its own.
		resolved, err := browser.Resolve(t.Context(), "Kitchen display 2.4GHz", "_http._tcp")
		if err != nil || !reflect.DeepEqual(resolved, want) {
			t.Errorf("resolved\n%+v, %v", resolved, err)
		}

		addrs, err := browser.LookupHost(t.Context(), "KITCHEN.local.")
		if err != nil || !reflect.DeepEqual(addrs, want.Addrs) {
			t.Errorf("the host is at %v, %v", addrs, err)
		}

		// Its text changes.
		want.Text = mdns.TXT{{Key: "path", Value: []byte("/new")}}
		if err = announced.Update(t.Context(), want.Text); err != nil {
			t.Fatal(err)
		}

		if got := all.next(t, mdns.Changed); !reflect.DeepEqual(got.instance, want) {
			t.Errorf("changed to\n%+v", got.instance)
		}

		// It goes: lost a second after its goodbye.
		withdrawn := time.Now()

		if err = announced.Close(); err != nil {
			t.Fatal(err)
		}

		<-announced.Done()

		if got := all.next(
			t,
			mdns.Lost,
		); got.at.Sub(withdrawn) != time.Second || !reflect.DeepEqual(got.instance, want) ||
			!errors.Is(announced.Err(), mdns.ErrClosed) {
			t.Errorf("lost %s later: %+v, %v", got.at.Sub(withdrawn), got.instance, announced.Err())
		}

		all.nothing(t)

		if err = announced.Update(t.Context(), nil); !errors.Is(err, mdns.ErrClosed) {
			t.Errorf("changing the text of what is withdrawn: %v", err)
		}
	})
}

// A name another host has is put to Rename: numbered when there is
// none, refused by Never, and whatever a program answers.
func TestAServiceWhoseNameIsTaken(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		first := peer(t, &network, "first", wired("en0", "lan", "1"))
		second := peer(t, &network, "second", wired("en0", "lan", "2"))
		third := peer(t, &network, "third", wired("en0", "lan", "3"))
		service := mdns.Service{Name: "Kitchen", Type: "_http._tcp", Port: 80}

		for index, want := range []string{"Kitchen", "Kitchen (2)", "Kitchen (3)"} {
			announced, err := []*mdns.Peer{first, second, third}[index].Announce(t.Context(), service)
			if err != nil || announced.Name() != want {
				t.Fatalf("announced as %q, %v", announced.Name(), err)
			}
		}

		service.Rename = mdns.Never
		if _, err := third.Announce(t.Context(), service); !errors.Is(err, mdns.ErrConflict) {
			t.Errorf("a name that is taken, and no other wanted: %v", err)
		}

		// Asked with the name refused and how many were; what it answers
		// is tried, and what cannot be a name ends it.
		var asked []string

		service.Rename = func(taken string, tries int) (string, bool) {
			asked = append(asked, taken)

			return []string{"", "Kitchen (2)", "Pantry", string(make([]byte, 64))}[tries], tries < 3
		}

		announced, err := third.Announce(t.Context(), service)
		if err != nil || announced.Name() != "Pantry" || !reflect.DeepEqual(asked, []string{"Kitchen", "Kitchen (2)"}) {
			t.Errorf("announced as %q after asking for %q, %v", announced.Name(), asked, err)
		}

		service.Rename = func(string, int) (string, bool) { return "a\x00name", true }
		if _, err = third.Announce(t.Context(), service); !errors.Is(err, mdns.ErrConflict) {
			t.Errorf("a name that cannot be one: %v", err)
		}
	})
}

// A host's name is taken as a service's is, the first time something is
// announced; and a service with no name of its own has its host's.
func TestAHostWhoseNameIsTaken(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		first := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		second := peer(t, &network, "Kitchen.local.", wired("en0", "lan", "2"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "3"))
		found := browse(t, browser, mdns.Query{Type: "_http._tcp"})

		// Not before something is announced.
		if second.Hostname() != "Kitchen.local" {
			t.Errorf("the host is %q before anything is announced", second.Hostname())
		}

		for index, want := range []mdns.Instance{
			{Name: "kitchen", Host: "kitchen.local", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
			{Name: "Kitchen-2", Host: "Kitchen-2.local", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.2")}},
		} {
			announcer := []*mdns.Peer{first, second}[index]

			announced, err := announcer.Announce(t.Context(), mdns.Service{Type: "_http._tcp", Port: 80})
			if err != nil || announced.Name() != want.Name || announcer.Hostname() != want.Host {
				t.Fatalf("announced as %q on %q, %v", announced.Name(), announcer.Hostname(), err)
			}

			want.Type, want.Port, want.Interfaces, want.Text = "_http._tcp", 80, []mdns.Interface{
				en(1, "en0"),
			}, mdns.TXT{}

			if got := found.next(t, mdns.Found); !reflect.DeepEqual(got.instance, want) {
				t.Errorf("found\n%+v\nwant\n%+v", got.instance, want)
			}
		}

		// A host that will have no other name has none.
		stubborn, err := mdns.Open(
			t.Context(),
			mdns.Config{Network: network.Host(wired("en0", "lan", "4")), Hostname: "kitchen", Rename: mdns.Never},
		)
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = stubborn.Close() }()

		synctest.Wait()

		if _, err = stubborn.Announce(
			t.Context(),
			mdns.Service{Type: "_http._tcp", Port: 80},
		); !errors.Is(
			err,
			mdns.ErrConflict,
		) {
			t.Errorf("a host name that is taken, and no other wanted: %v", err)
		}
	})
}

// A service that is somewhere else is announced with the host it is on
// and the addresses that host is at; two on one host share it, and one
// host is at one set of addresses.
func TestAServiceThatIsSomewhereElse(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		beside := peer(t, &network, "beside", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"))
		found := browse(t, browser, mdns.Query{Type: "_rtsp._tcp"})

		camera := mdns.Service{
			Name:  "Garden camera",
			Type:  "_rtsp._tcp",
			Port:  554,
			Host:  "garden-camera",
			Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.40"), netip.MustParseAddr("2001:db8::40")},
		}

		announced, err := beside.Announce(t.Context(), camera)
		if err != nil {
			t.Fatal(err)
		}

		want := mdns.Instance{
			Name: "Garden camera", Type: "_rtsp._tcp", Interfaces: []mdns.Interface{en(1, "en0")},
			Host: "garden-camera.local", Port: 554, Text: mdns.TXT{}, Addrs: camera.Addrs,
		}

		if got := found.next(t, mdns.Found); !reflect.DeepEqual(got.instance, want) {
			t.Errorf("found\n%+v\nwant\n%+v", got.instance, want)
		}

		// Nothing of this host's own was announced for it.
		if _, err = browser.LookupHost(timeout(t, 3*time.Second), "beside"); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("the host beside the service: %v", err)
		}

		second := camera
		second.Name, second.Port = "Garden camera, low", 555

		low, err := beside.Announce(t.Context(), second)
		if err != nil {
			t.Fatal(err)
		}

		found.next(t, mdns.Found)

		second.Addrs = second.Addrs[:1]
		if _, err = beside.Announce(t.Context(), second); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("one host at two sets of addresses: %v", err)
		}

		// The host is announced for as long as one of the two is.
		_ = announced.Close()

		if got := found.next(t, mdns.Lost); got.instance.Port != 554 {
			t.Errorf("lost %+v", got.instance)
		}

		addrs, err := browser.LookupHost(t.Context(), "garden-camera")
		if err != nil || !reflect.DeepEqual(addrs, camera.Addrs) {
			t.Errorf("the camera is at %v, %v", addrs, err)
		}

		_ = low.Close()

		found.next(t, mdns.Lost)
		time.Sleep(2 * time.Second)

		if _, err = browser.LookupHost(
			timeout(t, 3*time.Second),
			"garden-camera",
		); !errors.Is(
			err,
			context.DeadlineExceeded,
		) {
			t.Errorf("the camera, once nothing is announced on it: %v", err)
		}
	})
}

func timeout(t *testing.T, after time.Duration) context.Context {
	t.Helper()

	ctx, stop := context.WithTimeout(t.Context(), after)
	t.Cleanup(stop)

	return ctx
}

// A service seen on two interfaces is one, which says both and has the
// addresses that reach it by either; it changes when one goes. One that
// is only to be listed has a name and where it is listed, and one
// announced on an interface is on no other.
func TestAServiceOnSeveralInterfaces(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"), wired("en1", "wifi", "11"))
		machine := network.Host(wired("eth0", "lan", "2"), wired("eth1", "wifi", "12"))

		browser, err := mdns.Open(t.Context(), mdns.Config{Network: machine})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = browser.Close() }()

		synctest.Wait()

		found := browse(t, browser, mdns.Query{Type: "_http._tcp"})
		listed := browse(t, browser, mdns.Query{Type: "_http._tcp", Unresolved: true})
		air := browse(t, browser, mdns.Query{Type: "_http._tcp", Interfaces: mdns.On("eth1")})

		if _, err = kitchen.Announce(
			t.Context(),
			mdns.Service{Name: "Kitchen", Type: "_http._tcp", Port: 80},
		); err != nil {
			t.Fatal(err)
		}

		both := []mdns.Interface{en(1, "eth0"), en(2, "eth1")}
		want := mdns.Instance{
			Name: "Kitchen", Type: "_http._tcp", Interfaces: both, Host: "kitchen.local", Port: 80, Text: mdns.TXT{},
			Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.11")},
		}
		over := want
		over.Interfaces, over.Addrs = both[1:], want.Addrs[1:]

		for what, row := range map[string]struct {
			browse *browsing
			want   map[string]mdns.Instance
		}{
			"everywhere":   {found, map[string]mdns.Instance{"Kitchen": want}},
			"listed":       {listed, map[string]mdns.Instance{"Kitchen": {Name: "Kitchen", Type: "_http._tcp", Interfaces: both}}},
			"over the air": {air, map[string]mdns.Instance{"Kitchen": over}},
		} {
			if got := row.browse.stands(t); !reflect.DeepEqual(got, row.want) {
				t.Errorf("%s:\n%+v\nwant\n%+v", what, got, row.want)
			}
		}

		// On one interface alone.
		if _, err = kitchen.Announce(
			t.Context(),
			mdns.Service{Name: "Wired", Type: "_http._tcp", Port: 81, Interfaces: mdns.On("en0")},
		); err != nil {
			t.Fatal(err)
		}

		if got := found.stands(t)["Wired"]; !reflect.DeepEqual(got.Interfaces, both[:1]) ||
			!reflect.DeepEqual(got.Addrs, want.Addrs[:1]) {
			t.Errorf("found %+v", got)
		}

		if got := air.stands(t); len(got) != 1 {
			t.Errorf("found over the air: %+v", got)
		}

		// An interface goes: what was seen on both is seen on one, at
		// the address that reaches it there; what was on that one alone
		// is lost.
		machine.Unplug("eth0")

		for what, browse := range map[string]*browsing{"everywhere": found, "over the air": air} {
			if got := browse.stands(t); !reflect.DeepEqual(got, map[string]mdns.Instance{"Kitchen": over}) {
				t.Errorf("%s, with one interface gone:\n%+v", what, got)
			}
		}
	})
}

// A host that turns up later with a service's name: the name is asked
// for again, lost, and another taken, which Rename is asked for and
// Name then gives. And a service that cannot be reached is doubted, and
// lost when no one answers for it.
func TestAServiceRenamedAndDoubted(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "3"))
		other := speaker(t, &network)
		found := browse(t, browser, mdns.Query{Type: "_http._tcp"})

		renamed := make(chan string, 4)

		announced, err := kitchen.Announce(t.Context(), mdns.Service{
			Name: "Kitchen", Type: "_http._tcp", Port: 80,
			Rename: func(taken string, tries int) (string, bool) {
				renamed <- taken

				return "Pantry", tries == 1
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		found.next(t, mdns.Found)
		time.Sleep(5 * time.Second)

		// Another host says it is where "Kitchen" is, and says so again
		// when asked: the name is its.
		instance := []string{"Kitchen", "_http", "_tcp", "local"}
		theirs := wire.Record{
			Name:  instance,
			Class: wire.ClassIN,
			TTL:   120,
			Flush: true,
			Data:  wire.Service{Port: 81, Target: []string{"other", "local"}},
		}

		say(t, other, theirs)
		time.Sleep(300 * time.Millisecond)
		say(t, other, theirs)

		if taken := <-renamed; taken != "Kitchen" {
			t.Errorf("asked for another name than %q", taken)
		}

		for announced.Name() != "Pantry" {
			time.Sleep(100 * time.Millisecond)
		}

		for {
			if got := <-found.seen; got.change == mdns.Found && got.instance.Name == "Pantry" {
				break
			}
		}

		// Taken again, and this time Rename has no other: it ends.
		pantry := theirs
		pantry.Name = []string{"Pantry", "_http", "_tcp", "local"}

		time.Sleep(5 * time.Second)
		say(t, other, pantry)
		time.Sleep(300 * time.Millisecond)
		say(t, other, pantry)

		<-announced.Done()

		if !errors.Is(announced.Err(), mdns.ErrConflict) || <-renamed != "Pantry" {
			t.Errorf("ended with %v", announced.Err())
		}
	})
}

// What cannot be reached is doubted, and forgotten when no one answers
// for it. What a Peer was doing ends with it, and what it cannot be
// asked is refused.
func TestWhatIsDoubtedAndWhatIsRefused(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"))
		found := browse(t, browser, mdns.Query{Type: "_http._tcp"})

		announced, err := kitchen.Announce(t.Context(), mdns.Service{Name: "Kitchen", Type: "_http._tcp", Port: 80})
		if err != nil {
			t.Fatal(err)
		}

		instance := found.next(t, mdns.Found).instance
		listed := browse(t, browser, mdns.Query{Type: "_http._tcp", Unresolved: true})
		listed.next(t, mdns.Found)

		// The wire is cut: the service is still thought to be there,
		// until a program says it could not be reached.
		network.Cut("lan")
		time.Sleep(30 * time.Second)
		found.nothing(t)

		doubted := time.Now()

		if err = browser.Reconfirm(instance); err != nil {
			t.Fatal(err)
		}

		if lost := found.next(t, mdns.Lost); lost.at.Sub(doubted) != 10*time.Second {
			t.Errorf("lost %s after it was doubted", lost.at.Sub(doubted))
		}

		// With where it is listed, and where its host is.
		if lost := listed.next(t, mdns.Lost); lost.at.Sub(doubted) != 10*time.Second {
			t.Errorf("no longer listed %s after it was doubted", lost.at.Sub(doubted))
		}

		if _, err = browser.LookupHost(
			timeout(t, 3*time.Second),
			"kitchen",
		); !errors.Is(
			err,
			context.DeadlineExceeded,
		) {
			t.Errorf("the host of what was doubted: %v", err)
		}

		for what, refused := range map[string]mdns.Instance{
			"a type that is none": {Name: "Kitchen", Type: "http", Host: "kitchen"},
			"no name":             {Type: "_http._tcp", Host: "kitchen"},
			"a host that is none": {Name: "Kitchen", Type: "_http._tcp", Host: "a..b"},
		} {
			if err = browser.Reconfirm(refused); !errors.Is(err, mdns.ErrInvalid) {
				t.Errorf("doubting %s: %v", what, err)
			}
		}

		nothing := func(mdns.Change, mdns.Instance) {}

		for what, query := range map[string]mdns.Query{
			"a type that is none":     {Type: "http._tcp"},
			"a subtype of two labels": {Type: "_http._tcp", Subtype: string(make([]byte, 64))},
			"a name of over 63 bytes": {Type: "_http._tcp", Name: string(make([]byte, 64))},
		} {
			if err = browser.Browse(t.Context(), query, nothing); !errors.Is(err, mdns.ErrInvalid) {
				t.Errorf("browsing for %s: %v", what, err)
			}
		}

		if _, err = browser.Resolve(t.Context(), "", "_http._tcp"); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("resolving no name: %v", err)
		}

		if _, err = browser.LookupHost(t.Context(), "a..b"); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("looking for a host that is none: %v", err)
		}

		if _, err = kitchen.Announce(
			t.Context(),
			mdns.Service{Type: "http", Port: 80},
		); !errors.Is(
			err,
			mdns.ErrInvalid,
		) {
			t.Errorf("announcing a type that is none: %v", err)
		}

		if _, err = mdns.Open(
			t.Context(),
			mdns.Config{Network: network.Host(), Hostname: "a.b"},
		); !errors.Is(
			err,
			mdns.ErrInvalid,
		) {
			t.Errorf("a host name of two labels: %v", err)
		}

		// The Peers close: what they announced and what they looked for
		// end with them.
		if err = kitchen.Close(); err != nil {
			t.Fatal(err)
		}

		<-announced.Done()

		if !errors.Is(announced.Err(), mdns.ErrClosed) {
			t.Errorf("an announcement of a Peer that closed: %v", announced.Err())
		}

		if err = browser.Close(); err != nil {
			t.Fatal(err)
		}

		if err = <-found.ended; !errors.Is(err, mdns.ErrClosed) {
			t.Errorf("a Browse of a Peer that closed: %v", err)
		}

		found.ended <- nil

		if _, err = browser.Resolve(t.Context(), "Kitchen", "_http._tcp"); !errors.Is(err, mdns.ErrClosed) {
			t.Errorf("resolving on a Peer that is closed: %v", err)
		}

		if _, err = browser.LookupHost(t.Context(), "kitchen"); !errors.Is(err, mdns.ErrClosed) {
			t.Errorf("looking for a host on a Peer that is closed: %v", err)
		}

		if _, err = kitchen.Announce(
			t.Context(),
			mdns.Service{Type: "_http._tcp", Port: 80},
		); !errors.Is(
			err,
			mdns.ErrClosed,
		) {
			t.Errorf("announcing on a Peer that is closed: %v", err)
		}
	})
}
