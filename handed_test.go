package mdns_test

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// What a Browse hands over can be handed back. Another host may
// announce an instance under a name this package would not announce,
// one that is not UTF-8 say, and on a host whose name is not under
// "local": it is found, and the Instance it is told as is one Resolve
// finds, LookupHost finds the host of, and Reconfirm takes, where the
// three refused it or asked for another name. An Instance found with
// Query.Unresolved, which has no host, is one Reconfirm takes too.
func TestWhatIsFoundCanBeHandedBack(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := stationed(t, &network, wired("en0", "lan", "9"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"))
		found := browse(t, browser, mdns.Query{Type: "_http._tcp"})
		listed := browse(t, browser, mdns.Query{Type: "_http._tcp", Unresolved: true})

		kind := []string{"_http", "_tcp", "local"}
		latin := []string{"Caf\xe9", "_http", "_tcp", "local"}
		away := []string{"printer", "example", "com"}
		addr := netip.MustParseAddr("192.0.2.9")

		other.say(t, "en0",
			of(kind, 4500, false, wire.Pointer{Target: latin}),
			of(latin, 120, true, wire.Service{Port: 80, Target: away}),
			of(latin, 4500, true, wire.Text{}),
			of(away, 120, true, wire.Address{Addr: addr}),
		)

		got := found.next(t, mdns.Found).instance
		if got.Name != "Caf\xe9" || got.Host != "printer.example.com" ||
			!reflect.DeepEqual(got.Addrs, []netip.Addr{addr}) {
			t.Fatalf("found %+v", got)
		}

		brief, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		if again, err := browser.Resolve(brief, got.Name, got.Type); err != nil || again.Host != got.Host {
			t.Errorf("Resolve of the name it was found under: %+v, %v", again, err)
		}

		if addrs, err := browser.LookupHost(
			brief,
			got.Host,
		); err != nil ||
			!reflect.DeepEqual(addrs, []netip.Addr{addr}) {
			t.Errorf("LookupHost of the host it was found on: %v, %v", addrs, err)
		}

		// No one answers for it: doubted, it is lost ten seconds later,
		// which says its records were the ones asked about again.
		unresolved := listed.next(t, mdns.Found).instance

		if err := browser.Reconfirm(got); err != nil {
			t.Errorf("Reconfirm of it: %v", err)
		}

		if err := browser.Reconfirm(unresolved); err != nil {
			t.Errorf("Reconfirm of it as found with no more than its name: %v", err)
		}

		time.Sleep(11 * time.Second)

		if lost := found.next(t, mdns.Lost).instance; lost.Name != got.Name {
			t.Errorf("lost %+v", lost)
		}

		if lost := listed.next(t, mdns.Lost).instance; lost.Name != got.Name {
			t.Errorf("lost from the list: %+v", lost)
		}

		// What no host can have announced is still refused: a name that
		// is no label, a host that is no name.
		long := strings.Repeat("n", 64)

		if err := browser.Reconfirm(mdns.Instance{Name: long, Type: "_http._tcp"}); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("Reconfirm of a name of 64 bytes: %v", err)
		}

		if err := browser.Reconfirm(
			mdns.Instance{Name: "n", Type: "_http._tcp", Host: "a..b"},
		); !errors.Is(
			err,
			mdns.ErrInvalid,
		) {
			t.Errorf("Reconfirm on a host that is no name: %v", err)
		}

		if _, err := browser.Resolve(brief, long, "_http._tcp"); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("Resolve of a name of 64 bytes: %v", err)
		}

		if _, err := browser.LookupHost(brief, "a..b"); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("LookupHost of a host that is no name: %v", err)
		}
	})
}
