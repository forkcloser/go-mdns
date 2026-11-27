package mdns_test

import (
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// An instance looked for by its name, with nothing asked about it
// (Query.Unresolved), is found when its type lists it, on the
// interfaces it is listed on, and lost when it is listed no more; and
// no other instance of the type is. It was told as found at once, on no
// interface, whether there was such an instance or not, and never lost.
func TestAnInstanceLookedForByNameAndNotResolved(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		kitchen := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "2"))
		named := browse(t, browser, mdns.Query{Type: "_http._tcp", Name: "Pantry", Unresolved: true})

		time.Sleep(5 * time.Second)
		named.nothing(t)

		if _, err := kitchen.Announce(
			t.Context(),
			mdns.Service{Name: "Kitchen", Type: "_http._tcp", Port: 80},
		); err != nil {
			t.Fatal(err)
		}

		time.Sleep(5 * time.Second)
		named.nothing(t)

		pantry, err := kitchen.Announce(t.Context(), mdns.Service{Name: "pantry", Type: "_http._tcp", Port: 81})
		if err != nil {
			t.Fatal(err)
		}

		// Found under the name it has, which is the one looked for but
		// for the case of its letters.
		want := mdns.Instance{Name: "pantry", Type: "_http._tcp", Interfaces: []mdns.Interface{en(1, "en0")}}
		if got := named.next(t, mdns.Found).instance; !reflect.DeepEqual(got, want) {
			t.Errorf("found %+v, want %+v", got, want)
		}

		time.Sleep(5 * time.Second)
		named.nothing(t)

		if err = pantry.Close(); err != nil {
			t.Fatal(err)
		}

		if got := named.next(t, mdns.Lost).instance; got.Name != "pantry" {
			t.Errorf("lost %+v", got)
		}

		time.Sleep(time.Minute)
		named.nothing(t)
	})
}
