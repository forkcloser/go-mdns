package engine_test

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// RFC 6762 section 6.6: a host that hears another say one of its
// records for less than half as long as it does, or goodbye, says its
// own again. Section 10.2: what is this host's alone is said whole, all
// the records of that name and type, since the bit they are said with
// has their hearers forget, a second later, what else they held of the
// set. A host with two addresses under its name that said one of them
// again, alone, took the other from every neighbour.
func TestARecordSaidAgainIsSaidWithItsSet(t *testing.T) {
	t.Parallel()

	for what, life := range map[string]uint32{"goodbye": 0, "under half as long": 59} {
		t.Run(what, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var network mdnstest.Network

				other := join(t, &network, port("en0", lan, 2))
				host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

				// Two addresses of one name, and what is no part of their
				// set: a record of another type under that name, one of
				// that type under another name, and two that others may
				// say too.
				settled(t, host, other, engine.Set{Records: []wire.Record{
					address(1, true),
					address(3, true),
					{
						Name:  hostName(),
						Class: wire.ClassIN,
						TTL:   120,
						Flush: true,
						Data:  wire.Text{Strings: []string{"a=b"}},
					},
					{
						Name: []string{"garden", "local"}, Class: wire.ClassIN, TTL: 120, Flush: true,
						Data: wire.Address{Addr: netip.AddrFrom4([4]byte{192, 0, 2, 5})},
					},
					pointer("Kitchen", 4500),
					pointer("Garden", 4500),
				}})

				// said is what the neighbour hears after it says a record
				// itself for so long, as data and whether it is said to be
				// this host's alone.
				said := func(theirs wire.Record) map[string]bool {
					time.Sleep(time.Minute)
					other.drain()

					theirs.TTL, theirs.Flush = life, false
					other.answer(t, "en0", theirs)
					time.Sleep(2 * time.Second)
					synctest.Wait()

					answers := map[string]bool{}

					for len(other.heard) > 0 {
						for _, answer := range (<-other.heard).Answers {
							answers[fmt.Sprint(answer.Data)] = answer.Flush
						}
					}

					return answers
				}

				both := map[string]bool{
					fmt.Sprint(address(1, true).Data): true,
					fmt.Sprint(address(3, true).Data): true,
				}

				if got := said(address(1, true)); !reflect.DeepEqual(got, both) {
					t.Errorf(
						"another host says one address of two, %s: this one says %v; want both, each its own",
						what,
						got,
					)
				}

				// What others may say too has no set: it is said again
				// alone.
				kitchen := map[string]bool{fmt.Sprint(pointer("Kitchen", 4500).Data): false}

				if got := said(pointer("Kitchen", 4500)); !reflect.DeepEqual(got, kitchen) {
					t.Errorf("another host says one instance of two, %s: this one says %v; want that one", what, got)
				}
			})
		})
	}
}
