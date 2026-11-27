package engine_test

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

// RFC 6762 section 6.2: a responder that takes the two families of an
// interface apart "MUST NOT put the corresponding automatic NSEC
// records in replies", a word in its IPv4 answers that the name has no
// IPv6 address. An Engine that speaks IPv4 alone is one: it does not
// know what IPv6 addresses the interface has, and another responder on
// the host may be saying them under the same name. It said, with every
// address and to whoever asked for an IPv6 one, that the host had none,
// as this host's own word.
func TestAnEngineOfOneFamilyDoesNotDenyTheOther(t *testing.T) {
	t.Parallel()

	both := mdnstest.Port{Interface: "en0", Wire: lan, Addrs: []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("2001:db8::1/64"),
	}}

	// denials is how many records that deny a type the neighbour hears
	// in answer to a question, and answers how many others.
	asked := func(t *testing.T, other *neighbour, name []string, kind uint16) (answers, denials int) {
		t.Helper()

		time.Sleep(time.Minute)
		other.drain()
		other.ask(t, query(name, kind))
		time.Sleep(time.Second)
		synctest.Wait()

		for len(other.heard) > 0 {
			message := <-other.heard

			for _, record := range append(message.Answers, message.Additionals...) {
				if _, denial := record.Data.(wire.NSEC); denial {
					denials++
				} else {
					answers++
				}
			}
		}

		return answers, denials
	}

	// A neighbour of each family: it asks, and hears, on the one it has.
	fourth := port("en0", lan, 2)
	sixth := mdnstest.Port{Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::2/64")}}

	for what, row := range map[string]struct {
		families transport.Family
		asker    mdnstest.Port
		// What is said to a question for the host's IPv4 address, for
		// its IPv6 address, and for a text it has not.
		four, six, text [2]int
	}{
		"IPv4 alone": {families: transport.IPv4, asker: fourth, four: [2]int{1, 0}, six: [2]int{0, 0}, text: [2]int{0, 0}},
		"IPv6 alone": {families: transport.IPv6, asker: sixth, four: [2]int{0, 0}, six: [2]int{1, 0}, text: [2]int{0, 0}},
		"both":       {asker: fourth, four: [2]int{2, 0}, six: [2]int{2, 0}, text: [2]int{0, 1}},
	} {
		t.Run(what, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var network mdnstest.Network

				other := join(t, &network, row.asker)
				host := open(t, engine.Config{Network: network.Host(both), Families: row.families})

				// A name with no address is denied what it has not, by
				// either: no one else answers for it.
				settled(t, host, other, engine.Set{Host: hostName(), Records: service()[1:]})

				for question, want := range map[uint16][2]int{
					wire.TypeA: row.four, wire.TypeAAAA: row.six, wire.TypeTXT: row.text,
				} {
					if answers, denials := asked(t, other, hostName(), question); [2]int{answers, denials} != want {
						t.Errorf(
							"asked for type %d of the host: %d records and %d denials, want %v",
							question,
							answers,
							denials,
							want,
						)
					}
				}

				if answers, denials := asked(t, other, instanceName(), wire.TypeA); answers != 0 || denials != 1 {
					t.Errorf(
						"asked for an address of the service's name: %d records and %d denials, want the one denial",
						answers,
						denials,
					)
				}
			})
		})
	}
}
