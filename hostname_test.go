package mdns_test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// renamedTo is a Peer whose host name another already has, and whose
// Rename answers a name written some way: what it then answers to, and
// where a browser finds its service.
func renamedTo(t *testing.T, written string) (hostname, found string) {
	t.Helper()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		first := peer(t, &network, "kitchen", wired("en0", "lan", "1"))
		browser := peer(t, &network, "browser", wired("en0", "lan", "3"))
		browsing := browse(t, browser, mdns.Query{Type: "_http._tcp"})

		if _, err := first.Announce(
			t.Context(),
			mdns.Service{Name: "First", Type: "_http._tcp", Port: 80},
		); err != nil {
			t.Fatal(err)
		}

		second, err := mdns.Open(t.Context(), mdns.Config{
			Network: network.Host(wired("en0", "lan", "2")), Hostname: "kitchen",
			Rename: func(string, int) (string, bool) { return written, true },
		})
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = second.Close() })

		if _, err = second.Announce(
			t.Context(),
			mdns.Service{Name: "Second", Type: "_http._tcp", Port: 81},
		); err != nil {
			t.Fatal(err)
		}

		time.Sleep(5 * time.Second)

		hostname, found = second.Hostname(), browsing.stands(t)["Second"].Host
	})

	return hostname, found
}

// What a Rename answers for a host is a name as Config.Hostname is one,
// with or without ".local", and is read as one: "pantry.LOCAL." is the
// host pantry. Its label was cut out of the answer as written, by a
// suffix that had to be ".local" in small letters, and a name written
// otherwise became one label with a dot in it.
func TestAHostRenamedToANameAsItIsRead(t *testing.T) {
	t.Parallel()

	for _, written := range []string{"pantry", "pantry.local", "pantry.local.", "pantry.LOCAL", "pantry.Local."} {
		if hostname, found := renamedTo(t, written); hostname != "pantry.local" || found != "pantry.local" {
			t.Errorf(
				"renamed to %q: the host answers to %q and its service is found on %q; want pantry.local",
				written,
				hostname,
				found,
			)
		}
	}
}
