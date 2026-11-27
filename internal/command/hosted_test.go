package command_test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/mdnstest"
)

// The announced event says the host a service is on: the one it says
// it is on when that is not this one, under "local" however it was
// written. It said this host's name for every service.
func TestTheHostOfAServiceOnAnotherIsSaid(t *testing.T) {
	t.Parallel()

	for written, want := range map[string]string{"oven": "oven.local", "oven.local": "oven.local", "Oven.LOCAL.": "Oven.LOCAL"} {
		synctest.Test(t, func(t *testing.T) {
			var network mdnstest.Network

			announcing := run(
				t,
				&network,
				"",
				"announce",
				"--type",
				"_http._tcp",
				"--port",
				"80",
				"--name",
				"Oven",
				"--host",
				written,
				"--address",
				"192.0.2.40",
			)

			time.Sleep(5 * time.Second)

			said := announcing.out.lines(t)
			if len(said) != 1 || said[0]["event"] != "announced" || said[0]["host"] != want {
				t.Errorf("a service on the host %q: said %v, want it announced on %q", written, said, want)
			}
		})
	}
}
