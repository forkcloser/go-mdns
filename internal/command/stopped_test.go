package command_test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/command"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// The command announces until it is told to stop, and has then done
// what it was asked: it ends as done whenever that is. Told to stop
// while its first service was still asking for its name, it ended as
// failed, with the stop as its error.
func TestToldToStopTheCommandEndsAsDone(t *testing.T) {
	t.Parallel()

	for _, after := range []time.Duration{0, 300 * time.Millisecond, 5 * time.Second} {
		synctest.Test(t, func(t *testing.T) {
			var network mdnstest.Network

			announcing := run(t, &network, "", "announce", "--type", "_http._tcp", "--port", "80", "--name", "Kitchen")

			time.Sleep(after)
			announcing.stop()

			if code := announcing.ended(t); code != command.Done || announcing.err.String() != "" {
				t.Errorf("told to stop %s in: ended with %d, saying %q", after, code, announcing.err.String())
			}
		})
	}
}
