package command_test

import (
	"context"
	"io"
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

// And told to stop while it waits for its document on standard input,
// which no one writes: it ends, as done. It waited for the end of
// standard input whatever it was told, and a terminal's has none.
func TestToldToStopWhileItReadsItsDocument(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var (
			network  mdnstest.Network
			out, err buffer
		)

		unwritten, writer := io.Pipe()
		ctx, stop := context.WithCancel(t.Context())
		ended := make(chan int, 1)

		go func() {
			ended <- command.Run(ctx, command.Environment{
				Args: []string{"announce", "-"}, In: unwritten, Out: &out, Err: &err, Network: network.Host(lan("1")),
			})
		}()

		time.Sleep(time.Second)
		stop()

		select {
		case code := <-ended:
			if code != command.Done || err.String() != "" {
				t.Errorf("told to stop while it reads: ended with %d, saying %q", code, err.String())
			}
		case <-time.After(time.Minute):
			t.Error("a minute after it was told to stop, the command still waits for standard input")
		}

		// The read is still waiting, and ends with what it reads from.
		_ = writer.Close()
	})

	// A document that does come is read as before.
	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		announcing := run(
			t,
			&network,
			`{"services": [{"name": "Kitchen", "type": "_http._tcp", "port": 80}]}`,
			"announce",
			"-",
		)

		time.Sleep(5 * time.Second)

		if said := announcing.out.lines(t); len(said) != 1 || said[0]["event"] != "announced" {
			t.Errorf("a document on standard input: said %v", said)
		}
	})
}
