package engine_test

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

// errBroken is why a network of a test cannot be watched.
var errBroken = errors.New("no network here")

// network is a Network that does as a test has it do: says nothing and
// waits, or gives up at once; before that, when it is to settle, it
// says it has no links.
type network struct {
	gives   error
	settles bool
}

func (n network) Watch(ctx context.Context, handle func(transport.Event)) error {
	if n.settles {
		handle(transport.Event{Change: transport.Settled})
	}

	if n.gives != nil {
		return n.gives
	}

	<-ctx.Done()

	return ctx.Err()
}

// An Engine is open once it knows the links there are: what is asked of
// it at once is asked on them. A network that cannot be watched, or
// that never says what links it has, is not one to be open on.
func TestAnEngineOpensOnTheLinksThereAre(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var wires mdnstest.Network

		other := join(t, &wires, port("en0", lan, 2))

		opened, err := engine.Open(t.Context(), engine.Config{Network: wires.Host(port("en0", lan, 1))})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = opened.Close() }()

		// At once, with no wait for anything: the name is asked for on
		// the link, which takes its three questions.
		began := time.Now()

		if _, err = opened.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(1, true)}},
		); err != nil ||
			time.Since(began) < 750*time.Millisecond {
			t.Errorf("published after %s, %v", time.Since(began), err)
		}

		if probe := other.next(); probe.Header.Response {
			t.Errorf("the name was not asked for: %+v", probe.Message)
		}

		if _, err = engine.Open(
			t.Context(),
			engine.Config{Network: network{gives: errBroken}},
		); !errors.Is(
			err,
			errBroken,
		) {
			t.Errorf("opening on a network that cannot be watched: %v", err)
		}

		ctx, stop := context.WithTimeout(t.Context(), time.Minute)
		defer stop()

		began = time.Now()

		if _, err = engine.Open(
			ctx,
			engine.Config{Network: network{}},
		); !errors.Is(err, context.DeadlineExceeded) ||
			time.Since(began) != time.Minute {
			t.Errorf("opening on a network that never says what links it has: %v, after %s", err, time.Since(began))
		}
	})
}

// A network that says what links it has and can then no longer be
// watched is one an Engine is open on, every time: that it was lost is
// for the log, not for Open to say or not as the moment has it.
func TestAnEngineOpensOnANetworkLostAtOnce(t *testing.T) {
	t.Parallel()

	for range 500 {
		opened, err := engine.Open(
			t.Context(),
			engine.Config{Network: network{gives: errBroken, settles: true}},
		)
		if err != nil {
			t.Fatalf("opening on a network that settled: %v", err)
		}

		_ = opened.Close()
	}
}
