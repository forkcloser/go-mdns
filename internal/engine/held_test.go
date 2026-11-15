package engine_test

import (
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// info is a record of another type under the host's name, the host's
// alone.
func info() wire.Record {
	return wire.Record{
		Name: hostName(), Class: wire.ClassIN, TTL: 120, Flush: true,
		Data: wire.Opaque{Kind: 13, Bytes: []byte("\x03ARM")},
	}
}

// A record an Engine holds for this host alone is taken, for another
// set of the same Engine as for another host: said at once, with no
// asking, since no one on the network would answer for it. It is one
// record by its name, its type and the link: another type of the name,
// a record others may say too, and the same on another link are free,
// and so is the record itself once it is given up.
func TestARecordTheEngineAlreadyHolds(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var wires mdnstest.Network

		opened := open(t, engine.Config{Network: wires.Host(port("en0", lan, 1), port("en1", wifi, 2))})
		one := func(records ...wire.Record) engine.Set { return engine.Set{Records: records} }

		held, err := opened.Publish(t.Context(), one(address(1, true)))
		if err != nil {
			t.Fatal(err)
		}

		began := time.Now()

		if _, err = opened.Publish(t.Context(), one(address(2, true))); !errors.Is(err, engine.ErrConflict) ||
			time.Since(began) != 0 {
			t.Errorf("a record already held: %v, after %s", err, time.Since(began))
		}

		// The host's own addresses are records of that name and type too.
		if _, err = opened.Publish(t.Context(), engine.Set{Host: hostName()}); !errors.Is(err, engine.ErrConflict) {
			t.Errorf("a host of a name whose address is held: %v", err)
		}

		for what, free := range map[string]engine.Set{
			"another type of the name":    one(info()),
			"a record others may say too": one(address(2, false)),
		} {
			published, refused := opened.Publish(t.Context(), free)
			if refused != nil {
				t.Errorf("%s: %v", what, refused)

				continue
			}

			_ = published.Close()
		}

		_ = held.Close()

		// The other order: the other type first, then the address.
		first, err := opened.Publish(t.Context(), one(info()))
		if err != nil {
			t.Fatal(err)
		}

		again, err := opened.Publish(t.Context(), one(address(2, true)))
		if err != nil {
			t.Fatalf("a record given up, beside another type of its name: %v", err)
		}

		_, _ = first.Close(), again.Close()

		// A name on two links, with on each the address it has there.
		here, err := opened.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(1, true)}, Interfaces: only("en0")},
		)
		if err != nil {
			t.Fatal(err)
		}

		there, err := opened.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(2, true)}, Interfaces: only("en1")},
		)
		if err != nil {
			t.Fatalf("the same record on another link: %v", err)
		}

		if _, err = opened.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(3, true)}, Interfaces: only("en1")},
		); !errors.Is(err, engine.ErrConflict) {
			t.Errorf("the same record on a link where it is held: %v", err)
		}

		_ = there.Close()

		// Refused for the link where it is held, a set stands on no other:
		// what it wanted there is free.
		if _, err = opened.Publish(t.Context(), one(address(3, true))); !errors.Is(err, engine.ErrConflict) {
			t.Errorf("a record held on one of two links: %v", err)
		}

		there, err = opened.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(2, true)}, Interfaces: only("en1")},
		)
		if err != nil {
			t.Fatalf("a record on a link where a refused set wanted it: %v", err)
		}

		_, _ = here.Close(), there.Close()

		// What others may say too holds nothing, whichever came first.
		shared, err := opened.Publish(t.Context(), one(address(1, false)))
		if err != nil {
			t.Fatal(err)
		}

		alone, err := opened.Publish(t.Context(), one(address(2, true)))
		if err != nil {
			t.Fatalf("a record beside one others may say too: %v", err)
		}

		_, _ = shared.Close(), alone.Close()

		// Two at once: one of them has it, whichever.
		var (
			asking sync.WaitGroup
			failed [2]error
		)

		for index := range failed {
			asking.Go(func() {
				_, failed[index] = opened.Publish(t.Context(), one(address(byte(index+4), true)))
			})
		}

		asking.Wait()

		if (failed[0] == nil) == (failed[1] == nil) || !errors.Is(errors.Join(failed[:]...), engine.ErrConflict) {
			t.Errorf("two sets of one record at once: %v and %v", failed[0], failed[1])
		}
	})
}

// A link that comes up later, where two sets then want one record: the
// one published first keeps it, and the other is lost, as it would be
// to another host. What was published after them is put on the link as
// if neither had been.
func TestARecordHeldOnALinkThatComesUp(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var wires mdnstest.Network

		host := wires.Host(port("en0", lan, 1))
		opened := open(t, engine.Config{Network: host})
		other := join(t, &wires, port("en1", wifi, 9))

		there := func(record wire.Record) *engine.Publication {
			published, err := opened.Publish(
				t.Context(),
				engine.Set{Records: []wire.Record{record}, Interfaces: only("en1")},
			)
			if err != nil {
				t.Fatalf("a record wanted where there is no link yet: %v", err)
			}

			return published
		}

		first, second := there(address(1, true)), there(address(2, true))
		third, fourth := there(named("third", 120)), there(named("fourth", 120))

		host.Plug(port("en1", wifi, 2))
		time.Sleep(5 * time.Second)
		synctest.Wait()

		select {
		case <-second.Done():
			if !errors.Is(second.Err(), engine.ErrConflict) {
				t.Errorf("the second set ended with %v", second.Err())
			}
		default:
			t.Error("the second set still stands")
		}

		said := map[string]bool{}

		for len(other.heard) > 0 {
			for _, answer := range (<-other.heard).Answers {
				said[answer.Name[0]] = true
			}
		}

		for index, kept := range []*engine.Publication{first, third, fourth} {
			select {
			case <-kept.Done():
				t.Errorf("set %d of those kept ended with %v", index+1, kept.Err())
			default:
			}
		}

		if !said["kitchen"] || !said["third"] || !said["fourth"] {
			t.Errorf("said on the link that came up: %v", said)
		}
	})
}
