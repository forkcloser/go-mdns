package engine_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

const (
	lan  = "lan"
	wifi = "wifi"
)

// port is an interface with one IPv4 address, 192.0.2.last, so that a
// host has one link for each interface.
func port(name, wired string, last byte) mdnstest.Port {
	return mdnstest.Port{
		Interface: name, Wire: wired,
		Addrs: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, last}), 24)},
	}
}

func typeName() []string { return []string{"_http", "_tcp", "local"} }
func hostName() []string { return []string{"kitchen", "local"} }

// pointer is a PTR record of the type's, to an instance of a name.
func pointer(instance string, ttl uint32) wire.Record {
	return wire.Record{
		Name: typeName(), Class: wire.ClassIN, TTL: ttl,
		Data: wire.Pointer{Kind: wire.TypePTR, Target: []string{instance, "_http", "_tcp", "local"}},
	}
}

// address is an A record of the host's, good for two minutes.
func address(last byte, flush bool) wire.Record {
	return wire.Record{
		Name: hostName(), Class: wire.ClassIN, TTL: 120, Flush: flush,
		Data: wire.Address{Addr: netip.AddrFrom4([4]byte{192, 0, 2, last})},
	}
}

// open opens an Engine on a host of the network, in a bubble, closed
// with the test.
func open(t *testing.T, cfg engine.Config) *engine.Engine {
	t.Helper()

	opened, err := engine.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = opened.Close() })

	// Its links are up before anything is asked of it.
	synctest.Wait()

	return opened
}

// heard is a message a neighbour heard, and when.
type heard struct {
	wire.Message

	at time.Time
	// on is the neighbour's interface it came in on, group whether it
	// was said to all, and size how many bytes it was.
	on    string
	group bool
	size  int
}

// neighbour is another host on the network, speaking for itself: what
// it hears is kept for the test to look at, and it says what the test
// has it say.
type neighbour struct {
	links map[string]transport.Link
	heard chan heard
}

// join puts a neighbour on the network, with interfaces of one address
// each.
func join(t *testing.T, network *mdnstest.Network, ports ...mdnstest.Port) *neighbour {
	t.Helper()

	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	joined := &neighbour{links: map[string]transport.Link{}, heard: make(chan heard, 1024)}
	up := make(chan transport.Link, len(ports))

	var running sync.WaitGroup

	running.Go(func() {
		_ = network.Host(ports...).Watch(ctx, func(event transport.Event) {
			if event.Change == transport.Up {
				up <- event.Link
			}
		})
	})

	for range ports {
		link := <-up
		joined.links[link.Interface().Name] = link

		running.Go(func() {
			buf := make([]byte, transport.MaxPacket)

			for {
				size, _, group, err := link.Read(buf)
				if err != nil {
					return
				}

				if message, err := wire.Parse(buf[:size]); err == nil {
					joined.heard <- heard{Message: message, at: time.Now(), on: link.Interface().Name, group: group, size: size}
				}
			}
		})
	}

	t.Cleanup(func() {
		stop()
		running.Wait()
	})

	return joined
}

// link is the neighbour's link on an interface it has.
func (n *neighbour) link(t *testing.T, name string) transport.Link {
	t.Helper()

	found, has := n.links[name]
	if !has {
		t.Fatalf("the neighbour has no interface %s", name)
	}

	return found
}

// next is the next message the neighbour hears, however long it takes.
func (n *neighbour) next() heard { return <-n.heard }

// quiet says that the neighbour hears nothing for a while.
func (n *neighbour) quiet(t *testing.T, during time.Duration) {
	t.Helper()

	select {
	case got := <-n.heard:
		t.Fatalf(
			"heard %+v after %s of what was to be %s of silence",
			got.Message,
			during-time.Until(got.at.Add(during)),
			during,
		)
	case <-time.After(during):
	}
}

// messages writes records as answers, in as many messages as it takes.
func messages(t *testing.T, header wire.Header, questions []wire.Question, records ...wire.Record) [][]byte {
	t.Helper()

	var written [][]byte

	message := wire.NewBuilder(nil, header, wire.Options{Limit: 1472})

	for _, question := range questions {
		if err := message.Question(question); err != nil {
			t.Fatal(err)
		}
	}

	for _, record := range records {
		err := message.Answer(record)
		if errors.Is(err, wire.ErrFull) {
			written = append(written, message.Bytes())
			message = wire.NewBuilder(nil, header, wire.Options{Limit: 1472})
			err = message.Answer(record)
		}

		if err != nil {
			t.Fatal(err)
		}
	}

	return append(written, message.Bytes())
}

// answer says records to everyone, on an interface of the neighbour's.
func (n *neighbour) answer(t *testing.T, on string, records ...wire.Record) {
	t.Helper()

	for _, message := range messages(t, wire.Header{Response: true, Authoritative: true}, nil, records...) {
		if err := n.link(t, on).Multicast(message); err != nil {
			t.Fatal(err)
		}
	}
}

// answerTo says records to one host alone, from its first interface.
func (n *neighbour) answerTo(t *testing.T, dest netip.Addr, records ...wire.Record) {
	t.Helper()

	for _, message := range messages(t, wire.Header{Response: true, Authoritative: true}, nil, records...) {
		if err := n.link(t, "en0").Unicast(message, netip.AddrPortFrom(dest, transport.Port)); err != nil {
			t.Fatal(err)
		}
	}
}

// ask asks a question of everyone on its first interface, saying what
// it already knows.
func (n *neighbour) ask(t *testing.T, question wire.Question, known ...wire.Record) {
	t.Helper()

	for _, message := range messages(t, wire.Header{}, []wire.Question{question}, known...) {
		if err := n.link(t, "en0").Multicast(message); err != nil {
			t.Fatal(err)
		}
	}
}

// told is what an Ask told its handler.
type told struct {
	change engine.Change
	answer engine.Answer
	at     time.Time
}

// asker is an Ask under way.
type asker struct {
	told  chan told
	ended chan error
	stop  context.CancelFunc
}

// ask starts an Ask, which ends with the test or when it is stopped.
func ask(t *testing.T, asked *engine.Engine, question engine.Question) *asker {
	t.Helper()

	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	asking := &asker{told: make(chan told, 1024), ended: make(chan error, 1), stop: stop}

	go func() {
		asking.ended <- asked.Ask(ctx, question, func(change engine.Change, answer engine.Answer) {
			asking.told <- told{change: change, answer: answer, at: time.Now()}
		})
	}()

	t.Cleanup(func() {
		stop()

		// However it ends, it ends: with its context, with the Engine,
		// or as the test that took its end left it.
		if err := <-asking.ended; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, engine.ErrClosed) {
			t.Errorf("an Ask ended with %v", err)
		}
	})

	// It is asking before anything else happens.
	synctest.Wait()

	return asking
}

// next is the next thing the Ask tells, however long it takes, which
// has to be the change given.
func (a *asker) next(t *testing.T, change engine.Change) told {
	t.Helper()

	got := <-a.told
	if got.change != change {
		t.Fatalf("told of change %d for %+v, want %d", got.change, got.answer.Record, change)
	}

	return got
}

// nothing says that the Ask has nothing more to tell, now that
// everything that could happen without time passing has.
func (a *asker) nothing(t *testing.T) {
	t.Helper()

	synctest.Wait()

	select {
	case got := <-a.told:
		t.Fatalf("told of change %d for %+v, want nothing", got.change, got.answer.Record)
	default:
	}
}

// names is the names of interfaces.
func names(interfaces []transport.Interface) string {
	var joined strings.Builder

	for _, one := range interfaces {
		joined.WriteString(one.Name + " ")
	}

	return joined.String()
}

// between says whether a time is so long after another, give or take.
func between(at, since time.Time, least, most time.Duration) bool {
	gone := at.Sub(since)

	return gone >= least && gone <= most
}

// drain forgets what the neighbour has heard so far.
func (n *neighbour) drain() {
	synctest.Wait()

	for len(n.heard) > 0 {
		<-n.heard
	}
}

// claim asks for a name as a host that means to take it does: with
// what it would say of it, and for an answer of its own or not.
func (n *neighbour) claim(t *testing.T, alone bool, proposed ...wire.Record) {
	t.Helper()

	if len(proposed) == 0 {
		t.Fatal("a claim with nothing to say")
	}

	message := wire.NewBuilder(nil, wire.Header{}, wire.Options{})

	if err := message.Question(
		wire.Question{Name: proposed[0].Name, Type: wire.TypeANY, Class: wire.ClassIN, Unicast: alone},
	); err != nil {
		t.Fatal(err)
	}

	for _, record := range proposed {
		if err := message.Authority(record); err != nil {
			t.Fatal(err)
		}
	}

	if err := n.link(t, "en0").Multicast(message.Bytes()); err != nil {
		t.Fatal(err)
	}
}

// published is a Publish under way, or done.
type published struct {
	*engine.Publication

	err error
	at  time.Time
}

// publish publishes a set, and says when Publish came back and with
// what.
func publish(t *testing.T, on *engine.Engine, set engine.Set) <-chan published {
	t.Helper()

	done := make(chan published, 1)

	go func() {
		publication, err := on.Publish(t.Context(), set)
		done <- published{Publication: publication, err: err, at: time.Now()}
	}()

	return done
}

// settled publishes a set and waits until it has been said three times
// and the link is quiet again.
func settled(t *testing.T, on *engine.Engine, other *neighbour, set engine.Set) *engine.Publication {
	t.Helper()

	result := <-publish(t, on, set)
	if result.err != nil {
		t.Fatal(result.err)
	}

	time.Sleep(4 * time.Second)
	other.drain()

	return result.Publication
}

// unique is a record as a host that holds its name alone says it.
func unique(record wire.Record) wire.Record {
	record.Flush = true

	return record
}
