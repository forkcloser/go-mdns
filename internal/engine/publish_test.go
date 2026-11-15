package engine_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

func instanceName() []string { return []string{"Kitchen", "_http", "_tcp", "local"} }

// service is the records of a service: the PTR others may say too, and
// the SRV and TXT records that are its own.
func service() []wire.Record {
	return []wire.Record{
		pointer("Kitchen", 4500),
		{
			Name:  instanceName(),
			Class: wire.ClassIN,
			TTL:   120,
			Flush: true,
			Data:  wire.Service{Port: 8080, Target: hostName()},
		},
		{
			Name:  instanceName(),
			Class: wire.ClassIN,
			TTL:   4500,
			Flush: true,
			Data:  wire.Text{Strings: []string{"path=/"}},
		},
	}
}

// denial is the record that says the host has an IPv4 address and no
// other record.
func denial() wire.Record {
	return wire.Record{
		Name: hostName(), Class: wire.ClassIN, TTL: 120, Flush: true,
		Data: wire.NSEC{Next: hostName(), Types: []uint16{wire.TypeA}},
	}
}

func query(name []string, kind uint16) wire.Question {
	return wire.Question{Name: name, Type: kind, Class: wire.ClassIN}
}

// asks and answers are the headers of a question and of an answer.
func asks() wire.Header    { return wire.Header{} }
func answers() wire.Header { return wire.Header{Response: true, Authoritative: true} }

// RFC 6762 section 8: a name that is to be this host's alone is asked
// for three times, 250 ms apart, after up to as long, saying what is
// meant to be said of it; then its records are said, and said again a
// second and three seconds later, and not again.
func TestANameIsAskedForAndTaken(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		start := time.Now()
		publishing := publish(t, host, engine.Set{Records: []wire.Record{address(1, true)}})

		last := start

		for index := range 3 {
			probe := other.next()
			want := wire.Message{
				Header: asks(),
				Questions: []wire.Question{
					{Name: hostName(), Type: wire.TypeANY, Class: wire.ClassIN, Unicast: true},
				},
				Authorities: []wire.Record{address(1, false)},
			}

			if !reflect.DeepEqual(probe.Message, want) || !probe.group {
				t.Fatalf("asked for the name with %+v", probe.Message)
			}

			if gap := probe.at.Sub(
				last,
			); index == 0 && gap > 250*time.Millisecond ||
				index > 0 && gap != 250*time.Millisecond {
				t.Fatalf("asked for the name a time %d after %s", index+1, gap)
			}

			last = probe.at
		}

		for index, gap := range []time.Duration{250 * time.Millisecond, time.Second, 2 * time.Second} {
			said := other.next()
			want := wire.Message{
				Header:      answers(),
				Answers:     []wire.Record{address(1, true)},
				Additionals: []wire.Record{denial()},
			}

			if !reflect.DeepEqual(said.Message, want) || said.at.Sub(last) != gap || !said.group {
				t.Fatalf("said a time %d after %s: %+v", index+1, said.at.Sub(last), said.Message)
			}

			// Publish comes back when the records are first said.
			if index == 0 {
				if done := <-publishing; done.err != nil || !done.at.Equal(said.at) {
					t.Fatalf("published after %s, %v", done.at.Sub(start), done.err)
				}
			}

			last = said.at
		}

		other.quiet(t, 3*time.Hour)
	})
}

// What others may say too is no one's to ask for: it is said at once.
func TestWhatOthersMaySayIsNotAskedFor(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		start := time.Now()

		if done := <-publish(
			t,
			host,
			engine.Set{Records: []wire.Record{pointer("Kitchen", 4500)}},
		); done.err != nil ||
			!done.at.Equal(start) {
			t.Fatalf("published after %s, %v", done.at.Sub(start), done.err)
		}

		want := wire.Message{Header: answers(), Answers: []wire.Record{pointer("Kitchen", 4500)}}
		if said := other.next(); !reflect.DeepEqual(said.Message, want) || !said.at.Equal(start) {
			t.Errorf("said after %s: %+v", said.at.Sub(start), said.Message)
		}

		// An address others may say too is no one's name alone: nothing
		// is said of what other records the name has not.
		settled(t, host, other, engine.Set{Records: []wire.Record{address(1, false)}})
		other.ask(t, query(hostName(), wire.TypeA))

		if said := other.next(); !reflect.DeepEqual(
			said.Message,
			wire.Message{Header: answers(), Answers: []wire.Record{address(1, false)}},
		) {
			t.Errorf("answered with %+v", said.Message)
		}

		other.ask(t, query(hostName(), wire.TypeAAAA))
		other.quiet(t, time.Minute)
	})
}

// Section 8.1: a name another host has is not taken; the same record
// from another host is no one having it (section 9).
func TestANameThatIsTaken(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		// Said before the name is asked for: not an answer to anything.
		other.answer(t, "en0", address(9, true))

		publishing := publish(t, host, engine.Set{Records: []wire.Record{address(1, true)}})

		other.next()
		other.answer(t, "en0", address(1, true))
		other.next()

		// Any record of the name, of any type, is someone having it.
		other.answer(t, "en0", wire.Record{Name: hostName(), Class: wire.ClassIN, TTL: 120, Data: wire.Text{}})

		if done := <-publishing; !errors.Is(done.err, engine.ErrConflict) || done.Publication != nil {
			t.Fatalf("published: %v", done.err)
		}

		// Nothing was said, and so nothing is taken back.
		other.quiet(t, time.Hour)
	})
}

// Section 8.2: of two hosts asking for a name at the same moment, the
// one whose records come first yields, and asks again a second later.
func TestTwoAskForANameAtOnce(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		publishing := publish(t, host, engine.Set{Records: []wire.Record{address(100, true)}})

		first := other.next()

		// One that comes first: ours stays, and goes on as it was.
		other.claim(t, true, address(99, false))

		if second := other.next(); second.at.Sub(first.at) != 250*time.Millisecond {
			t.Fatalf("asked again after %s", second.at.Sub(first.at))
		}

		// One that comes later: ours yields, and starts over in a second.
		// Told again while it waits, it does not start the wait over.
		yielded := time.Now()

		other.claim(t, true, address(101, false))
		time.Sleep(500 * time.Millisecond)
		other.claim(t, true, address(101, false))

		for index, after := range []time.Duration{time.Second, 1250 * time.Millisecond, 1500 * time.Millisecond} {
			if probe := other.next(); probe.at.Sub(yielded) != after || probe.Header.Response {
				t.Fatalf("asked a time %d %s after yielding: %+v", index+1, probe.at.Sub(yielded), probe.Message)
			}
		}

		// The other host did not take the name after all.
		if done := <-publishing; done.err != nil || done.at.Sub(yielded) != 1750*time.Millisecond {
			t.Errorf("published %s after yielding, %v", done.at.Sub(yielded), done.err)
		}

		// How two sets of records are told apart (8.2.1): by type before
		// data, and the one that runs out first comes first.
		_ = host.Close()

		text := wire.Record{Name: hostName(), Class: wire.ClassIN, TTL: 120, Data: wire.Text{}}

		for what, row := range map[string]struct {
			theirs []wire.Record
			yields bool
		}{
			"the same record":              {theirs: []wire.Record{address(100, false)}},
			"a type that comes later":      {theirs: []wire.Record{text}, yields: true},
			"the same record and one more": {theirs: []wire.Record{address(100, false), address(101, false)}, yields: true},
		} {
			second := open(t, engine.Config{Network: network.Host(port("en0", lan, 50))})

			other.drain()

			claiming := publish(t, second, engine.Set{Records: []wire.Record{address(100, true)}})
			first := other.next()

			other.claim(t, true, row.theirs...)

			if next := other.next(); (next.at.Sub(first.at) == time.Second) != row.yields {
				t.Errorf("%s: asked again %s later", what, next.at.Sub(first.at))
			}

			if done := <-claiming; done.err != nil {
				t.Errorf("%s: %v", what, done.err)
			}

			_ = second.Close()
		}
	})
}

// Section 6: what is this host's alone is answered at once and what
// others may say too after 20 to 120 ms; not to who says it knows, for
// half its life or more (7.1); not twice in a second (6); and for a
// type the name has not, that it has not (6.1).
func TestQuestionsAreAnswered(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		settled(t, host, other, engine.Set{Records: append(service(), address(1, true))})

		asked := func(question wire.Question, known ...wire.Record) (heard, time.Duration) {
			began := time.Now()

			other.ask(t, question, known...)

			said := other.next()

			return said, said.at.Sub(began)
		}

		// The host's address, at once, with the word that it has no other.
		said, after := asked(query(hostName(), wire.TypeA))
		if want := (wire.Message{Header: answers(), Answers: []wire.Record{address(1, true)}, Additionals: []wire.Record{denial()}}); after != 0 ||
			!reflect.DeepEqual(said.Message, want) ||
			!said.group {
			t.Errorf("the address, %s later: %+v", after, said.Message)
		}

		// An address of the other family: that there is none. Asked in
		// another case, and for any class.
		said, after = asked(wire.Question{Name: []string{"KITCHEN", "Local"}, Type: wire.TypeAAAA, Class: 255})
		if want := (wire.Message{Header: answers(), Answers: []wire.Record{denial()}}); after != 0 ||
			!reflect.DeepEqual(said.Message, want) {
			t.Errorf("no IPv6 address, %s later: %+v", after, said.Message)
		}

		// A service of the type: after a while, with what will be asked
		// for next.
		service := service()

		said, after = asked(query(typeName(), wire.TypePTR))
		if want := (wire.Message{Header: answers(), Answers: service[:1], Additionals: []wire.Record{service[1], service[2], address(1, true), denial()}}); after < 20*time.Millisecond ||
			after > 120*time.Millisecond ||
			!reflect.DeepEqual(said.Message, want) {
			t.Errorf("the service, %s later: %+v", after, said.Message)
		}

		// Everything of a name.
		time.Sleep(time.Second)

		said, after = asked(query(instanceName(), wire.TypeANY))
		if want := (wire.Message{Header: answers(), Answers: service[1:], Additionals: []wire.Record{address(1, true), denial()}}); after != 0 ||
			!reflect.DeepEqual(said.Message, want) {
			t.Errorf("everything of the instance, %s later: %+v", after, said.Message)
		}

		// Asked again at once: not said twice in a second.
		if _, after = asked(query(instanceName(), wire.TypeSRV)); after != time.Second {
			t.Errorf("said again %s later", after)
		}

		time.Sleep(time.Second)

		// To who knows it for half its life or more, nothing; for less,
		// again.
		known := service[1]
		known.TTL, known.Flush = 60, false
		other.ask(t, query(instanceName(), wire.TypeSRV), known)
		other.quiet(t, time.Second)

		known.TTL = 59
		if _, after = asked(query(instanceName(), wire.TypeSRV), known); after != 0 {
			t.Errorf("said to who knows it for under half its life %s later", after)
		}

		// Two questions in one message, of which one is for no one here:
		// someone else may answer the other, and this host waits.
		time.Sleep(time.Second)

		began := time.Now()

		for _, message := range messages(t, asks(), []wire.Question{query(hostName(), wire.TypeA), query([]string{"garden", "local"}, wire.TypeA)}) {
			if err := other.link(t, "en0").Multicast(message); err != nil {
				t.Fatal(err)
			}
		}

		if said := other.next(); !between(said.at, began, 20*time.Millisecond, 120*time.Millisecond) {
			t.Errorf("answered one question of two %s later", said.at.Sub(began))
		}

		// A name that is no one's here, a class that is not the
		// Internet's: nothing.
		other.ask(t, query([]string{"garden", "local"}, wire.TypeA))
		other.ask(t, wire.Question{Name: hostName(), Type: wire.TypeA, Class: 3})
		other.drain()
		other.quiet(t, time.Second)
	})
}

// Section 5.4: a question that would take an answer of its own gets
// one, when the record was said to all within a quarter of its life;
// and is answered to all otherwise.
func TestAnAnswerToTheAskerAlone(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		third := join(t, &network, port("en0", lan, 3))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		settled(t, host, other, engine.Set{Records: []wire.Record{address(1, true)}})
		third.drain()

		question := wire.Question{Name: hostName(), Type: wire.TypeA, Class: wire.ClassIN, Unicast: true}

		other.ask(t, question)
		third.next()

		if said := other.next(); said.group || !reflect.DeepEqual(said.Answers, []wire.Record{address(1, true)}) {
			t.Errorf("answered to all, or not: %+v", said)
		}

		third.quiet(t, 25*time.Second)

		// Thirty seconds after it was last said to all: to all again.
		time.Sleep(6 * time.Second)
		other.ask(t, question)
		third.next()

		if said := third.next(); !said.group || !reflect.DeepEqual(said.Answers, []wire.Record{address(1, true)}) {
			t.Errorf("not answered to all: %+v", said)
		}

		// To all, and so not to the asker alone as well.
		other.next()
		other.quiet(t, time.Second)

		// Asked of this host alone, from the link: answered to the asker
		// alone, with or without the asking (5.5). From off it: not at
		// all.
		far := join(
			t,
			&network,
			mdnstest.Port{Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("198.51.100.9/24")}},
		)
		question.Unicast = false

		for _, message := range messages(t, asks(), []wire.Question{question}) {
			for _, from := range []*neighbour{far, other} {
				if err := from.link(t, "en0").Unicast(message, netip.MustParseAddrPort("192.0.2.1:5353")); err != nil {
					t.Fatal(err)
				}
			}
		}

		if said := other.next(); said.group || !reflect.DeepEqual(said.Answers, []wire.Record{address(1, true)}) {
			t.Errorf("answered to all, or not: %+v", said)
		}

		far.quiet(t, time.Minute)
		third.quiet(t, time.Minute)
	})
}

// Section 7.2: a question cut short is answered after 400 to 500 ms,
// and not with what its asker says it knows in what follows. Section
// 7.4: what another host has just said need not be said again.
func TestWhatNeedNotBeSaid(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		settled(t, host, other, engine.Set{Records: []wire.Record{pointer("Kitchen", 4500), pointer("Garden", 4500)}})

		cut := func(known ...wire.Record) {
			for _, message := range messages(t, wire.Header{Truncated: true}, []wire.Question{query(typeName(), wire.TypePTR)}, known...) {
				if err := other.link(t, "en0").Multicast(message); err != nil {
					t.Fatal(err)
				}
			}
		}

		began := time.Now()

		cut()
		time.Sleep(100 * time.Millisecond)

		// The rest of what it knows, with no question: the kitchen.
		for _, message := range messages(t, asks(), nil, pointer("Kitchen", 4500)) {
			if err := other.link(t, "en0").Multicast(message); err != nil {
				t.Fatal(err)
			}
		}

		other.drain()

		if said := other.next(); !between(said.at, began, 400*time.Millisecond, 500*time.Millisecond) ||
			!reflect.DeepEqual(said.Answers, []wire.Record{pointer("Garden", 4500)}) {
			t.Errorf("answered %s later with %+v", said.at.Sub(began), said.Answers)
		}

		// Another host says the garden before this one does: only the
		// kitchen is left to say.
		time.Sleep(2 * time.Second)
		other.ask(t, query(typeName(), wire.TypePTR))
		other.answer(t, "en0", pointer("Garden", 4500))
		other.drain()

		if said := other.next(); !reflect.DeepEqual(said.Answers, []wire.Record{pointer("Kitchen", 4500)}) {
			t.Errorf("answered with %+v", said.Answers)
		}

		// Said by another for less long than this host says it, it is
		// still this host's to say.
		time.Sleep(2 * time.Second)
		other.ask(t, query(typeName(), wire.TypePTR))
		other.answer(t, "en0", pointer("Garden", 4499))

		if said := other.next(); !reflect.DeepEqual(
			said.Answers,
			[]wire.Record{pointer("Kitchen", 4500), pointer("Garden", 4500)},
		) {
			t.Errorf("answered with %+v", said.Answers)
		}

		// Said by another for half as long or more, nothing; for less,
		// it is said again, so that no one forgets it early (6.6).
		time.Sleep(2 * time.Second)
		other.answer(t, "en0", pointer("Garden", 2250))
		other.quiet(t, time.Minute)

		again := time.Now()

		other.answer(t, "en0", pointer("Garden", 2249))

		if said := other.next(); !said.at.Equal(again) ||
			!reflect.DeepEqual(said.Answers, []wire.Record{pointer("Garden", 4500)}) {
			t.Errorf("said again %s later: %+v", said.at.Sub(again), said.Answers)
		}

		// A question cut short twice: the wait starts over with the
		// second.
		time.Sleep(2 * time.Second)

		began = time.Now()

		cut()
		time.Sleep(300 * time.Millisecond)

		// More of what it knows, itself cut short, and no question.
		for _, message := range messages(t, wire.Header{Truncated: true}, nil, pointer("Cellar", 4500)) {
			if err := other.link(t, "en0").Multicast(message); err != nil {
				t.Fatal(err)
			}
		}

		if said := other.next(); !between(said.at, began, 700*time.Millisecond, 800*time.Millisecond) {
			t.Errorf("answered %s after a question cut short twice", said.at.Sub(began))
		}
	})
}

// Section 6.7: a resolver that is not a Multicast DNS one is answered
// where it asked from, as a DNS server would: its question and its
// number said again, nothing to remember over ten seconds, nothing
// marked as this host's alone.
func TestAResolverOfAnotherKind(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		resolver := network.Host(port("en0", lan, 7))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		settled(t, host, other, engine.Set{Records: append(service(), address(1, true))})

		socket, err := resolver.Socket(netip.MustParseAddrPort("192.0.2.7:49152"))
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = socket.Close() }()

		question := query(instanceName(), wire.TypeSRV)
		message := wire.NewBuilder(nil, wire.Header{ID: 0x1234, RecursionDesired: true}, wire.Options{})

		if err = message.Question(question); err != nil {
			t.Fatal(err)
		}

		if err = socket.Multicast(message.Bytes()); err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, transport.MaxPacket)

		size, from, err := socket.Read(buf)
		if err != nil || from != netip.MustParseAddrPort("192.0.2.1:5353") {
			t.Fatalf("answered from %s, %v", from, err)
		}

		short := func(record wire.Record) wire.Record {
			record.Flush, record.TTL = false, min(record.TTL, 10)

			return record
		}

		want := wire.Message{
			Header:      wire.Header{ID: 0x1234, Response: true, Authoritative: true, RecursionDesired: true},
			Questions:   []wire.Question{question},
			Answers:     []wire.Record{short(service()[1])},
			Additionals: []wire.Record{short(address(1, true)), short(denial())},
		}

		if got, err := wire.Parse(buf[:size]); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("answered with\n%+v\nwant\n%+v, %v", got, want, err)
		}

		// The target written in full: a resolver of 1996 reads no other.
		if full := "\x00\x00\x00\x00\x1f\x90\x07kitchen\x05local\x00"; !bytes.Contains(buf[:size], []byte(full)) {
			t.Errorf("the target is not written in full in %q", buf[:size])
		}

		// And no one else was told anything, but the question.
		if overheard := other.next(); overheard.Header.Response {
			t.Errorf("said to all: %+v", overheard.Message)
		}

		other.quiet(t, time.Second)
	})
}

// Section 10.1: what is withdrawn is said goodbye to; and everything
// is, when the Engine closes.
func TestAGoodbyeIsSaid(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		first := settled(t, host, other, engine.Set{Records: []wire.Record{address(1, true)}})

		settled(t, host, other, engine.Set{Records: []wire.Record{pointer("Kitchen", 4500)}})

		gone := func(record wire.Record) wire.Record {
			record.TTL, record.Flush = 0, false

			return record
		}

		if first.Err() != nil {
			t.Fatalf("a publication that stands has ended: %v", first.Err())
		}

		if err := first.Close(); err != nil {
			t.Fatal(err)
		}

		<-first.Done()

		if said := other.next(); !reflect.DeepEqual(
			said.Message,
			wire.Message{Header: answers(), Answers: []wire.Record{gone(address(1, true))}},
		) ||
			!errors.Is(first.Err(), engine.ErrClosed) {
			t.Errorf("withdrawn with %+v, %v", said.Message, first.Err())
		}

		// Closed twice, nothing more is said; and it is answered for no
		// more.
		_ = first.Close()

		other.ask(t, query(hostName(), wire.TypeA))
		other.quiet(t, time.Second)

		if err := host.Close(); err != nil {
			t.Fatal(err)
		}

		if said := other.next(); !reflect.DeepEqual(said.Answers, []wire.Record{gone(pointer("Kitchen", 4500))}) {
			t.Errorf("left with %+v", said.Message)
		}

		if _, err := host.Publish(
			t.Context(),
			engine.Set{Records: []wire.Record{address(1, true)}},
		); !errors.Is(
			err,
			engine.ErrClosed,
		) {
			t.Errorf("publishing on an Engine that is closed: %v", err)
		}
	})
}

// Section 9: when another host says a record of a name this host holds,
// the name is asked for again; kept when no one answers, and lost when
// the other does.
func TestANameIsContested(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		publication := settled(t, host, other, engine.Set{Records: append(service(), address(1, true))})

		// A record of another type, a goodbye: no one having the name.
		other.answer(t, "en0", wire.Record{Name: hostName(), Class: wire.ClassIN, TTL: 120, Data: wire.Text{}})
		other.answer(
			t,
			"en0",
			wire.Record{
				Name:  hostName(),
				Class: wire.ClassIN,
				TTL:   0,
				Data:  wire.Address{Addr: netip.MustParseAddr("192.0.2.9")},
			},
		)
		other.quiet(t, time.Second)

		// Another address under the name: asked for again, with all that
		// is this host's alone; and while it is, not answered for.
		contested := time.Now()

		other.answer(t, "en0", address(9, true))

		for index := range 3 {
			// For the two names that are this host's alone, and not for
			// the one others may say too.
			if probe := other.next(); probe.Header.Response || len(probe.Questions) != 2 ||
				len(probe.Authorities) != 3 ||
				probe.at.Sub(contested) > time.Duration(250*(index+1))*time.Millisecond {
				t.Fatalf("not asked for again, a time %d: %+v", index+1, probe.Message)
			}

			other.ask(t, query(hostName(), wire.TypeA))
		}

		// No one answers: the name is kept, and said again.
		if said := other.next(); !said.Header.Response || len(said.Answers) != 4 || publication.Err() != nil {
			t.Fatalf("not said again: %+v, %v", said.Message, publication.Err())
		}

		time.Sleep(4 * time.Second)
		other.drain()

		// Again, and this time the other host answers: the name is lost.
		// What others may say too is said goodbye to; the rest is no
		// longer this host's to speak of.
		other.answer(t, "en0", address(9, true))
		other.next()
		other.answer(t, "en0", address(9, true))

		<-publication.Done()

		if !errors.Is(publication.Err(), engine.ErrConflict) {
			t.Errorf("ended with %v", publication.Err())
		}

		if said := other.next(); !reflect.DeepEqual(said.Answers, []wire.Record{pointer("Kitchen", 0)}) {
			t.Errorf("left with %+v", said.Answers)
		}

		other.quiet(t, time.Hour)
	})
}

// Section 8.1: a host that asks for a name this one holds is told so at
// once, and to it alone, however long ago the record was last said: it
// has 750 ms to learn of it. And all are told again, should it have
// been long enough (5.4); twice in a row, not sooner than 250 ms apart
// (6).
func TestANameIsDefended(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		third := join(t, &network, port("en0", lan, 3))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		settled(t, host, other, engine.Set{Records: []wire.Record{address(1, true)}})
		time.Sleep(time.Minute)
		third.drain()

		// Asking for an answer of its own: it gets one, and all are told,
		// the record having been said a minute ago.
		asked := time.Now()

		other.claim(t, true, address(9, false))
		third.next()

		for _, told := range []heard{other.next(), other.next(), third.next()} {
			if !told.at.Equal(asked) || !reflect.DeepEqual(told.Answers, []wire.Record{address(1, true)}) {
				t.Errorf("told %s later: %+v", told.at.Sub(asked), told.Answers)
			}
		}

		// Asking again at once: its own answer and no more, all having
		// just been told.
		other.claim(t, true, address(9, false))

		if told := other.next(); told.group || !told.at.Equal(asked) {
			t.Errorf("told %s later, to all %t", told.at.Sub(asked), told.group)
		}

		third.next()
		third.quiet(t, time.Minute)

		// Asking all, twice in a row: all are told twice, 250 ms apart,
		// where any other question would wait a second.
		asked = time.Now()

		for _, after := range []time.Duration{0, 250 * time.Millisecond} {
			other.claim(t, false, address(9, false))
			third.next()

			if told := third.next(); !told.group || told.at.Sub(asked) != after {
				t.Errorf("all told %s later", told.at.Sub(asked))
			}
		}

		// Asked of all, the name's holder answers all, and not the asker
		// alone as well.
		other.drain()

		time.Sleep(time.Minute)
		other.claim(t, false, address(9, false))

		if told := other.next(); !told.group {
			t.Error("an asker that did not ask for an answer of its own got one")
		}

		other.quiet(t, time.Minute)
	})
}

// A host's name is at other addresses on each link: each interface's
// own, said there and nowhere else (section 6.2), and said again when
// they change (8.4). On two interfaces of one wire, a host hears itself
// and is no one to lose its name to (14).
func TestAHostsAddresses(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("eth0", lan, 2), port("eth1", wifi, 12))
		machine := network.Host(port("en0", lan, 1), port("en1", wifi, 11), port("en2", lan, 21))
		host := open(t, engine.Config{Network: machine})

		only := func(_ transport.Interface, addr netip.Addr) bool {
			return addr != netip.MustParseAddr("192.0.2.66")
		}

		start := time.Now()

		// Within a second: an interface that hears another of the host's
		// ask for the name does not yield to it.
		if done := <-publish(
			t,
			host,
			engine.Set{Host: hostName(), Addresses: only},
		); done.err != nil ||
			done.at.Sub(start) > time.Second {
			t.Fatalf("published after %s: %v", done.at.Sub(start), done.err)
		}

		time.Sleep(4 * time.Second)

		// Said on each link: the addresses of the interfaces there, and
		// no other. Two of them are on one wire, and hear each other.
		said := map[string][]string{}

		for len(other.heard) > 0 {
			message := <-other.heard

			for _, record := range message.Answers {
				if data, ok := record.Data.(wire.Address); ok &&
					!slices.Contains(said[message.on], data.Addr.String()) {
					said[message.on] = append(said[message.on], data.Addr.String())
				}
			}
		}

		slices.Sort(said["eth0"])

		if want := map[string][]string{
			"eth0": {"192.0.2.1", "192.0.2.21"},
			"eth1": {"192.0.2.11"},
		}; !reflect.DeepEqual(
			said,
			want,
		) {
			t.Errorf("said %v, want %v", said, want)
		}

		// Other addresses on an interface: said there, at once, with no
		// asking; one that is not to be said is not. The address of the
		// other family comes with its own link, a moment after.
		changed := time.Now()

		machine.Plug(mdnstest.Port{Interface: "en1", Wire: wifi, Addrs: []netip.Prefix{
			netip.MustParsePrefix(
				"192.0.2.12/24",
			),
			netip.MustParsePrefix("192.0.2.66/24"),
			netip.MustParsePrefix("2001:db8::12/64"),
		}})

		ipv6 := unique(wire.Record{
			Name:  hostName(),
			Class: wire.ClassIN,
			TTL:   120,
			Data:  wire.Address{Addr: netip.MustParseAddr("2001:db8::12")},
		})

		for _, want := range []wire.Message{
			{Header: answers(), Answers: []wire.Record{address(12, true)}, Additionals: []wire.Record{denial()}},
			{Header: answers(), Answers: []wire.Record{address(12, true), ipv6}},
		} {
			if got := other.next(); got.on != "eth1" || !got.at.Equal(changed) ||
				!reflect.DeepEqual(got.Message, want) {
				t.Errorf("said on %s, %s later: %+v", got.on, got.at.Sub(changed), got.Message)
			}
		}
	})
}

// Addresses that change while the name is still asked for are not said
// before it is taken. And what another host says to this one alone was
// not said to all: it is still this host's to say (7.4).
func TestWhileANameIsAskedFor(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		machine := network.Host(port("en0", lan, 1))
		host := open(t, engine.Config{Network: machine})

		settled(t, host, other, engine.Set{Records: []wire.Record{pointer("Kitchen", 4500)}})

		publishing := publish(t, host, engine.Set{Host: hostName()})

		other.next()
		machine.Plug(port("en0", lan, 5))

		// Asked a question while it asks for its name: the answer it is
		// about to give is said to it alone by another, which it takes,
		// having just asked for answers of its own.
		other.ask(t, query(typeName(), wire.TypePTR))
		other.answerTo(t, netip.MustParseAddr("192.0.2.5"), pointer("Kitchen", 4500))

		if said := other.next(); !said.Header.Response ||
			!reflect.DeepEqual(said.Answers, []wire.Record{pointer("Kitchen", 4500)}) {
			t.Fatalf("answered with %+v", said.Message)
		}

		for range 2 {
			if probe := other.next(); probe.Header.Response ||
				!reflect.DeepEqual(probe.Authorities, []wire.Record{address(5, false)}) {
				t.Fatalf("not asked for with the address it now has: %+v", probe.Message)
			}
		}

		if said := other.next(); !said.Header.Response ||
			!reflect.DeepEqual(said.Answers, []wire.Record{address(5, true)}) {
			t.Errorf("said %+v", said.Message)
		}

		if done := <-publishing; done.err != nil {
			t.Error(done.err)
		}
	})
}

// An interface that comes up later is published on as the others were,
// when it is one of those chosen.
func TestALinkThatComesLater(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("eth0", lan, 2), port("eth1", wifi, 12))
		machine := network.Host()
		host := open(t, engine.Config{Network: machine})
		chosen := func(candidate transport.Interface) bool { return candidate.Name == "en1" }

		// With no link to say it on, a set is published at once.
		start := time.Now()

		done := <-publish(t, host, engine.Set{Records: []wire.Record{address(1, true)}, Interfaces: chosen})
		if done.err != nil || !done.at.Equal(start) {
			t.Fatalf("published after %s, %v", done.at.Sub(start), done.err)
		}

		machine.Plug(port("en0", lan, 1))
		machine.Plug(port("en1", wifi, 11))

		for index := range 4 {
			if said := other.next(); said.on != "eth1" || said.Header.Response != (index == 3) {
				t.Fatalf("message %d on %s: %+v", index, said.on, said.Message)
			}
		}

		// The link goes: nothing is said on it, and the set stands.
		machine.Unplug("en1")
		other.quiet(t, time.Hour)

		if done.Err() != nil {
			t.Errorf("ended with %v", done.Err())
		}
	})
}

// Section 8.4: records that change are said again, without asking for
// their names again; what others may say too is said goodbye to first;
// and not more than ten times a minute.
func TestRecordsChange(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		publication := settled(t, host, other, engine.Set{Records: service()})

		text := func(value string) wire.Record {
			return wire.Record{
				Name:  instanceName(),
				Class: wire.ClassIN,
				TTL:   4500,
				Flush: true,
				Data:  wire.Text{Strings: []string{value}},
			}
		}

		changed := []wire.Record{pointer("Kitchen", 4500), service()[1], text("path=/new")}

		began := time.Now()

		if err := publication.Update(changed); err != nil {
			t.Fatal(err)
		}

		if said := other.next(); !said.at.Equal(began) || !reflect.DeepEqual(said.Answers, changed) {
			t.Errorf("said %s later: %+v", said.at.Sub(began), said.Answers)
		}

		// Twice more in a row: said once, six seconds after the first,
		// as they then stand; with a goodbye, at once, for what others
		// may say too and is no more.
		last := []wire.Record{service()[1], text("path=/last")}

		for _, next := range [][]wire.Record{{service()[1], text("path=/between")}, last} {
			if err := publication.Update(next); err != nil {
				t.Fatal(err)
			}
		}

		if said := other.next(); !said.at.Equal(began) ||
			!reflect.DeepEqual(said.Answers, []wire.Record{pointer("Kitchen", 0)}) {
			t.Errorf("said goodbye %s later with %+v", said.at.Sub(began), said.Answers)
		}

		for range 2 {
			other.next()
		}

		if said := other.next(); said.at.Sub(began) != 6*time.Second || !reflect.DeepEqual(said.Answers, last) {
			t.Errorf("said %s later: %+v", said.at.Sub(began), said.Answers)
		}

		// A name that was not asked for cannot be slipped in; nor a
		// record that cannot be said.
		other.drain()

		for what, refused := range map[string][]wire.Record{
			"a name not asked for": {address(1, true)},
			"a record of no data":  {{Name: instanceName(), TTL: 1}},
			"nothing":              nil,
		} {
			if err := publication.Update(refused); !errors.Is(err, engine.ErrInvalid) {
				t.Errorf("%s: %v", what, err)
			}
		}

		_ = publication.Close()

		if err := publication.Update(last); !errors.Is(err, engine.ErrClosed) {
			t.Errorf("changing what is withdrawn: %v", err)
		}
	})
}

// What a host answers for answers its own questions; and a Publish that
// is given up says nothing.
func TestWhatIsPublishedIsKnown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		asking := ask(t, host, engine.Question{Name: hostName(), Type: wire.TypeANY})

		asking.nothing(t)

		// Known when the name is taken, and not while it is asked for.
		taken := <-publish(t, host, engine.Set{Records: []wire.Record{address(1, true)}})
		publication := taken.Publication

		found := asking.next(t, engine.Found)
		if !found.at.Equal(taken.at) || !reflect.DeepEqual(found.answer.Record, address(1, true)) ||
			names(found.answer.Interfaces) != "en0 " {
			t.Errorf("found %+v, %s before it was published", found.answer, taken.at.Sub(found.at))
		}

		time.Sleep(4 * time.Second)

		_ = publication.Close()

		asking.next(t, engine.Lost)
		asking.nothing(t)
		asking.stop()
		other.drain()

		// Given up while the name is asked for.
		ctx, stop := context.WithCancel(t.Context())
		done := make(chan error, 1)

		go func() {
			_, err := host.Publish(ctx, engine.Set{Records: []wire.Record{address(1, true), pointer("Kitchen", 4500)}})
			done <- err
		}()

		for len(other.heard) == 0 {
			time.Sleep(10 * time.Millisecond)
		}

		other.drain()
		stop()

		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("a Publish given up: %v", err)
		}

		other.quiet(t, time.Hour)

		for what, refused := range map[string]engine.Set{
			"nothing":              {},
			"a record with no TTL": {Records: []wire.Record{{Name: hostName(), Data: wire.Text{}}}},
			"a record of no name":  {Records: []wire.Record{{TTL: 1, Data: wire.Text{}}}},
			"a host of no name":    {Host: []string{}},
			"a host of a bad name": {Host: []string{""}},
		} {
			if _, err := host.Publish(t.Context(), refused); !errors.Is(err, engine.ErrInvalid) {
				t.Errorf("%s: %v", what, err)
			}
		}
	})
}

// What comes from another port than 5353 is not Multicast DNS: an
// answer from there is not taken (section 6), and a question from there
// is not one that others answer to all, so it does not stand for this
// host's own (7.3).
func TestWhatComesFromAnotherPort(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		resolver := network.Host(port("en0", lan, 7))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		socket, err := resolver.Socket(netip.MustParseAddrPort("192.0.2.7:49152"))
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = socket.Close() }()

		first := other.next()

		for _, message := range messages(t, answers(), nil, pointer("Kitchen", 4500)) {
			if err = socket.Multicast(message); err != nil {
				t.Fatal(err)
			}
		}

		other.next()
		asking.nothing(t)

		time.Sleep(500 * time.Millisecond)

		for _, message := range messages(t, asks(), []wire.Question{query(typeName(), wire.TypePTR)}) {
			if err = socket.Multicast(message); err != nil {
				t.Fatal(err)
			}
		}

		other.next()

		if again := other.next(); again.at.Sub(first.at) != time.Second {
			t.Errorf("asked again %s after the first", again.at.Sub(first.at))
		}
	})
}
