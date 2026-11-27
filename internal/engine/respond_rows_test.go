package engine_test

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

// RFC 6762 section 17: a message is as large as its link carries, and
// one sent in pieces because a record is larger holds that record and
// no other.
func TestMessagesFitTheirLink(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		var many []wire.Record
		for index := range 80 {
			many = append(many, pointer(fmt.Sprintf("An instance with a name of some length, %02d", index), 4500))
		}

		said := time.Now()

		if done := <-publish(t, host, engine.Set{Records: many}); done.err != nil {
			t.Fatal(done.err)
		}

		synctest.Wait()

		answers := 0

		for len(other.heard) > 0 {
			message := <-other.heard
			if !message.at.Equal(said) {
				break
			}

			if answers += len(message.Answers); message.size > 1500-28 {
				t.Errorf(
					"a message of %d bytes and %d records on a link that carries 1500",
					message.size,
					len(message.Answers),
				)
			}
		}

		if answers != len(many) {
			t.Errorf("%d records said at first, of %d", answers, len(many))
		}

		// One record larger than the link carries, between two that are
		// not: it goes alone.
		time.Sleep(time.Minute)
		other.drain()

		large := wire.Record{
			Name:  hostName(),
			Class: wire.ClassIN,
			TTL:   4500,
			Data:  wire.Text{Strings: slicesOf(strings.Repeat("x", 250), 12)},
		}

		if done := <-publish(
			t,
			host,
			engine.Set{Records: []wire.Record{pointer("Before", 4500), large, pointer("After", 4500)}},
		); done.err != nil {
			t.Fatal(done.err)
		}

		var shapes []string

		for range 3 {
			message := other.next()
			shapes = append(
				shapes,
				fmt.Sprintf("%d records, over the link's room: %t", len(message.Answers), message.size > 1500-28),
			)
		}

		if want := []string{
			"1 records, over the link's room: false",
			"1 records, over the link's room: true",
			"1 records, over the link's room: false",
		}; !reflect.DeepEqual(
			shapes,
			want,
		) {
			t.Errorf("said as %q", shapes)
		}
	})
}

func slicesOf(one string, count int) []string {
	many := make([]string, count)
	for index := range many {
		many[index] = one
	}

	return many
}

// Section 8.1: after fifteen conflicts in ten seconds, a host waits five
// before it asks for a name again.
func TestTooManyNamesLost(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		began := time.Now()

		for range 15 {
			publishing := publish(t, host, engine.Set{Records: []wire.Record{address(1, true)}})

			other.next()
			other.answer(t, "en0", address(9, true))

			if done := <-publishing; !errors.Is(done.err, engine.ErrConflict) {
				t.Fatalf("published: %v", done.err)
			}
		}

		if time.Since(began) > 10*time.Second {
			t.Fatalf("fifteen names lost in %s", time.Since(began))
		}

		asked := time.Now()

		publish(t, host, engine.Set{Records: []wire.Record{address(1, true)}})

		if probe := other.next(); !between(probe.at, asked, 5*time.Second, 5250*time.Millisecond) {
			t.Errorf("asked for a name again %s after losing fifteen", probe.at.Sub(asked))
		}
	})
}

// Section 10.1: an address that goes, the last of its family, has
// nothing said in its place to take it back, and is said goodbye to.
func TestTheLastAddressOfAFamilyGoes(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		both := mdnstest.Port{Interface: "en0", Wire: lan, Addrs: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("2001:db8::1/64"),
		}}

		other := join(t, &network, port("en0", lan, 2))
		machine := network.Host(both)
		host := open(t, engine.Config{Network: machine})

		settled(t, host, other, engine.Set{Host: hostName()})

		machine.Plug(port("en0", lan, 1))

		gone := wire.Record{
			Name:  hostName(),
			Class: wire.ClassIN,
			Data:  wire.Address{Addr: netip.MustParseAddr("2001:db8::1")},
		}

		if said := other.next(); !reflect.DeepEqual(said.Answers, []wire.Record{gone}) {
			t.Errorf("said %+v", said.Answers)
		}

		if said := other.next(); !reflect.DeepEqual(said.Answers, []wire.Record{address(1, true)}) {
			t.Errorf("then said %+v", said.Answers)
		}
	})
}

// Another program on the host says where the host is as truly as this
// one, and is not lost the host's name to, whatever else it says of
// that name; a service it says is somewhere else is a conflict as any
// other host's is.
func TestAnotherProgramOnTheHost(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		machine := network.Host(mdnstest.Port{Interface: "en0", Wire: lan, Addrs: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("192.0.2.3/24"),
		}})

		first := open(t, engine.Config{Network: machine})
		second := open(t, engine.Config{Network: machine})
		one := func(_ transport.Interface, addr netip.Addr) bool { return addr == netip.MustParseAddr("192.0.2.1") }

		// The first holds the host's name at both addresses; the second
		// asks for it at one of them, and is answered with both and with
		// the word of what other records the name has not.
		for index, set := range []engine.Set{{Host: hostName()}, {Host: hostName(), Addresses: one}} {
			if done := <-publish(t, []*engine.Engine{first, second}[index], set); done.err != nil {
				t.Fatalf("the host's name, for program %d: %v", index+1, done.err)
			}
		}

		service := service()

		if done := <-publish(t, first, engine.Set{Records: service[1:]}); done.err != nil {
			t.Fatal(done.err)
		}

		elsewhere := service[1]
		elsewhere.Data = wire.Service{Port: 9090, Target: hostName()}

		if done := <-publish(
			t,
			second,
			engine.Set{Records: []wire.Record{elsewhere}},
		); !errors.Is(
			done.err,
			engine.ErrConflict,
		) {
			t.Errorf("a service another program on the host has: %v", done.err)
		}
	})
}

// A life of 2^31 seconds and over is still more than half of any other.
func TestALifeTooLongToDouble(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		settled(t, host, other, engine.Set{Records: []wire.Record{pointer("Kitchen", 4500)}})

		// Said to be known for that long: not said again. Said by another
		// for that long: not said again either.
		other.ask(t, query(typeName(), wire.TypePTR), pointer("Kitchen", 1<<31))
		other.quiet(t, time.Minute)

		other.answer(t, "en0", pointer("Kitchen", 1<<31))
		other.quiet(t, time.Minute)
	})
}

// What a host answers for answers its own questions; the word that one
// of its names has no record of a type is an answer to others, and no
// record to itself.
func TestAHostAsksItselfForWhatItHasNot(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		settled(t, host, other, engine.Set{Records: []wire.Record{address(1, true)}})

		// A neighbour that asks is told the name has no such record,
		// which is what makes the word there is to find.
		other.ask(t, query(hostName(), wire.TypeAAAA))

		if said := other.next(); !reflect.DeepEqual(said.Answers, []wire.Record{denial()}) {
			t.Fatalf("a neighbour was told %+v", said.Answers)
		}

		ask(t, host, engine.Question{Name: hostName(), Type: wire.TypeAAAA}).nothing(t)

		everything := ask(t, host, engine.Question{Name: hostName(), Type: wire.TypeANY})
		if found := everything.next(t, engine.Found); !reflect.DeepEqual(found.answer.Record, address(1, true)) {
			t.Errorf("found %+v", found.answer.Record)
		}

		everything.nothing(t)
	})
}

// RFC 6762 section 6: a responder answers what it is asked, and its
// limits are there against "excessive packet flooding due to software
// bugs or malicious attack". A message that repeats one question two
// hundred times, or asks two questions the same records answer, is
// answered with each record once: to its asker alone where it asks for
// that, as a host asking for a name does, and to a resolver that is no
// Multicast DNS host.
func TestAQuestionRepeatedIsAnsweredOnce(t *testing.T) {
	t.Parallel()

	repeated := func(t *testing.T, id uint16, questions ...wire.Question) []byte {
		t.Helper()

		message := wire.NewBuilder(nil, wire.Header{ID: id}, wire.Options{Limit: 1472})

		for range 200 / len(questions) {
			for _, question := range questions {
				if err := message.Question(question); err != nil {
					t.Fatal(err)
				}
			}
		}

		// What the asker means to say of the name, as a host asking for
		// it does: it is then answered at once, and alone.
		if id == 0 {
			record := wire.Record{Name: instanceName(), Class: wire.ClassIN, TTL: 120, Data: wire.Text{}}
			if err := message.Authority(record); err != nil {
				t.Fatal(err)
			}
		}

		return message.Bytes()
	}

	once := func(t *testing.T, what string, answers []wire.Record) {
		t.Helper()

		seen := map[string]int{}

		for _, record := range answers {
			data, err := wire.AppendData(nil, record.Data)
			if err != nil {
				t.Fatal(err)
			}

			seen[fmt.Sprint(record.Name, record.Type())+string(data)]++
		}

		// The service's SRV and TXT records.
		if len(seen) != 2 || len(answers) != 2 {
			t.Errorf("%s: answered with %d records, %d of them distinct; want the name's two, each once",
				what, len(answers), len(seen))
		}
	}

	alone := func(name []string, kind uint16) wire.Question {
		question := query(name, kind)
		question.Unicast = true

		return question
	}

	for what, questions := range map[string][]wire.Question{
		"one question, two hundred times":       {alone(instanceName(), wire.TypeANY)},
		"two questions the same records answer": {alone(instanceName(), wire.TypeANY), alone(instanceName(), wire.TypeSRV), alone(instanceName(), wire.TypeTXT)},
	} {
		t.Run(what, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var network mdnstest.Network

				other := join(t, &network, port("en0", lan, 2))
				resolver := network.Host(port("en0", lan, 7))
				host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

				settled(t, host, other, engine.Set{Records: service()})
				time.Sleep(time.Minute)
				other.drain()

				if err := other.link(t, "en0").Multicast(repeated(t, 0, questions...)); err != nil {
					t.Fatal(err)
				}

				time.Sleep(2 * time.Second)
				synctest.Wait()

				var told []wire.Record

				for len(other.heard) > 0 {
					if message := <-other.heard; !message.group {
						told = append(told, message.Answers...)
					}
				}

				once(t, "to the host that asks for the name", told)

				// A resolver, from a port of its own.
				socket, err := resolver.Socket(netip.MustParseAddrPort("192.0.2.7:49152"))
				if err != nil {
					t.Fatal(err)
				}

				defer func() { _ = socket.Close() }()

				if err = socket.Multicast(repeated(t, 7, questions...)); err != nil {
					t.Fatal(err)
				}

				buf := make([]byte, transport.MaxPacket)

				size, _, err := socket.Read(buf)
				if err != nil {
					t.Fatal(err)
				}

				answer, err := wire.Parse(buf[:size])
				if err != nil {
					t.Fatal(err)
				}

				once(t, "to a resolver", answer.Answers)
			})
		})
	}
}

// RFC 6762 section 10.2: "Any time a host sends a response packet
// containing some members of a unique RRSet, it MUST send the entire
// RRSet". An asker that knows one of a name's two addresses is told
// both, each to be this host's alone; one that knows both is told
// nothing (section 7.1). Records others may say too are left out one by
// one: there is no set of them to say whole.
func TestASetThatIsThisHostsAloneIsSaidWhole(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		settled(t, host, other, engine.Set{Records: []wire.Record{
			address(1, true), address(3, true), pointer("Kitchen", 4500), pointer("Garden", 4500),
		}})

		// told is what the neighbour hears in answer, as its data and
		// whether it is said to be this host's alone.
		told := func(question wire.Question, known ...wire.Record) map[string]bool {
			time.Sleep(time.Minute)
			other.drain()
			other.ask(t, question, known...)
			time.Sleep(time.Second)
			synctest.Wait()

			answers := map[string]bool{}

			for len(other.heard) > 0 {
				for _, answer := range (<-other.heard).Answers {
					answers[fmt.Sprint(answer.Data)] = answer.Flush
				}
			}

			return answers
		}

		both := map[string]bool{fmt.Sprint(address(1, true).Data): true, fmt.Sprint(address(3, true).Data): true}

		if got := told(query(hostName(), wire.TypeA), address(1, false)); !reflect.DeepEqual(got, both) {
			t.Errorf("an asker that knows one address of two is told %v; want both, each this host's alone", got)
		}

		if got := told(query(hostName(), wire.TypeA), address(1, false), address(3, false)); len(got) != 0 {
			t.Errorf("an asker that knows both addresses is told %v; want nothing", got)
		}

		garden := map[string]bool{fmt.Sprint(pointer("Garden", 4500).Data): false}

		if got := told(query(typeName(), wire.TypePTR), pointer("Kitchen", 4500)); !reflect.DeepEqual(got, garden) {
			t.Errorf("an asker that knows one instance of two is told %v; want the other alone", got)
		}
	})
}

// Section 7.2: what an asker knows may come in more than one message,
// after a question cut short. The set is weighed against all of it: an
// asker that says in its second message that it knows the address it
// did not name in its first knows both, and is told nothing; one that
// knows one address in all, said first or after, is told both.
func TestASetIsWeighedAgainstAllItsAskerKnows(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		settled(t, host, other, engine.Set{Records: []wire.Record{address(1, true), address(3, true)}})

		// A set of another name, held along with the first when both are
		// asked for in one message.
		garden := wire.Record{
			Name: []string{"garden", "local"}, Class: wire.ClassIN, TTL: 120, Flush: true,
			Data: wire.Address{Addr: netip.AddrFrom4([4]byte{192, 0, 2, 5})},
		}

		settled(t, host, other, engine.Set{Records: []wire.Record{garden}})

		say := func(header wire.Header, questions []wire.Question, known ...wire.Record) {
			for _, message := range messages(t, header, questions, known...) {
				if err := other.link(t, "en0").Multicast(message); err != nil {
					t.Fatal(err)
				}
			}
		}

		// told is what the neighbour hears in answer to a question cut
		// short, knowing some addresses then, and others in the message
		// that follows.
		told := func(names [][]string, first, then []wire.Record) map[string]bool {
			var questions []wire.Question

			for _, name := range names {
				questions = append(questions, query(name, wire.TypeA))
			}

			time.Sleep(time.Minute)
			other.drain()
			say(wire.Header{Truncated: true}, questions, first...)
			time.Sleep(100 * time.Millisecond)
			say(asks(), nil, then...)
			time.Sleep(time.Second)
			synctest.Wait()

			answers := map[string]bool{}

			for len(other.heard) > 0 {
				for _, answer := range (<-other.heard).Answers {
					answers[fmt.Sprint(answer.Data)] = answer.Flush
				}
			}

			return answers
		}

		one, three := address(1, false), address(3, false)
		both := map[string]bool{fmt.Sprint(one.Data): true, fmt.Sprint(three.Data): true}

		for what, row := range map[string]struct {
			first, then []wire.Record
			want        map[string]bool
		}{
			"one, then the other": {first: []wire.Record{one}, then: []wire.Record{three}, want: map[string]bool{}},
			"none, then both":     {then: []wire.Record{one, three}, want: map[string]bool{}},
			"none, then one":      {then: []wire.Record{one}, want: both},
			"one, then no other":  {first: []wire.Record{one}, then: []wire.Record{pointer("Kitchen", 4500)}, want: both},
		} {
			if got := told([][]string{hostName()}, row.first, row.then); !reflect.DeepEqual(got, row.want) {
				t.Errorf("an asker that knows %s is told %v; want %v", what, got, row.want)
			}
		}

		// Two names asked for at once: a set is the records of one.
		alone := map[string]bool{fmt.Sprint(garden.Data): true}

		if got := told(
			[][]string{hostName(), garden.Name},
			[]wire.Record{one},
			[]wire.Record{three},
		); !reflect.DeepEqual(
			got,
			alone,
		) {
			t.Errorf("an asker that knows all of one name and nothing of another is told %v; want %v", got, alone)
		}
	})
}
