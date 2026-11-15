package engine_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

// named is an A record of a name under local, good for so long.
func named(name string, ttl uint32) wire.Record {
	return wire.Record{
		Name: []string{name, "local"}, Class: wire.ClassIN, TTL: ttl,
		Data: wire.Address{Addr: netip.MustParseAddr("192.0.2.77")},
	}
}

func only(name string) func(transport.Interface) bool {
	return func(candidate transport.Interface) bool { return candidate.Name == name }
}

// Section 5.2: the first question waits 20 to 120 ms, chosen at random.
// Three hundred of them fill that span and none is outside it.
func TestTheFirstQuestionWaitsAtRandom(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asked := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		start := time.Now()

		const many = 300

		for index := range many {
			ask(t, asked, engine.Question{Name: []string{fmt.Sprintf("host-%d", index), "local"}, Type: wire.TypeA})
		}

		soonest, latest := time.Hour, time.Duration(0)

		for seen := 0; seen < many; {
			question := other.next()
			seen += len(question.Questions)
			soonest, latest = min(soonest, question.at.Sub(start)), max(latest, question.at.Sub(start))
		}

		if soonest < 20*time.Millisecond || soonest > 25*time.Millisecond || latest > 120*time.Millisecond ||
			latest < 115*time.Millisecond {
			t.Errorf("first asked between %s and %s", soonest, latest)
		}
	})
}

// A question for every record of a name is never done being asked,
// whatever was answered (section 5.2); what is known is said without
// the mark of its holder (10.2); and a record of a type no one asks
// for by name is still one that is looked for.
func TestAQuestionForEverythingOfAName(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(
			t,
			open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}),
			engine.Question{Name: hostName(), Type: wire.TypeANY},
		)

		first := other.next()
		record := address(1, true)
		record.TTL = 100

		other.answer(t, "en0", record)
		asking.next(t, engine.Found)

		known := record
		known.Flush, known.TTL = false, 99

		if again := other.next(); again.at.Sub(first.at) != time.Second ||
			!reflect.DeepEqual(again.Answers, []wire.Record{known}) {
			t.Fatalf("asked again after %s, knowing %+v", again.at.Sub(first.at), again.Answers)
		}

		// Asked about again as it gets old, by its own type.
		for {
			question := other.next()
			if question.at.Sub(first.at) < 70*time.Second {
				continue
			}

			if want := []wire.Question{
				{Name: hostName(), Type: wire.TypeA, Class: wire.ClassIN},
			}; !reflect.DeepEqual(
				question.Questions,
				want,
			) ||
				!between(question.at, first.at, 80*time.Second, 82*time.Second) {
				t.Errorf("asked %s later: %+v", question.at.Sub(first.at), question.Questions)
			}

			break
		}
	})
}

// A record heard on both families of an interface is heard on that
// interface, once. And of two who ask the same, each is told of what is
// heard where it asked.
func TestWhereAnAnswerIsHeard(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		ipv4 := join(t, &network, port("en0", lan, 2))
		ipv6 := join(
			t,
			&network,
			mdnstest.Port{Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::9/64")}},
		)
		air := join(t, &network, port("en0", wifi, 12))

		asked := open(
			t,
			engine.Config{Network: network.Host(mdnstest.Port{Interface: "en0", Wire: lan}, port("en1", wifi, 11))},
		)
		everywhere := ask(t, asked, browse())
		there := ask(t, asked, engine.Question{Name: typeName(), Type: wire.TypePTR, Interfaces: only("en1")})

		ipv4.answer(t, "en0", pointer("Kitchen", 4500))

		if found := everywhere.next(t, engine.Found); names(found.answer.Interfaces) != "en0 " {
			t.Errorf("found on %s", names(found.answer.Interfaces))
		}

		ipv6.answer(t, "en0", pointer("Kitchen", 4500))
		everywhere.nothing(t)
		there.nothing(t)

		air.answer(t, "en0", pointer("Kitchen", 4500))

		if found := there.next(t, engine.Found); names(found.answer.Interfaces) != "en1 " {
			t.Errorf("found on %s by who asks on en1", names(found.answer.Interfaces))
		}

		if changed := everywhere.next(t, engine.Changed); names(changed.answer.Interfaces) != "en0 en1 " {
			t.Errorf("changed to %s", names(changed.answer.Interfaces))
		}

		// What no one asks about on a link is not asked about again as it
		// gets old there: on the wire, where one of the two asks, it is.
		there.stop()
		everywhere.stop()

		later := ask(t, asked, engine.Question{Name: hostName(), Type: wire.TypeA, Interfaces: only("en1")})
		record := address(1, false)
		record.TTL = 100

		ipv4.answer(t, "en0", record)
		air.answer(t, "en0", record)
		later.next(t, engine.Found)

		for len(ipv4.heard) > 0 {
			<-ipv4.heard
		}

		ipv4.quiet(t, 200*time.Second)
	})
}

// A message is as large as its link carries, the headers of its family
// counted: 48 bytes of them over IPv6.
func TestAMessageFitsItsLink(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		addr := func(last string) []netip.Prefix {
			return []netip.Prefix{netip.MustParsePrefix("2001:db8::" + last + "/64")}
		}
		other := join(t, &network, mdnstest.Port{Interface: "en0", Wire: lan, Addrs: addr("2")})
		asking := ask(
			t,
			open(t, engine.Config{Network: network.Host(mdnstest.Port{Interface: "en0", Wire: lan, Addrs: addr("1")})}),
			browse(),
		)

		other.next()

		for index := range 60 {
			other.answer(
				t,
				"en0",
				pointer(fmt.Sprintf("An instance with a name as long as a name can well be %02d", index), 4500),
			)
			asking.next(t, engine.Found)
		}

		// Nineteen of them and the question: one more would be 1454,
		// two bytes more than fit under 48 of headers.
		if first := other.next(); first.size != 1383 || len(first.Answers) != 19 {
			t.Errorf("a message of %d bytes and %d records on a link that carries 1500", first.size, len(first.Answers))
		}
	})
}

// Section 7.1: a record is said to be known while it has more than half
// its life left, and no longer at the half.
func TestWhatIsKnownAtHalfItsLife(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		first := other.next()

		// Asked again 1, 3, 7, 15 and 31 seconds after the first: at 31
		// seconds one of these is at half its life, the other not yet.
		other.answer(t, "en0", pointer("Kitchen", 62), pointer("Garden", 64))
		asking.next(t, engine.Found)
		asking.next(t, engine.Found)

		for {
			question := other.next()
			if question.at.Sub(first.at) < 31*time.Second {
				continue
			}

			if question.at.Sub(first.at) != 31*time.Second ||
				!reflect.DeepEqual(question.Answers, []wire.Record{pointer("Garden", 33)}) {
				t.Errorf("asked %s later knowing %+v", question.at.Sub(first.at), question.Answers)
			}

			break
		}
	})
}

// Section 7.3 is for the same question, asked of all, for answers to
// all, whole: a question cut short, one sent to this host alone, one
// that would take an answer of its own, one of another class are not
// reasons to keep quiet. What the other says it knows of another name
// is nothing to do with it.
func TestQuestionsOfOthersThatAreNotTheSame(t *testing.T) {
	t.Parallel()

	question := wire.Question{Name: typeName(), Type: wire.TypePTR, Class: wire.ClassIN}
	alone, classless := question, question
	alone.Unicast, classless.Class = true, 3

	for what, row := range map[string]struct {
		header   wire.Header
		question wire.Question
		known    []wire.Record
		direct   bool
		quiet    bool
	}{
		"cut short":                   {header: wire.Header{Truncated: true}, question: question},
		"sent to this host alone":     {question: question, direct: true},
		"for an answer of its own":    {question: alone},
		"of another class":            {question: classless},
		"knowing of another name":     {question: question, known: []wire.Record{named("elsewhere", 4500)}, quiet: true},
		"knowing what is not known":   {question: question, known: []wire.Record{pointer("Unknown", 4500)}},
		"the same, and nothing known": {question: question, quiet: true},
	} {
		t.Run(what, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var network mdnstest.Network

				other := join(t, &network, port("en0", lan, 2))
				third := join(t, &network, port("en0", lan, 3))

				ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

				first := other.next()

				time.Sleep(500 * time.Millisecond)

				for _, message := range messages(t, row.header, []wire.Question{row.question}, row.known...) {
					var err error

					if row.direct {
						err = third.link(t, "en0").Unicast(message, netip.MustParseAddrPort("192.0.2.1:5353"))
					} else {
						err = third.link(t, "en0").Multicast(message)

						other.next()
					}

					if err != nil {
						t.Fatal(err)
					}
				}

				want := time.Second
				if row.quiet {
					want = 2500 * time.Millisecond
				}

				if again := other.next(); again.at.Sub(first.at) != want {
					t.Errorf("asked again %s after the first", again.at.Sub(first.at))
				}
			})
		})
	}
}

// A question that has its answer is not woken by another host asking
// it; the answer is asked about at 80% of its life each time it is
// given anew; and a life no record has is cut to a week.
func TestAnAnswerThatIsKept(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(
			t,
			open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}),
			engine.Question{Name: hostName(), Type: wire.TypeA},
		)

		other.next()

		said := time.Now()

		other.answer(t, "en0", address(1, true))
		asking.next(t, engine.Found)

		time.Sleep(10 * time.Second)
		other.ask(t, wire.Question{Name: hostName(), Type: wire.TypeA, Class: wire.ClassIN})

		for range 2 {
			if again := other.next(); !between(again.at, said, 96*time.Second, 98400*time.Millisecond) {
				t.Fatalf("asked again %s after the answer", again.at.Sub(said))
			}

			said = time.Now()

			other.answer(t, "en0", address(1, true))
		}

		forever := address(1, true)
		forever.TTL = 1<<32 - 1

		said = time.Now()

		other.answer(t, "en0", forever)

		const week = 7 * 24 * time.Hour

		if again := other.next(); !between(again.at, said, week*80/100, week*82/100) {
			t.Errorf("asked again %s after an answer good for ever", again.at.Sub(said))
		}

		asking.nothing(t)
	})
}

// Section 6.1 again: the word that a name has no record of a type is
// its holder's to give, and is about that type.
func TestWhoSaysANameHasNoRecord(t *testing.T) {
	t.Parallel()

	denial := func(flush bool, types ...uint16) wire.Record {
		return wire.Record{
			Name:  hostName(),
			Class: wire.ClassIN,
			TTL:   120,
			Flush: flush,
			Data:  wire.NSEC{Next: hostName(), Types: types},
		}
	}

	for what, said := range map[string]wire.Record{
		"not by the name's holder":    denial(false, wire.TypeA),
		"of a name that has the type": denial(true, wire.TypeA, wire.TypeAAAA),
	} {
		t.Run(what, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var network mdnstest.Network

				other := join(t, &network, port("en0", lan, 2))

				ask(
					t,
					open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}),
					engine.Question{Name: hostName(), Type: wire.TypeAAAA},
				)

				first := other.next()
				other.answer(t, "en0", said)

				if again := other.next(); again.at.Sub(first.at) != time.Second {
					t.Errorf("asked again after %s", again.at.Sub(first.at))
				}
			})
		})
	}
}

// Section 10.5 counts two questions in ten seconds: one that went
// unanswered longer ago than that is forgotten, not the record.
func TestQuestionsUnansweredFarApart(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())
		question := wire.Question{Name: typeName(), Type: wire.TypePTR, Class: wire.ClassIN}

		other.answer(t, "en0", pointer("Kitchen", 4500))
		asking.next(t, engine.Found)

		other.ask(t, question)
		time.Sleep(11 * time.Second)

		second := time.Now()

		other.ask(t, question)
		time.Sleep(time.Second)
		asking.nothing(t)
		other.ask(t, question)

		if lost := asking.next(t, engine.Lost); lost.at.Sub(second) != 10*time.Second {
			t.Errorf("lost %s after the second question", lost.at.Sub(second))
		}
	})
}

// A neighbour cannot make a host remember without end: past 4096
// records on a link, only what is asked about is kept; and what runs
// out makes room again.
func TestWhatNoOneAsksAboutIsKeptOnlySoFar(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asked := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		wanted := ask(t, asked, engine.Question{Name: []string{"wanted", "local"}, Type: wire.TypeA})

		var filling []wire.Record
		for index := range 4096 {
			filling = append(filling, named(fmt.Sprintf("filler-%d", index), 100))
		}

		other.answer(t, "en0", filling...)
		other.answer(t, "en0", named("late", 4500), named("wanted", 4500))

		// Asked about, it is kept all the same.
		wanted.next(t, engine.Found)

		// The first is known; the one that came when there was no room
		// is not.
		ask(t, asked, engine.Question{Name: []string{"filler-0", "local"}, Type: wire.TypeA}).next(t, engine.Found)
		ask(t, asked, engine.Question{Name: []string{"late", "local"}, Type: wire.TypeA}).nothing(t)

		// The fillers run out: there is room again.
		time.Sleep(101 * time.Second)
		other.answer(t, "en0", named("later", 4500))
		synctest.Wait()

		began := time.Now()
		if found := ask(
			t,
			asked,
			engine.Question{Name: []string{"later", "local"}, Type: wire.TypeA},
		).next(t, engine.Found); !found.at.Equal(
			began,
		) {
			t.Errorf("told %s later", found.at.Sub(began))
		}
	})
}

// What was heard before anyone asked about it is asked about again as
// it gets old from the moment someone does.
func TestWhatWasHeardBeforeItWasAskedAbout(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asked := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		said := time.Now()

		other.answer(t, "en0", named("early", 100))
		time.Sleep(10 * time.Second)

		ask(t, asked, engine.Question{Name: []string{"early", "local"}, Type: wire.TypeA}).next(t, engine.Found)

		// The questions that double come 73 and 137 seconds after it was
		// said: one between is for a record getting old.
		for {
			question := other.next()
			if question.at.Sub(said) < 75*time.Second {
				continue
			}

			if !between(question.at, said, 80*time.Second, 82*time.Second) {
				t.Errorf("asked about again %s after it was said", question.at.Sub(said))
			}

			break
		}
	})
}

// A goodbye does not give a record more time than it had (10.1); a
// record doubted twice has the ten seconds of the first (10.4); and
// one that is confirmed is asked about no more.
func TestTimesThatDoNotStartOver(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asked := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		asking := ask(t, asked, browse())

		said := time.Now()

		other.answer(t, "en0", pointer("Kitchen", 2), pointer("Garden", 4500), pointer("Cellar", 4500))

		for range 3 {
			asking.next(t, engine.Found)
		}

		time.Sleep(1500 * time.Millisecond)
		other.answer(t, "en0", pointer("Kitchen", 0))

		if lost := asking.next(t, engine.Lost); lost.at.Sub(said) != 2*time.Second {
			t.Errorf("lost %s after it was said for two seconds", lost.at.Sub(said))
		}

		// Past the questions that double, for a while.
		time.Sleep(70 * time.Second)

		doubted := time.Now()

		if err := asked.Reconfirm(pointer("Garden", 4500)); err != nil {
			t.Fatal(err)
		}

		time.Sleep(5 * time.Second)

		if err := asked.Reconfirm(pointer("Garden", 4500)); err != nil {
			t.Fatal(err)
		}

		if lost := asking.next(t, engine.Lost); lost.at.Sub(doubted) != 10*time.Second {
			t.Errorf("lost %s after it was first doubted", lost.at.Sub(doubted))
		}

		for len(other.heard) > 0 {
			<-other.heard
		}

		if err := asked.Reconfirm(pointer("Cellar", 4500)); err != nil {
			t.Fatal(err)
		}

		other.next()
		other.answer(t, "en0", pointer("Cellar", 4500))
		other.quiet(t, 20*time.Second)
		asking.nothing(t)
	})
}

// A record of another class than the Internet's is no record here; and
// a name is its labels, not their letters end to end.
func TestWhatIsNotAnAnswer(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(
			t,
			open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}),
			engine.Question{Name: []string{"ab", "c", "local"}, Type: wire.TypeA},
		)

		classless := wire.Record{
			Name:  []string{"ab", "c", "local"},
			Class: 3,
			TTL:   120,
			Data:  wire.Address{Addr: netip.MustParseAddr("192.0.2.77")},
		}
		split := wire.Record{
			Name:  []string{"a", "bc", "local"},
			Class: wire.ClassIN,
			TTL:   120,
			Data:  wire.Address{Addr: netip.MustParseAddr("192.0.2.77")},
		}

		other.answer(t, "en0", classless, split)
		asking.nothing(t)

		split.Name = []string{"AB", "C", "LOCAL"}
		other.answer(t, "en0", split)
		asking.next(t, engine.Found)
	})
}

// Section 11: an IPv6 link-local address is on the link, whatever
// prefixes the interface has.
func TestALinkLocalNeighbour(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(
			t,
			&network,
			mdnstest.Port{Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::2/64")}},
		)
		host := network.Host()
		asking := ask(t, open(t, engine.Config{Network: host}), browse())

		host.Plug(
			mdnstest.Port{Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/64")}},
		)

		if first := other.next(); !first.Questions[0].Unicast {
			t.Fatal("no answer of its own was asked for")
		}

		other.answerTo(t, netip.MustParseAddr("2001:db8::1"), pointer("Kitchen", 4500))
		asking.next(t, engine.Found)
	})
}

// say says a message of answers under a header of a test's making.
func (n *neighbour) say(t *testing.T, header wire.Header, questions []wire.Question, records ...wire.Record) {
	t.Helper()

	for _, message := range messages(t, header, questions, records...) {
		if err := n.link(t, "en0").Multicast(message); err != nil {
			t.Fatal(err)
		}
	}
}

// RFC 6762 sections 18.3 and 18.11: a message under an opcode or a
// response code that is not zero is ignored, an answer as a question.
func TestMessagesThatAreNotMulticastDNS(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		third := join(t, &network, port("en0", lan, 3))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		first := other.next()

		third.say(t, wire.Header{Response: true, Authoritative: true, RCode: 3}, nil, pointer("Refused", 4500))
		third.say(t, wire.Header{Response: true, Authoritative: true, Opcode: 1}, nil, pointer("Status", 4500))
		asking.nothing(t)

		// The same question under a response code is no one asking it.
		time.Sleep(500 * time.Millisecond)
		third.say(
			t,
			wire.Header{RCode: 3},
			[]wire.Question{{Name: typeName(), Type: wire.TypePTR, Class: wire.ClassIN}},
		)

		for range 3 {
			other.next()
		}

		if again := other.next(); again.at.Sub(first.at) != time.Second {
			t.Errorf("asked again %s after the first", again.at.Sub(first.at))
		}
	})
}

// A question that had its answer and has it no more is asked again, at
// once: its one holder went quiet.
func TestAnAnswerThatGoes(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(
			t,
			open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}),
			engine.Question{Name: hostName(), Type: wire.TypeA},
		)

		other.next()

		record := address(1, true)
		record.TTL = 10

		said := time.Now()

		other.answer(t, "en0", record)
		asking.next(t, engine.Found)

		if lost := asking.next(t, engine.Lost); lost.at.Sub(said) != 10*time.Second {
			t.Fatalf("lost after %s", lost.at.Sub(said))
		}

		// What was asked as it got old, and then the question anew.
		again := other.next()
		for again.at.Sub(said) < 10*time.Second {
			again = other.next()
		}

		if !between(again.at, said, 10020*time.Millisecond, 10120*time.Millisecond) || len(again.Answers) != 0 {
			t.Errorf("asked again %s after the answer was said, knowing %+v", again.at.Sub(said), again.Answers)
		}
	})
}

// A question no one asks any more is forgotten whole: asked anew, it is
// told of what is heard.
func TestAQuestionAskedAnew(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asked := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		first := ask(t, asked, browse())
		first.stop()

		if err := <-first.ended; !errors.Is(err, context.Canceled) {
			t.Fatalf("the first Ask ended with %v", err)
		}

		first.ended <- nil

		second := ask(t, asked, browse())

		other.answer(t, "en0", pointer("Kitchen", 4500))
		second.next(t, engine.Found)
	})
}

// A link whose addresses change is on the prefixes it now has: an
// answer to it alone is taken from a neighbour there.
func TestALinkThatChangesItsAddresses(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		elsewhere := mdnstest.Port{
			Interface: "en0",
			Wire:      lan,
			Addrs:     []netip.Prefix{netip.MustParsePrefix("198.51.100.2/24")},
		}
		other := join(t, &network, elsewhere)
		host := network.Host()
		asking := ask(t, open(t, engine.Config{Network: host}), browse())

		host.Plug(port("en0", lan, 1))

		if first := other.next(); !first.Questions[0].Unicast {
			t.Fatal("no answer of its own was asked for")
		}

		elsewhere.Addrs = []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24")}
		host.Plug(elsewhere)
		synctest.Wait()

		other.answerTo(t, netip.MustParseAddr("198.51.100.1"), pointer("Kitchen", 4500))
		asking.next(t, engine.Found)
	})
}

// What is asked about is a neighbour's to fill too: past 16384 records
// on a link, nothing more is kept.
func TestWhatIsAskedAboutIsKeptOnlySoFar(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		const most = 16384

		found := make(chan int, 128)

		done := make(chan struct{})
		defer close(done)

		go func() {
			for count := 1; ; count++ {
				select {
				case <-asking.told:
				case <-done:
					return
				}

				if count >= most {
					found <- count
				}
			}
		}()

		for batch := range (most + 64) / 64 {
			records := make([]wire.Record, 0, 64)
			for index := range 64 {
				records = append(records, pointer(fmt.Sprintf("i%d", batch*64+index), 4500))
			}

			other.answer(t, "en0", records...)
		}

		<-found
		synctest.Wait()

		select {
		case count := <-found:
			t.Errorf("told of %d records", count)
		default:
		}
	})
}

// A text record that was acted on and was wrong is its name's one,
// whatever a program read of it.
func TestATextRecordInDoubt(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		name := []string{"Kitchen", "_http", "_tcp", "local"}
		text := func(strings ...string) wire.Record {
			return wire.Record{
				Name:  name,
				Class: wire.ClassIN,
				TTL:   4500,
				Flush: true,
				Data:  wire.Text{Strings: strings},
			}
		}

		other := join(t, &network, port("en0", lan, 2))
		asked := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		asking := ask(t, asked, engine.Question{Name: name, Type: wire.TypeTXT})

		other.answer(t, "en0", text("path=/", "=no key", "path=again"))
		asking.next(t, engine.Found)

		doubted := time.Now()

		if err := asked.Reconfirm(text("path=/")); err != nil {
			t.Fatal(err)
		}

		if lost := asking.next(t, engine.Lost); lost.at.Sub(doubted) != 10*time.Second {
			t.Errorf("lost %s after it was doubted", lost.at.Sub(doubted))
		}
	})
}
