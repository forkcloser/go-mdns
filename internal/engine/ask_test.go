package engine_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

func browse() engine.Question { return engine.Question{Name: typeName(), Type: wire.TypePTR} }

// RFC 6762 section 5.2: a first question after 20 to 120 ms, the next a
// second later, and each after twice as long, up to an hour.
func TestAQuestionIsAskedAgainAndAgain(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		start := time.Now()

		ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		first := other.next()
		want := []wire.Question{{Name: typeName(), Type: wire.TypePTR, Class: wire.ClassIN}}

		if !between(first.at, start, 20*time.Millisecond, 120*time.Millisecond) || first.Header != (wire.Header{}) ||
			!reflect.DeepEqual(first.Questions, want) || first.Answers != nil {
			t.Fatalf("first asked %s in: %+v", first.at.Sub(start), first.Message)
		}

		last := first.at

		for _, seconds := range []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 3600, 3600} {
			gap := time.Duration(seconds) * time.Second

			again := other.next()
			if again.at.Sub(last) != gap || !reflect.DeepEqual(again.Questions, want) {
				t.Fatalf("asked again after %s, want %s: %+v", again.at.Sub(last), gap, again.Message)
			}

			last = again.at
		}
	})
}

// A record is told of when it is heard, said to be known in the
// questions that follow for as long as it has over half its life left
// (section 7.1), asked about again at 80, 85, 90 and 95% of it, each
// up to 2% late, and lost when it runs out (section 5.2).
func TestARecordIsKeptForAsLongAsItSaid(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		other.next()

		record := pointer("Kitchen", 100)
		said := time.Now()

		other.answer(t, "en0", record)

		if found := asking.next(
			t,
			engine.Found,
		); !reflect.DeepEqual(found.answer.Record, record) || names(found.answer.Interfaces) != "en0 " ||
			!found.at.Equal(said) {
			t.Fatalf("found %+v at %s", found.answer, found.at.Sub(said))
		}

		// Said again, it is the same record still.
		other.answer(t, "en0", record)
		asking.nothing(t)

		said = time.Now()
		lost := make(chan told, 1)

		go func() { lost <- asking.next(t, engine.Lost) }()

		var late []time.Duration

		for {
			select {
			case gone := <-lost:
				if gone.at.Sub(said) != 100*time.Second || !reflect.DeepEqual(gone.answer.Record, record) {
					t.Errorf("lost %+v after %s", gone.answer, gone.at.Sub(said))
				}

				if len(late) != 4 {
					t.Fatalf("asked again %d times as it ran out: %v", len(late), late)
				}

				for index, after := range late {
					least := time.Duration(80+5*index) * time.Second
					if after < least || after > least+2*time.Second {
						t.Errorf("asked again after %s, want %s to %s", after, least, least+2*time.Second)
					}
				}

				return
			case question := <-other.heard:
				after := question.at.Sub(said)

				// What is known is said for the first half of its life.
				switch known := len(question.Answers) == 1; {
				case after < 50*time.Second && (!known || question.Answers[0].TTL != uint32(100-after/time.Second)):
					t.Errorf("asked after %s without what is known: %+v", after, question.Answers)
				case after > 50*time.Second && known:
					t.Errorf("asked after %s with what is known", after)
				}

				// The questions that double stop at 64 seconds: after
				// that there are only those for a record getting old.
				if after > 70*time.Second {
					late = append(late, after)
				}
			}
		}
	})
}

// A record said again for less long is asked about again as that life
// runs out, at 80, 85, 90 and 95% of it, each up to 2% of it late, and
// not as late as 2% of the longer life it was first said with would be.
func TestARecordSaidAgainForLessLongIsAskedAboutInThatLife(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		other.next()
		other.answer(t, "en0", pointer("Kitchen", 604800))
		asking.next(t, engine.Found)

		// Between two of the questions that double, 127 and 255 seconds
		// in: what is asked in the 100 seconds that follow is for the
		// record getting old.
		time.Sleep(130 * time.Second)
		other.drain()

		said := time.Now()

		other.answer(t, "en0", pointer("Kitchen", 100))

		lost := make(chan told, 1)

		go func() { lost <- asking.next(t, engine.Lost) }()

		var late []time.Duration

		for {
			select {
			case gone := <-lost:
				if gone.at.Sub(said) != 100*time.Second {
					t.Errorf("lost after %s, want the 100 seconds it was last said for", gone.at.Sub(said))
				}

				if len(late) != 4 {
					t.Fatalf("asked again %d times as it ran out: %v, want 4", len(late), late)
				}

				for index, after := range late {
					least := time.Duration(80+5*index) * time.Second
					if after < least || after > least+2*time.Second {
						t.Errorf("asked again after %s, want %s to %s", after, least, least+2*time.Second)
					}
				}

				return
			case question := <-other.heard:
				late = append(late, question.at.Sub(said))
			}
		}
	})
}

// Section 10.1: a record said goodbye to is kept a second, and gone.
func TestAGoodbye(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		other.answer(t, "en0", pointer("Kitchen", 4500), pointer("Garden", 4500))
		asking.next(t, engine.Found)
		asking.next(t, engine.Found)

		// A goodbye for what was never heard of is nothing.
		said := time.Now()

		other.answer(t, "en0", pointer("Kitchen", 0), pointer("Cellar", 0))

		if lost := asking.next(
			t,
			engine.Lost,
		); lost.at.Sub(said) != time.Second ||
			!reflect.DeepEqual(lost.answer.Record, pointer("Kitchen", 4500)) {
			t.Errorf("lost %+v after %s", lost.answer.Record, lost.at.Sub(said))
		}

		asking.nothing(t)
	})
}

// Section 10.2: a record that is its holder's alone takes the place of
// what was heard of its name and type more than a second before, which
// goes a second later. And section 5.2: with such an answer the
// question is asked no more, but to keep the answer.
func TestARecordThatIsItsHoldersAlone(t *testing.T) {
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
		other.answer(t, "en0", address(50, false))
		asking.next(t, engine.Found)

		time.Sleep(1500 * time.Millisecond)

		// Two addresses said together are both the holder's: the second
		// does not take the place of the first.
		said := time.Now()

		other.answer(t, "en0", address(51, true), address(52, true))

		for _, last := range []byte{51, 52} {
			if found := asking.next(
				t,
				engine.Found,
			); !found.at.Equal(said) ||
				!reflect.DeepEqual(found.answer.Record, address(last, true)) {
				t.Errorf("found %+v after %s", found.answer.Record, found.at.Sub(said))
			}
		}

		if lost := asking.next(
			t,
			engine.Lost,
		); lost.at.Sub(said) != time.Second ||
			!reflect.DeepEqual(lost.answer.Record, address(50, false)) {
			t.Errorf("lost %+v after %s", lost.answer.Record, lost.at.Sub(said))
		}

		asking.nothing(t)

		// No question until the answer is 80% through its life.
		for len(other.heard) > 0 {
			<-other.heard
		}

		if again := other.next(); !between(again.at, said, 96*time.Second, 98400*time.Millisecond) {
			t.Errorf("asked again after %s", again.at.Sub(said))
		}
	})
}

// Section 6.1: a name whose holder says it has no record of a type is
// asked no more for one.
func TestANameThatHasNoRecordOfAType(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(
			t,
			open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}),
			engine.Question{Name: hostName(), Type: wire.TypeAAAA},
		)

		other.next()
		other.answer(t, "en0", wire.Record{
			Name: hostName(), Class: wire.ClassIN, TTL: 120, Flush: true,
			Data: wire.NSEC{Next: hostName(), Types: []uint16{wire.TypeA}},
		})

		asking.nothing(t)
		other.quiet(t, 90*time.Second)
	})
}

// Section 7.2: what is known that does not fit one message follows in
// others, each but the last marked as cut short, the question in the
// first alone.
func TestWhatIsKnownAndDoesNotFit(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		other.next()

		var records []wire.Record
		for index := range 60 {
			records = append(
				records,
				pointer(fmt.Sprintf("An instance with a name as long as a name can well be, %02d", index), 4500),
			)
		}

		other.answer(t, "en0", records...)

		for range records {
			asking.next(t, engine.Found)
		}

		first := other.next()
		if len(first.Questions) != 1 || !first.Header.Truncated {
			t.Fatalf("asked with %d questions, cut short %t", len(first.Questions), first.Header.Truncated)
		}

		known, cut := len(first.Answers), true

		for cut {
			more := other.next()
			if !more.at.Equal(first.at) || len(more.Questions) != 0 || len(more.Answers) == 0 {
				t.Fatalf(
					"followed %s later by %d questions and %d records",
					more.at.Sub(first.at),
					len(more.Questions),
					len(more.Answers),
				)
			}

			known, cut = known+len(more.Answers), more.Header.Truncated
		}

		if known != len(records) {
			t.Errorf("said to know %d records of %d", known, len(records))
		}
	})
}

// Section 7.3: a question another host has just asked, saying to know
// nothing more, is not asked again.
func TestAQuestionAnotherHostJustAsked(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		third := join(t, &network, port("en0", lan, 3))

		ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())

		other.next()
		time.Sleep(500 * time.Millisecond)

		question := wire.Question{Name: []string{"_HTTP", "_tcp", "local"}, Type: wire.TypePTR, Class: wire.ClassIN}
		third.ask(t, question)

		theirs := other.next()

		// Ours was due half a second later, and is taken as asked: the
		// next comes two seconds after theirs, as it would after ours.
		if again := other.next(); again.at.Sub(theirs.at) != 2*time.Second {
			t.Errorf("asked again %s after another host did", again.at.Sub(theirs.at))
		}

		// One that says to know what we do not is no reason to keep quiet.
		time.Sleep(time.Second)
		third.ask(t, question, pointer("Kitchen", 4500))

		theirs = other.next()

		if again := other.next(); again.at.Sub(theirs.at) != 3*time.Second {
			t.Errorf("asked again %s after another host asked knowing more", again.at.Sub(theirs.at))
		}
	})
}

// A record heard on two interfaces is one answer, which says both; it
// changes when one of them goes, and is lost with the last.
func TestOneAnswerOnSeveralInterfaces(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("eth0", lan, 2), port("eth1", wifi, 12))
		host := network.Host(port("en0", lan, 1), port("en1", wifi, 11))
		asking := ask(t, open(t, engine.Config{Network: host}), browse())

		// Asked on both.
		if one, two := other.next(), other.next(); one.on == two.on {
			t.Fatalf("asked twice on %s", one.on)
		}

		record := pointer("Kitchen", 4500)

		other.answer(t, "eth1", record)

		if found := asking.next(t, engine.Found); names(found.answer.Interfaces) != "en1 " {
			t.Errorf("found on %s", names(found.answer.Interfaces))
		}

		other.answer(t, "eth0", record)

		if changed := asking.next(t, engine.Changed); names(changed.answer.Interfaces) != "en0 en1 " {
			t.Errorf("changed to %s", names(changed.answer.Interfaces))
		}

		other.answer(t, "eth1", pointer("Kitchen", 0))

		if changed := asking.next(t, engine.Changed); names(changed.answer.Interfaces) != "en0 " {
			t.Errorf("changed to %s", names(changed.answer.Interfaces))
		}

		// Section 10.3: what was heard on a link goes with it.
		host.Unplug("en0")

		if lost := asking.next(
			t,
			engine.Lost,
		); names(lost.answer.Interfaces) != "en0 " ||
			!reflect.DeepEqual(lost.answer.Record, record) {
			t.Errorf("lost %+v", lost.answer)
		}

		asking.nothing(t)
	})
}

// What one learns the others have: a second Ask is told at once of what
// is known, and the question is asked once for both.
func TestTwoAskTheSame(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asked := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		first := ask(t, asked, browse())

		other.next()
		other.answer(t, "en0", pointer("Kitchen", 4500))
		first.next(t, engine.Found)

		began := time.Now()
		second := ask(t, asked, engine.Question{Name: []string{"_http", "_TCP", "local"}, Type: wire.TypePTR})

		if found := second.next(t, engine.Found); !found.at.Equal(began) {
			t.Errorf("the second was told %s later", found.at.Sub(began))
		}

		// The first leaves: the question goes on for the second. Then the
		// second: it stops.
		first.stop()

		if again := other.next(); again.at.Sub(began) != time.Second {
			t.Errorf("asked again after %s", again.at.Sub(began))
		}

		second.stop()
		other.quiet(t, 2*time.Hour)
	})
}

// Section 5.4: what is being asked when a link comes up is asked there
// for an answer of its own, once; and section 11: such an answer is
// taken from the link, for two seconds, and from nowhere else.
func TestAnAnswerToThisHostAlone(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		far := join(t, &network, mdnstest.Port{Interface: "en0", Wire: lan, Addrs: port("", "", 0).Addrs[:0:0]})
		host := network.Host()
		asking := ask(t, open(t, engine.Config{Network: host}), browse())

		synctest.Wait()
		host.Plug(port("en0", lan, 1))

		if first := other.next(); !first.Questions[0].Unicast {
			t.Fatal("the first question on a link that came up asks for no answer of its own")
		}

		dest := port("", "", 1).Addrs[0].Addr()

		// From a host with no address on the link's prefix: not taken.
		far.answerTo(t, dest, pointer("Far", 4500))
		asking.nothing(t)

		other.answerTo(t, dest, pointer("Kitchen", 4500))
		asking.next(t, engine.Found)

		if again := other.next(); again.Questions[0].Unicast {
			t.Error("the second question asks for an answer of its own")
		}

		// Two seconds after it was asked for, no more.
		time.Sleep(1200 * time.Millisecond)
		other.answerTo(t, dest, pointer("Garden", 4500))
		asking.nothing(t)
	})
}

// Section 10.5: a record that two questions of other hosts should have
// brought, and that no one says in ten seconds, is forgotten.
func TestARecordNoOneAnswersWith(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asking := ask(t, open(t, engine.Config{Network: network.Host(port("en0", lan, 1))}), browse())
		question := wire.Question{Name: typeName(), Type: wire.TypePTR, Class: wire.ClassIN}

		other.answer(t, "en0", pointer("Kitchen", 4500), pointer("Garden", 4500), pointer("Cellar", 4500))

		for range 3 {
			asking.next(t, engine.Found)
		}

		// The asker says it knows of the cellar: that one is not expected.
		first := time.Now()

		other.ask(t, question, pointer("Cellar", 4500))
		time.Sleep(3 * time.Second)
		other.ask(t, question, pointer("Cellar", 4500))

		// The garden is said again: it stays.
		time.Sleep(time.Second)
		other.answer(t, "en0", pointer("Garden", 4500))

		if lost := asking.next(
			t,
			engine.Lost,
		); lost.at.Sub(first) != 10*time.Second ||
			!reflect.DeepEqual(lost.answer.Record, pointer("Kitchen", 4500)) {
			t.Errorf("lost %+v after %s", lost.answer.Record, lost.at.Sub(first))
		}

		asking.nothing(t)
	})
}

// Section 10.4: a record that was acted on and was wrong is asked about
// again, without saying it is known, and forgotten when no one
// confirms it in ten seconds.
func TestARecordInDoubt(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		asked := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		asking := ask(t, asked, browse())

		other.answer(t, "en0", pointer("Kitchen", 4500), pointer("Garden", 4500))
		asking.next(t, engine.Found)
		asking.next(t, engine.Found)

		// Past the questions that double, for a while.
		time.Sleep(70 * time.Second)

		for len(other.heard) > 0 {
			<-other.heard
		}

		doubted := time.Now()

		// One that was never heard of is no one's to doubt.
		for _, record := range []wire.Record{pointer("Kitchen", 4500), pointer("Unknown", 4500)} {
			if err := asked.Reconfirm(record); err != nil {
				t.Fatal(err)
			}
		}

		// Asked three times, saying to know the garden and not the
		// kitchen: whoever has the kitchen is to say so.
		for _, after := range []time.Duration{0, time.Second, 3 * time.Second} {
			question := other.next()
			if question.at.Sub(doubted) != after || len(question.Questions) != 1 || len(question.Answers) != 1 ||
				!reflect.DeepEqual(question.Answers[0].Data, pointer("Garden", 0).Data) {
				t.Fatalf(
					"asked after %s, %d questions, knowing %+v",
					question.at.Sub(doubted),
					len(question.Questions),
					question.Answers,
				)
			}
		}

		if lost := asking.next(
			t,
			engine.Lost,
		); lost.at.Sub(doubted) != 10*time.Second ||
			!reflect.DeepEqual(lost.answer.Record, pointer("Kitchen", 4500)) {
			t.Errorf("lost %+v after %s", lost.answer.Record, lost.at.Sub(doubted))
		}

		// The garden is doubted, and confirmed: it stays.
		if err := asked.Reconfirm(pointer("Garden", 4500)); err != nil {
			t.Fatal(err)
		}

		other.next()
		other.answer(t, "en0", pointer("Garden", 4500))
		time.Sleep(11 * time.Second)
		asking.nothing(t)
	})
}

// Where to be, and where to ask, are each a choice.
func TestTheInterfacesAndFamiliesChosen(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		both := mdnstest.Port{Interface: "en2", Wire: "both"}
		other := join(t, &network, port("eth0", lan, 2), port("eth1", wifi, 12), both, both)
		host := network.Host(port("en0", lan, 1), port("en1", wifi, 11), both)

		only := func(name string) func(transport.Interface) bool {
			return func(candidate transport.Interface) bool { return candidate.Name == name }
		}

		// An Engine on en1 and en2, for IPv6 alone; a question for en2.
		asked := open(t, engine.Config{
			Network:    host,
			Families:   transport.IPv6,
			Interfaces: func(candidate transport.Interface) bool { return candidate.Name != "en0" },
		})

		ask(t, asked, engine.Question{Name: typeName(), Type: wire.TypePTR, Interfaces: only("en2")})

		if first := other.next(); first.on != "en2" {
			t.Errorf("asked on %s", first.on)
		}

		// Once: on one family of the three links it could have been on.
		other.quiet(t, 900*time.Millisecond)
	})
}

func TestAnAskEnds(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		asked := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
		nothing := func(engine.Change, engine.Answer) {}

		for _, name := range [][]string{nil, {""}, {"a", "", "local"}, {string(make([]byte, 64))}} {
			if err := asked.Ask(
				t.Context(),
				engine.Question{Name: name, Type: wire.TypeA},
				nothing,
			); !errors.Is(
				err,
				engine.ErrInvalid,
			) {
				t.Errorf("asking for %q: %v", name, err)
			}
		}

		stopped := ask(t, asked, browse())

		synctest.Wait()
		stopped.stop()

		if err := <-stopped.ended; !errors.Is(err, context.Canceled) {
			t.Errorf("an Ask whose context ended: %v", err)
		}

		stopped.ended <- nil

		closed := ask(t, asked, browse())

		synctest.Wait()

		if err := asked.Close(); err != nil {
			t.Fatal(err)
		}

		if err := <-closed.ended; !errors.Is(err, engine.ErrClosed) {
			t.Errorf("an Ask on an Engine that was closed: %v", err)
		}

		closed.ended <- nil

		if err := asked.Ask(t.Context(), browse(), nothing); !errors.Is(err, engine.ErrClosed) {
			t.Errorf("asking of an Engine that is closed: %v", err)
		}

		if err := asked.Reconfirm(pointer("Kitchen", 1)); !errors.Is(err, engine.ErrClosed) {
			t.Errorf("doubting on an Engine that is closed: %v", err)
		}

		if _, err := engine.Open(t.Context(), engine.Config{}); !errors.Is(err, engine.ErrInvalid) {
			t.Errorf("opening on no network: %v", err)
		}
	})
}
