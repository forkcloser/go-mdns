package engine_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// Two records of a name with the same data and different types are two
// records, whatever the types: an asker for every type is told of both.
// Types from 0xD800 to 0xDFFF were told as one, the type having been
// made part of what tells answers apart as a character, and those
// being no characters.
func TestRecordsOfTwoTypesAreTwoAnswers(t *testing.T) {
	t.Parallel()

	for _, kinds := range [][2]uint16{{0xC800, 0xC801}, {0xD800, 0xD801}, {0xDFFF, 0xE000}, {0x00FF, 0xFF00}} {
		synctest.Test(t, func(t *testing.T) {
			var network mdnstest.Network

			other := join(t, &network, port("en0", lan, 2))
			host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})
			asking := ask(t, host, engine.Question{Name: hostName(), Type: wire.TypeANY})

			for _, kind := range kinds {
				other.answer(t, "en0", wire.Record{
					Name:  hostName(),
					Class: wire.ClassIN,
					TTL:   120,
					Data:  wire.Opaque{Kind: kind, Bytes: []byte{1, 2, 3}},
				})
			}

			time.Sleep(time.Second)
			synctest.Wait()

			if found := len(asking.told); found != 2 {
				t.Errorf(
					"records of the types %#x and %#x with the same data: told of %d, want 2",
					kinds[0],
					kinds[1],
					found,
				)
			}
		})
	}
}

// A question added to a Group may have answers already, heard for
// another asker: Add says the next Poll tells them, and Wait that it
// waits until a Poll may have something to tell. Wait waited for the
// next thing heard instead, which for a record good for an hour and a
// quarter is a long time.
func TestAGroupIsWokenForWhatAQuestionAlreadyHas(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, port("en0", lan, 2))
		host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

		// Heard for one who asks, and kept.
		first := ask(t, host, engine.Question{Name: typeName(), Type: wire.TypePTR})
		other.answer(t, "en0", pointer("Kitchen", 4500))
		first.next(t, engine.Found)

		group := host.Group()
		defer group.Close()

		if _, err := group.Add(engine.Question{Name: typeName(), Type: wire.TypePTR}); err != nil {
			t.Fatal(err)
		}

		soon, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()

		began := time.Now()

		if err := group.Wait(soon); err != nil || time.Since(began) != 0 {
			t.Fatalf("Wait after a question that has an answer already: %v, %s later", err, time.Since(began))
		}

		if told, err := group.Poll(); err != nil || len(told) != 1 || told[0].Change != engine.Found {
			t.Errorf("Poll after it: %+v, %v", told, err)
		}
	})
}
