package engine_test

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// sized is the data of a text record of so many bytes.
func sized(size int) wire.Text {
	var text wire.Text

	for size > 0 {
		length := min(size-1, 255)
		text.Strings = append(text.Strings, strings.Repeat("t", length))
		size -= length + 1
	}

	return text
}

// most is the most bytes a message is on an IPv6 link, where it is the
// least: 9000 with its headers, which there are 48 bytes (RFC 6762
// section 17).
const most = 8952

// RFC 6762 section 17: a message is 9000 bytes at most, its IP and UDP
// headers included. A record that fits none cannot be said, and a set
// that has one is refused, where it was published and never said. Up to
// that, a record is said, alone in a message when it has to be.
func TestARecordThatFitsNoMessageIsRefused(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, mdnstest.Port{
			Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::2/64")},
		})
		host := open(t, engine.Config{Network: network.Host(mdnstest.Port{
			Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::1/64")},
		})})

		// Twelve bytes of header, eighteen of the type's name and ten of
		// what a record always has leave 8912.
		shared := func(size int) engine.Set {
			return engine.Set{
				Records: []wire.Record{{Name: typeName(), Class: wire.ClassIN, TTL: 120, Data: sized(size)}},
			}
		}

		if _, err := host.Publish(t.Context(), shared(8913)); !errors.Is(err, engine.ErrInvalid) {
			t.Errorf("a record one byte more than a message holds: %v", err)
		}

		published, err := host.Publish(t.Context(), shared(8912))
		if err != nil {
			t.Fatalf("a record that fills a message: %v", err)
		}

		time.Sleep(4 * time.Second)
		synctest.Wait()

		said := 0

		for len(other.heard) > 0 {
			message := <-other.heard
			if len(message.Answers) != 1 || message.size != most {
				continue
			}

			if text, is := message.Answers[0].Data.(wire.Text); is && slices.Equal(text.Strings, sized(8912).Strings) {
				said++
			}
		}

		if said != 3 {
			t.Errorf("a record that fills a message was said whole %d times, want 3", said)
		}

		// Changed to one that fits none: refused, and what it was stays.
		if err = published.Update(shared(8913).Records); !errors.Is(err, engine.ErrInvalid) {
			t.Errorf("changed to a record one byte more than a message holds: %v", err)
		}

		other.ask(t, query(typeName(), wire.TypeTXT))
		time.Sleep(time.Second)
		synctest.Wait()

		if len(other.heard) != 1 || (<-other.heard).size != most {
			t.Error("after a change that was refused, the record is not answered with as it was")
		}

		// A set is said in as many messages as it takes: it is not held
		// to what one holds.
		var many []wire.Record

		for index := range 80 {
			many = append(many, wire.Record{
				Name: []string{fmt.Sprintf("n%d", index), "local"}, Class: wire.ClassIN, TTL: 120, Data: sized(900),
			})
		}

		if _, err = host.Publish(t.Context(), engine.Set{Records: many}); err != nil {
			t.Fatalf("eighty records of 900 bytes: %v", err)
		}

		time.Sleep(500 * time.Millisecond)
		synctest.Wait()

		names := map[string]bool{}

		for len(other.heard) > 0 {
			for _, answer := range (<-other.heard).Answers {
				names[answer.Name[0]] = true
			}
		}

		if len(names) != len(many) {
			t.Errorf("of eighty records of 900 bytes, %d were said", len(names))
		}
	})
}

// RFC 6762 section 8.1 and 8.2: a name is asked for in one message, with
// the records meant for it, which another host asking at the same
// moment compares with its own. Records that each fit a message, and
// not that one together, are refused, where the question was never sent
// and the name taken without having been asked for.
func TestNamesThatCannotBeAskedForAreRefused(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := join(t, &network, mdnstest.Port{
			Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::2/64")},
		})
		host := open(t, engine.Config{Network: network.Host(mdnstest.Port{
			Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::1/64")},
		})})

		// The header is twelve bytes; the question is the name, 26, and
		// four; the SRV its name as a pointer, two, ten, six and its
		// host with "local" as a pointer, ten; the TXT two and ten, and
		// its data: 8870 bytes of it fill the message.
		with := func(size int) engine.Set {
			records := service()
			records[2].Data = sized(size)

			return engine.Set{Records: records}
		}

		if _, err := host.Publish(t.Context(), with(8871)); !errors.Is(err, engine.ErrInvalid) {
			t.Errorf("records one byte more than the question for their name holds: %v", err)
		}

		if result := <-publish(t, host, with(8870)); result.err != nil {
			t.Fatalf("records that fill the question for their name: %v", result.err)
		}

		synctest.Wait()

		asked := 0

		for len(other.heard) > 0 {
			message := <-other.heard
			if !message.Header.Response && len(message.Questions) == 1 && len(message.Authorities) == 2 &&
				message.size == most {
				asked++
			}
		}

		if asked != 3 {
			t.Errorf("the name was asked for, with its records, %d times before it was taken, want 3", asked)
		}
	})
}

// A host with more addresses than the question for its name holds still
// asks for the name, with those that fit.
func TestAHostWithMoreAddressesThanItsQuestionHolds(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		// Sixteen bytes an address in the question, with its name as a
		// pointer: 600 are more than 9000.
		addrs := make([]netip.Prefix, 600)
		for index := range addrs {
			addrs[index] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 1, byte(index / 250), byte(1 + index%250)}), 16)
		}

		other := join(t, &network, mdnstest.Port{
			Interface: "en0", Wire: lan, Addrs: []netip.Prefix{netip.MustParsePrefix("10.1.255.1/16")},
		})
		host := open(t, engine.Config{Network: network.Host(mdnstest.Port{Interface: "en0", Wire: lan, Addrs: addrs})})

		if result := <-publish(t, host, engine.Set{Host: hostName()}); result.err != nil {
			t.Fatal(result.err)
		}

		synctest.Wait()

		asked, said := 0, map[netip.Addr]bool{}

		for len(other.heard) > 0 {
			message := <-other.heard

			if !message.Header.Response && len(message.Questions) == 1 && len(message.Authorities) > 500 {
				asked++
			}

			for _, answer := range message.Answers {
				if address, is := answer.Data.(wire.Address); is {
					said[address.Addr] = true
				}
			}
		}

		if asked != 3 || len(said) != len(addrs) {
			t.Errorf(
				"the name was asked for %d times, want 3, and %d addresses of %d said",
				asked,
				len(said),
				len(addrs),
			)
		}
	})
}

// A set may hold several names, more than one message asks for: they
// are asked for in as many as it takes, each name in one with its own
// records, and none of those messages is more than the link sends
// whole. Twelve names with a text of 760 bytes each were asked for in
// one message of over 9000 bytes, which the link refused: they were
// taken without having been asked for. A name whose own records are
// more than the link sends whole is asked for alone, in a message sent
// in pieces.
func TestNamesAreAskedForInAsManyMessagesAsItTakes(t *testing.T) {
	t.Parallel()

	// The size of each name's text, the first one's when it is another,
	// and in how many messages the names are asked for, three times.
	for _, row := range []struct{ size, first, messages int }{
		// Four texts of 300 bytes to a message.
		{size: 300, first: 300, messages: 9},
		{size: 760, first: 760, messages: 36},
		// And one alone, the eleven others four to a message.
		{size: 300, first: 8500, messages: 12},
	} {
		size := row.size

		t.Run(fmt.Sprint(row.size, row.first), func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var network mdnstest.Network

				other := join(t, &network, port("en0", lan, 2))
				host := open(t, engine.Config{Network: network.Host(port("en0", lan, 1))})

				var records []wire.Record

				for index := range 12 {
					records = append(records, wire.Record{
						Name: []string{fmt.Sprintf("n%d", index), "local"}, Class: wire.ClassIN, TTL: 120, Flush: true,
						Data: sized(size),
					})
				}

				records[0].Data = sized(row.first)

				if result := <-publish(t, host, engine.Set{Records: records}); result.err != nil {
					t.Fatal(result.err)
				}

				synctest.Wait()

				// An IPv4 link of the usual size sends 1472 bytes whole.
				asked, messages := map[string]int{}, 0

				for len(other.heard) > 0 {
					message := <-other.heard
					if message.Header.Response {
						continue
					}

					messages++

					if message.size > 1472 && len(message.Questions) > 1 {
						t.Errorf(
							"%d names asked for in %d bytes, more than the link sends whole",
							len(message.Questions),
							message.size,
						)
					}

					// Each name with the record meant for it.
					for _, question := range message.Questions {
						if slices.ContainsFunc(message.Authorities, func(record wire.Record) bool {
							return slices.Equal(record.Name, question.Name)
						}) {
							asked[question.Name[0]]++
						}
					}
				}

				for _, record := range records {
					if asked[record.Name[0]] != 3 {
						t.Errorf(
							"%q was asked for, with its record, %d times, want 3",
							record.Name[0],
							asked[record.Name[0]],
						)
					}
				}

				if messages != row.messages {
					t.Errorf("asked in %d messages, want %d", messages, row.messages)
				}
			})
		})
	}
}
