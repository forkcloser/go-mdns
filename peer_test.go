package mdns_test

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

// speaker is a host that says what a test has it say, to everyone on
// its wire.
func speaker(t *testing.T, network *mdnstest.Network) transport.Link {
	t.Helper()

	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	up := make(chan transport.Link, 1)
	ended := make(chan struct{})

	go func() {
		defer close(ended)

		_ = network.Host(mdnstest.Port{
			Interface: "eth0", Wire: "lan",
			Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
		}).Watch(ctx, func(event transport.Event) { up <- event.Link })
	}()

	t.Cleanup(func() {
		stop()
		<-ended
	})

	return <-up
}

// say says records as an answer.
func say(t *testing.T, link transport.Link, records ...wire.Record) {
	t.Helper()

	message := wire.NewBuilder(nil, wire.Header{Response: true, Authoritative: true}, wire.Options{})

	for _, record := range records {
		if err := message.Answer(record); err != nil {
			t.Fatal(err)
		}
	}

	if err := link.Multicast(message.Bytes()); err != nil {
		t.Fatal(err)
	}
}

// A Peer asks, and tells of what is answered in this package's words:
// every kind of data, a text record read as RFC 6763 has one read.
func TestAPeerAsks(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		other := speaker(t, &network)

		peer, err := mdns.Open(t.Context(), mdns.Config{Network: network.Host(mdnstest.Port{
			Interface: "en0", Wire: "lan",
			Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")},
		})})
		if err != nil {
			t.Fatal(err)
		}

		synctest.Wait()

		name := mdns.Name{"Kitchen display", "_http", "_tcp", "local"}
		host := mdns.Name{"kitchen", "local"}
		en0 := []mdns.Interface{{Index: 1, Name: "en0"}}

		type told struct {
			change mdns.Change
			answer mdns.Answer
		}

		heard := make(chan told, 16)
		ended := make(chan error, 1)

		go func() {
			ended <- peer.Ask(t.Context(), mdns.Question{Name: name, Type: mdns.TypeANY}, func(change mdns.Change, answer mdns.Answer) {
				heard <- told{change: change, answer: answer}
			})
		}()

		synctest.Wait()

		say(
			t,
			other,
			wire.Record{
				Name:  name,
				Class: wire.ClassIN,
				TTL:   4500,
				Data:  wire.Text{Strings: []string{"path=/", "secure", "=lost", "", "empty=", "PATH=second"}},
			},
			wire.Record{Name: name, Class: wire.ClassIN, TTL: 120, Data: wire.Service{Port: 8080, Target: host}},
			wire.Record{
				Name:  name,
				Class: wire.ClassIN,
				TTL:   120,
				Data:  wire.NSEC{Next: name, Types: []uint16{16, 33}},
			},
			wire.Record{
				Name:  name,
				Class: wire.ClassIN,
				TTL:   60,
				Data:  wire.Pointer{Kind: wire.TypeCNAME, Target: host},
			},
			wire.Record{Name: name, Class: wire.ClassIN, TTL: 60, Data: wire.Pointer{Target: host}},
			wire.Record{
				Name:  name,
				Class: wire.ClassIN,
				TTL:   60,
				Data:  wire.Address{Addr: netip.MustParseAddr("192.0.2.2")},
			},
			wire.Record{
				Name:  name,
				Class: wire.ClassIN,
				TTL:   60,
				Data:  wire.Opaque{Kind: 13, Bytes: []byte("\x03ARM")},
			},
		)

		// In the order of their types.
		for _, want := range []mdns.Record{
			{Name: name, TTL: time.Minute, Data: mdns.Addr{Addr: netip.MustParseAddr("192.0.2.2")}},
			{Name: name, TTL: time.Minute, Data: mdns.Raw{Kind: 5, Bytes: []byte("\x07kitchen\x05local\x00")}},
			{Name: name, TTL: time.Minute, Data: mdns.PTR{Target: host}},
			{Name: name, TTL: time.Minute, Data: mdns.Raw{Kind: 13, Bytes: []byte("\x03ARM")}},
			{Name: name, TTL: 75 * time.Minute, Data: mdns.TXT{
				{Key: "path", Value: []byte("/")}, {Key: "secure"}, {Key: "empty", Value: []byte{}},
			}},
			{Name: name, TTL: 2 * time.Minute, Data: mdns.SRV{Port: 8080, Target: host}},
			{Name: name, TTL: 2 * time.Minute, Data: mdns.NSEC{Next: name, Types: []mdns.Type{mdns.TypeTXT, mdns.TypeSRV}}},
		} {
			if got := <-heard; got.change != mdns.Found ||
				!reflect.DeepEqual(got.answer, mdns.Answer{Record: want, Interfaces: en0}) {
				t.Errorf("told %s of\n%+v\nwant\n%+v", got.change, got.answer, want)
			}
		}

		// A record that was wrong is asked about, and forgotten.
		doubted := mdns.Record{Name: name, Data: mdns.SRV{Port: 8080, Target: host}}
		if err = peer.ReconfirmRecord(doubted); err != nil {
			t.Fatal(err)
		}

		began := time.Now()

		if got := <-heard; got.change != mdns.Lost || !reflect.DeepEqual(got.answer.Record.Data, doubted.Data) ||
			time.Since(began) != 10*time.Second {
			t.Errorf("told %s of %+v after %s", got.change, got.answer.Record, time.Since(began))
		}

		if err = peer.Close(); err != nil {
			t.Fatal(err)
		}

		if err = <-ended; !errors.Is(err, mdns.ErrClosed) {
			t.Errorf("the Ask of a Peer that was closed: %v", err)
		}

		if err = peer.ReconfirmRecord(doubted); !errors.Is(err, mdns.ErrClosed) {
			t.Errorf("doubting on a Peer that is closed: %v", err)
		}

		if err = peer.Close(); err != nil {
			t.Errorf("closing twice: %v", err)
		}
	})
}

func TestWhatAPeerRefuses(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	if _, err := mdns.Open(
		t.Context(),
		mdns.Config{Network: network.Host(), Hostname: "a..b"},
	); !errors.Is(
		err,
		mdns.ErrInvalid,
	) {
		t.Errorf("a host name that is none: %v", err)
	}

	peer, err := mdns.Open(t.Context(), mdns.Config{Network: network.Host()})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = peer.Close() }()

	if err = peer.Ask(t.Context(), mdns.Question{Type: mdns.TypeA}, nil); !errors.Is(err, mdns.ErrInvalid) {
		t.Errorf("a question for no name: %v", err)
	}

	host := mdns.Name{"kitchen", "local"}

	for what, record := range map[string]mdns.Record{
		"no name":                  {Data: mdns.PTR{Target: host}},
		"no data":                  {Name: host},
		"an address that is none":  {Name: host, Data: mdns.Addr{}},
		"a target that is none":    {Name: host, Data: mdns.PTR{}},
		"a service with no target": {Name: host, Data: mdns.SRV{}},
		"a text key with an =":     {Name: host, Data: mdns.TXT{{Key: "a=b"}}},
		"a denial of no name":      {Name: host, Data: mdns.NSEC{}},
		"a record of every type":   {Name: host, Data: mdns.Raw{Kind: mdns.TypeANY}},
		"a record of no type":      {Name: host, Data: mdns.Raw{}},
		"a life below nothing":     {Name: host, TTL: -time.Second, Data: mdns.PTR{Target: host}},
	} {
		if err = peer.ReconfirmRecord(record); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("%s: %v", what, err)
		}
	}
}

// Two Peers on a wire: what one publishes the other finds, and loses a
// second after it is withdrawn; and a name one holds the other cannot
// take.
func TestAPeerPublishes(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		open := func(last string) *mdns.Peer {
			peer, err := mdns.Open(t.Context(), mdns.Config{Network: network.Host(mdnstest.Port{
				Interface: "en0", Wire: "lan",
				Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2." + last + "/24")},
			})})
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { _ = peer.Close() })

			return peer
		}

		one, other := open("1"), open("2")

		synctest.Wait()

		name := mdns.Name{"kitchen", "local"}
		record := mdns.Record{Name: name, Data: mdns.Addr{Addr: netip.MustParseAddr("192.0.2.1")}}

		heard := make(chan mdns.Change, 4)
		ended := make(chan error, 1)
		ctx, stop := context.WithCancel(t.Context())

		go func() {
			ended <- other.Ask(ctx, mdns.Question{Name: name, Type: mdns.TypeA}, func(change mdns.Change, answer mdns.Answer) {
				// Two minutes, as RFC 6762 recommends for an address.
				if answer.Record.TTL != 2*time.Minute || !reflect.DeepEqual(answer.Record.Data, record.Data) {
					t.Errorf("told of %+v", answer.Record)
				}

				heard <- change
			})
		}()

		published, err := one.Publish(t.Context(), mdns.Records{Records: []mdns.Record{record}})
		if err != nil {
			t.Fatal(err)
		}

		if change := <-heard; change != mdns.Found {
			t.Errorf("told %s", change)
		}

		// The other cannot have the name for another address.
		taken := mdns.Record{Name: name, Data: mdns.Addr{Addr: netip.MustParseAddr("192.0.2.2")}}
		if _, err = other.Publish(
			t.Context(),
			mdns.Records{Records: []mdns.Record{taken}},
		); !errors.Is(
			err,
			mdns.ErrConflict,
		) {
			t.Errorf("a name that is taken: %v", err)
		}

		// Nor a record that cannot be said.
		if _, err = other.Publish(
			t.Context(),
			mdns.Records{Records: []mdns.Record{{Name: name}}},
		); !errors.Is(
			err,
			mdns.ErrInvalid,
		) {
			t.Errorf("a record with no data: %v", err)
		}

		if published.Err() != nil {
			t.Errorf("what stands has ended: %v", published.Err())
		}

		withdrawn := time.Now()

		if err = published.Close(); err != nil {
			t.Fatal(err)
		}

		<-published.Done()

		if change := <-heard; change != mdns.Lost || time.Since(withdrawn) != time.Second ||
			!errors.Is(published.Err(), mdns.ErrClosed) {
			t.Errorf("told %s after %s, ended with %v", change, time.Since(withdrawn), published.Err())
		}

		// What others may say too is said by both.
		shared := mdns.Records{
			Shared:  true,
			Records: []mdns.Record{{Name: mdns.Name{"_http", "_tcp", "local"}, Data: mdns.PTR{Target: name}}},
		}

		for _, peer := range []*mdns.Peer{one, other} {
			if _, err = peer.Publish(t.Context(), shared); err != nil {
				t.Errorf("what others may say too: %v", err)
			}
		}

		stop()

		if err = <-ended; !errors.Is(err, context.Canceled) {
			t.Errorf("the Ask ended with %v", err)
		}
	})
}

// A record that does not say how long it is to be remembered is given
// what RFC 6762 section 10 recommends: two minutes when its name is a
// host's or its data holds a host's name, 75 minutes otherwise.
func TestHowLongARecordIsRememberedByDefault(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		open := func(last string) *mdns.Peer {
			peer, err := mdns.Open(t.Context(), mdns.Config{Network: network.Host(mdnstest.Port{
				Interface: "en0", Wire: "lan",
				Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2." + last + "/24")},
			})})
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { _ = peer.Close() })

			return peer
		}

		one, other := open("1"), open("2")

		synctest.Wait()

		host := mdns.Name{"kitchen", "local"}
		back := mdns.Name{"1", "2", "0", "192", "in-addr", "arpa"}
		listed := mdns.Name{"_http", "_tcp", "local"}

		for what, row := range map[string]struct {
			record mdns.Record
			want   time.Duration
		}{
			"an address":                    {mdns.Record{Name: host, Data: mdns.Addr{Addr: netip.MustParseAddr("192.0.2.1")}}, 2 * time.Minute},
			"where a service is":            {mdns.Record{Name: mdns.Name{"a", "_http", "_tcp", "local"}, Data: mdns.SRV{Port: 80, Target: host}}, 2 * time.Minute},
			"what a host is":                {mdns.Record{Name: mdns.Name{"described", "local"}, Data: mdns.Raw{Kind: 13, Bytes: []byte("\x03ARM\x05Linux")}}, 2 * time.Minute},
			"an address back to its host":   {mdns.Record{Name: back, Data: mdns.PTR{Target: host}}, 2 * time.Minute},
			"what lists a service":          {mdns.Record{Name: listed, Data: mdns.PTR{Target: mdns.Name{"a", "_http", "_tcp", "local"}}}, 75 * time.Minute},
			"what a service says of itself": {mdns.Record{Name: mdns.Name{"b", "_http", "_tcp", "local"}, Data: mdns.TXT{}}, 75 * time.Minute},
		} {
			if _, err := one.Publish(t.Context(), mdns.Records{Records: []mdns.Record{row.record}}); err != nil {
				t.Fatalf("%s: %v", what, err)
			}

			ctx, stop := context.WithCancel(t.Context())

			_ = other.Ask(
				ctx,
				mdns.Question{Name: row.record.Name, Type: row.record.Data.Type()},
				func(_ mdns.Change, answer mdns.Answer) {
					if answer.Record.TTL != row.want {
						t.Errorf("%s: good for %s, want %s", what, answer.Record.TTL, row.want)
					}

					stop()
				},
			)
		}
	})
}

// errNoSocket is why a network of a test cannot be watched.
var errNoSocket = errors.New("no socket on the port")

// unwatched is a Network that cannot be watched: it gives up at once
// with what it is given, or says nothing for as long as it is let.
type unwatched struct{ gives error }

func (u unwatched) Watch(ctx context.Context, _ func(transport.Event)) error {
	if u.gives != nil {
		return u.gives
	}

	<-ctx.Done()

	return ctx.Err()
}

// A Peer that cannot be opened for what the network is says so as it
// is: nothing that was asked of it was invalid.
func TestAPeerOnANetworkThatCannotBeWatched(t *testing.T) {
	t.Parallel()

	_, err := mdns.Open(t.Context(), mdns.Config{Network: unwatched{gives: errNoSocket}})
	if !errors.Is(err, errNoSocket) || errors.Is(err, mdns.ErrInvalid) {
		t.Errorf("on a network that cannot be watched: %v", err)
	}

	ctx, stop := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer stop()

	_, err = mdns.Open(ctx, mdns.Config{Network: unwatched{}})
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, mdns.ErrInvalid) {
		t.Errorf("on a network that never says what links it has: %v", err)
	}
}
