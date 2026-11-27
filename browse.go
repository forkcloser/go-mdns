package mdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
)

// Query says which services to look for.
type Query struct {
	// Type is the kind of service: "_http._tcp". A type older than RFC
	// 6335, longer than fifteen characters, is looked for all the same.
	Type string

	// Subtype narrows it to the instances announced under one:
	// "_printer".
	Subtype string

	// Name narrows it to the one instance of that name. Its records are
	// then asked for directly, which finds it sooner than browsing for
	// its type does.
	Name string

	// Unresolved tells of instances as soon as their names are known,
	// and asks no more about them: enough to show a list, and less to
	// say on the network. An Instance then has a name, a type and its
	// interfaces, and nothing else.
	Unresolved bool

	// Interfaces says which interfaces to ask on, of those the Peer is
	// on: On("en0"), or any rule. Nil is all of them.
	Interfaces func(Interface) bool
}

// Instance is a service found: what was announced, as it is known now.
//
// It is one instance however many interfaces it is seen on. What makes
// it one is its name, its type, and the host and port it says it is
// at: the same name heard on two links from two different hosts is two
// instances, as RFC 6762 allows two links to have.
type Instance struct {
	// Name and Type are the instance's name and its type.
	Name string
	Type string

	// Interfaces is the interfaces it is seen on, in the order of their
	// indexes: never empty for an instance found or changed, and those
	// it was last seen on for one lost.
	Interfaces []Interface

	// Host is the host it is on, ending in ".local", and Port where it
	// listens there.
	Host string
	Port uint16

	// Priority and Weight are its SRV record's.
	Priority uint16
	Weight   uint16

	// Text is its TXT record.
	Text TXT

	// Addrs is where the host is, by any of those interfaces, each
	// address once, in the order they were learned. An IPv6 link-local
	// address carries its zone, which says the interface it is good on;
	// any other is to be routed as the system routes. It may be empty
	// for a moment after the instance is found: a host's addresses are
	// records of their own.
	Addrs []netip.Addr
}

// Change is what happened to an instance, or to a record.
type Change uint8

// The changes.
const (
	// Found: it was not known, and is.
	Found Change = iota + 1
	// Changed: it is known, and something of it is no longer what it
	// was.
	Changed
	// Lost: it said goodbye, or was not heard of for as long as it said
	// it could be remembered.
	Lost
)

// String is the change as a word: "found", "changed", "lost".
func (c Change) String() string {
	switch c {
	case Found:
		return "found"
	case Changed:
		return "changed"
	case Lost:
		return "lost"
	default:
		return "no change"
	}
}

// Browse tells handle of the services a query finds: first those the
// Peer already knows of, each as found, and then every one that is
// found, changes or is lost, for as long as ctx lasts. Calls come one at
// a time and in order, on the goroutine that called Browse; handle may
// take its time, which holds back this Browse and nothing else, and may
// ask things of the Peer. Each carries the instance whole, as it stands
// after the change, or for one lost as it last stood, so that one
// applied twice does no harm; a handle that is slow is told where
// things stand, not every step they took to get there.
//
// An instance is found once its SRV and TXT records are known on some
// interface; changed when they, its host's addresses or the interfaces
// it is seen on are no longer what they were; and lost when it is seen
// on none. With Query.Unresolved it is found once its name is.
//
// Browse asks, and goes on asking as RFC 6762 has it: at lengthening
// intervals, saying what it already knows so that it is not told again,
// and before what it knows runs out. Several may browse at once, for the
// same thing or not; what one learns the others have.
//
// It returns ctx's error when ctx ends, ErrClosed when the Peer closes,
// and ErrInvalid for a query that is not one.
func (p *Peer) Browse(ctx context.Context, query Query, handle func(Change, Instance)) error {
	return p.search(ctx, query, handle)
}

// Reconfirm tells the Peer that an instance could not be reached where
// it said it was, which the Peer cannot know by itself. Its records are
// asked for again at once, and forgotten if no one answers within ten
// seconds, however long they were said to last: a Browse then tells of
// it as lost. It takes any Instance a Browse told of; of one found with
// Query.Unresolved, which says no host, it asks whether it is still
// listed. It returns at once, and ErrClosed from a Peer that is.
func (p *Peer) Reconfirm(doubted Instance) error {
	service, proto, err := serviceType(doubted.Type)
	if err != nil {
		return err
	}

	// Under any label: the instance is one another host announced, and
	// not every host holds its names to text.
	kind := Name{service, proto, local}
	instance := append(Name{doubted.Name}, kind...)
	records := []wire.Record{{Name: kind, Data: wire.Pointer{Target: instance}}}

	// An instance found with Query.Unresolved says no more than that it
	// is listed.
	if doubted.Host != "" {
		var host Name

		if host, err = foundHost(doubted.Host); err != nil {
			return err
		}

		records = append(records, wire.Record{
			Name: instance,
			Data: wire.Service{Priority: doubted.Priority, Weight: doubted.Weight, Port: doubted.Port, Target: host},
		})

		for _, addr := range doubted.Addrs {
			records = append(records, wire.Record{Name: host, Data: wire.Address{Addr: addr.WithZone("")}})
		}
	}

	for _, record := range records {
		if err = p.engine.Reconfirm(record); err != nil {
			return translate(err)
		}
	}

	return nil
}

// Resolve finds the one instance of a name and a type, and returns it
// once its SRV and TXT records and an address of its host are known, on
// whichever link that is so first. It asks until ctx ends, and then
// returns ctx's error: nothing on the network says that an instance is
// not there.
func (p *Peer) Resolve(ctx context.Context, name, service string) (Instance, error) {
	if name == "" {
		return Instance{}, fmt.Errorf("%w: an instance with no name", ErrInvalid)
	}

	ctx, found := context.WithCancel(ctx)
	defer found()

	var resolved *Instance

	err := p.search(ctx, Query{Type: service, Name: name}, func(change Change, instance Instance) {
		if change != Lost && len(instance.Addrs) > 0 && resolved == nil {
			resolved = &instance

			found()
		}
	})

	if resolved != nil {
		return *resolved, nil
	}

	return Instance{}, err
}

// LookupHost finds where a host is: "printer.local", or "printer". A
// name of more than one label is looked for as it is written, since the
// host a service says it is on may be under another name than "local".
// It returns the addresses known a moment after the first one is, so that
// a host with both an IPv4 and an IPv6 address is given a chance to say
// both. An IPv6 link-local address carries its zone. It asks until ctx
// ends, and then returns ctx's error.
func (p *Peer) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	name, err := foundHost(host)
	if err != nil {
		return nil, err
	}

	asked := p.engine.Group()
	defer asked.Close()

	for _, kind := range []uint16{wire.TypeA, wire.TypeAAAA} {
		if _, err = asked.Add(engine.Question{Name: name, Type: kind}); err != nil {
			return nil, translate(err)
		}
	}

	found := whereabouts{addrs: map[string]engine.Answer{}}

	// Until there is one address; then a moment more, for the others.
	if err = found.gather(ctx, asked, func() bool { return len(found.order) > 0 }); err != nil {
		return nil, err
	}

	more, enough := context.WithTimeout(ctx, moment)
	defer enough()

	if err = found.gather(
		more,
		asked,
		func() bool { return false },
	); ctx.Err() != nil ||
		!errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}

	return found.reached(nil), nil
}

// gather takes a host's addresses as questions bring them, until there
// are enough or ctx ends.
func (w *whereabouts) gather(ctx context.Context, asked *engine.Group, enough func() bool) error {
	for {
		told, err := asked.Poll()
		if err != nil {
			return translate(err)
		}

		for _, one := range told {
			w.take(one.Change, one.Answer)
		}

		if enough() {
			return nil
		}

		if err = asked.Wait(ctx); err != nil {
			return translate(err)
		}
	}
}

// moment is how long after a host's first address LookupHost waits for
// the others: those of the other family, which come with it or right
// after.
const moment = 100 * time.Millisecond

// ServiceType is a type of service that is announced.
type ServiceType struct {
	// Type is the type: "_http._tcp".
	Type string
	// Interfaces is the interfaces it is announced on, as an Instance's
	// are.
	Interfaces []Interface
}

// ServiceTypes tells handle of every type of service announced on the
// links the Peer is on, as RFC 6763 has them enumerated: those known,
// and then each found or lost, until ctx ends. It returns as Browse
// does.
func (p *Peer) ServiceTypes(ctx context.Context, handle func(Change, ServiceType)) error {
	enumeration := engine.Question{Name: Name{"_services", "_dns-sd", "_udp", local}, Type: wire.TypePTR}

	return translate(p.engine.Ask(ctx, enumeration, func(change engine.Change, answer engine.Answer) {
		// Only the two labels of the type count; what follows is the
		// domain it was asked in.
		if pointer, ok := answer.Record.Data.(wire.Pointer); ok && len(pointer.Target) > 2 {
			handle(Change(change), ServiceType{Type: Name(pointer.Target[:2]).String(), Interfaces: answer.Interfaces})
		}
	}))
}
