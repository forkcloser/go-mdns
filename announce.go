package mdns

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
)

// Announcement is a service being announced.
type Announcement struct {
	peer    *Peer
	service Service
	// kind is the service's type as a name: its two labels, and local.
	kind Name
	// elsewhere is the host the service is on, when it is not this one.
	elsewhere *elsewhere
	// stop ends what keeps the service announced; done is closed when it
	// no longer is, err saying why.
	stop context.CancelFunc
	done chan struct{}

	// mu guards what follows: the name it has and how many were refused
	// before it, its host, its text, and what it is published as.
	mu        sync.Mutex
	name      string
	refused   int
	target    Name
	text      TXT
	published *engine.Publication
	err       error
}

// Announce offers a service on every link the Peer is on, and on each it
// comes to be on. It first asks, on each link, whether the name is free,
// as RFC 6762 has it; a name another host holds, or that this Peer
// already announces a service of the same type under on an interface
// this one is wanted on, is put to the service's Rename, and the
// answer tried. It returns once the service is announced
// on the links there are, under the name it ended with, which Name
// gives; or with ErrConflict when Rename gave up, ErrInvalid for a
// service that does not validate, or ctx's error, the service then
// withdrawn.
//
// From then on the Peer answers for the service, defends its name,
// announces it on links that come up, and renames it should a host turn
// up later with the same one.
//
//nolint:contextcheck // what keeps the service announced lives as long as the Peer, not as long as the call
func (p *Peer) Announce(ctx context.Context, service Service) (*Announcement, error) {
	if err := service.Validate(); err != nil {
		return nil, err
	}

	label, proto, _ := serviceType(service.Type)
	announced := &Announcement{
		peer: p, service: service, kind: Name{label, proto, local},
		name: service.Name, text: service.Text, done: make(chan struct{}),
	}

	var err error

	if service.Host != "" {
		announced.elsewhere, announced.target, err = p.borrow(ctx, &service)
	} else {
		announced.target, err = p.host(ctx)
	}

	if err != nil {
		return nil, err
	}

	if announced.name == "" {
		announced.name = announced.target[0]
	}

	if err = announced.publish(ctx); err != nil {
		if announced.elsewhere != nil {
			p.give(announced.elsewhere)
		}

		return nil, err
	}

	life, stop := context.WithCancel(p.life)
	announced.stop = stop

	p.mu.Lock()
	p.announced = append(p.announced, announced)
	p.mu.Unlock()

	p.keeping.Go(func() { announced.keep(life) })

	if announced.elsewhere != nil {
		return announced, nil
	}

	// The host may lose its name while the service is being announced,
	// and take another. Whoever points the services at the new name may
	// do it before the name read here is given, which would undo it: so
	// the name is looked at again after, until it has not changed.
	for {
		p.mu.Lock()
		held := p.held
		p.mu.Unlock()

		if held == nil {
			announced.end(ErrConflict)

			return nil, fmt.Errorf("%w: the host of %q has no name", ErrConflict, announced.Name())
		}

		announced.retarget(Name{held.label, local})

		p.mu.Lock()
		kept := p.held == held
		p.mu.Unlock()

		if kept {
			return announced, nil
		}
	}
}

// Name is the instance name the service is announced under now: the one
// asked for, or the one it was renamed to.
func (a *Announcement) Name() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.name
}

// Update changes the service's text record and tells the neighbours, as
// RFC 6762 has a changed record told. Nothing else of a service changes
// while it is announced: a new port is a new announcement.
//
// A text that changes more than ten times a minute is more than the
// protocol means to carry: the neighbours are told of the last, not of
// each.
func (a *Announcement) Update(ctx context.Context, text TXT) error {
	if err := text.Validate(); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("changing the text of %q: %w", a.Name(), context.Cause(ctx))
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.published == nil {
		return ErrClosed
	}

	a.text = slices.Clone(text)

	return translate(a.published.Update(a.records()))
}

// Close withdraws the service: its neighbours are told goodbye, and
// forget it at once.
func (a *Announcement) Close() error {
	a.end(ErrClosed)

	return nil
}

// Done is closed when the service is no longer announced: withdrawn by
// Close or by the Peer's, or renamed to nothing by Rename.
func (a *Announcement) Done() <-chan struct{} {
	return a.done
}

// Err is why, once Done is closed: ErrClosed, or ErrConflict. Nil until
// then.
func (a *Announcement) Err() error {
	select {
	case <-a.done:
		a.mu.Lock()
		defer a.mu.Unlock()

		return a.err
	default:
		return nil
	}
}

// ttlOf is a TTL in seconds: the one asked for, or the one RFC 6762
// recommends when none is.
func ttlOf(asked time.Duration, recommended uint32) uint32 {
	if asked <= 0 {
		return recommended
	}

	return uint32(min(max(asked/time.Second, 1), maxTTL)) // #nosec G115 -- between one and maxTTL
}

// records is the service as its records: the PTR records that list it
// under its type, under each of its subtypes and its type among the
// types there are, which others may say too; and its SRV and TXT
// records, which are its own.
func (a *Announcement) records() []wire.Record {
	instance := append(Name{a.name}, a.kind...)
	long, short := ttlOf(a.service.TTL, otherTTL), ttlOf(a.service.TTL, hostTTL)

	records := []wire.Record{
		{Name: a.kind, TTL: long, Data: wire.Pointer{Target: instance}},
		{Name: Name{"_services", "_dns-sd", "_udp", local}, TTL: long, Data: wire.Pointer{Target: a.kind}},
	}

	for _, subtype := range a.service.Subtypes {
		records = append(
			records,
			wire.Record{
				Name: append(Name{subtype, "_sub"}, a.kind...),
				TTL:  long,
				Data: wire.Pointer{Target: instance},
			},
		)
	}

	return append(records,
		wire.Record{Name: instance, TTL: short, Flush: true, Data: wire.Service{
			Priority: a.service.Priority, Weight: a.service.Weight, Port: a.service.Port, Target: a.target,
		}},
		wire.Record{Name: instance, TTL: long, Flush: true, Data: a.text.wire()},
	)
}

// publish announces the service under the name it has, and under the
// next that Rename gives for as long as the one tried is taken.
func (a *Announcement) publish(ctx context.Context) error {
	for {
		a.mu.Lock()
		set := engine.Set{Records: a.records(), Interfaces: a.service.Interfaces}
		a.mu.Unlock()

		published, err := a.peer.engine.Publish(ctx, set)
		if err == nil {
			a.mu.Lock()
			a.published = published
			a.mu.Unlock()

			return nil
		}

		if !errors.Is(err, engine.ErrConflict) {
			return translate(err)
		}

		if !a.renamed() {
			return fmt.Errorf("%w: the service %q", ErrConflict, a.Name())
		}
	}
}

// renamed gives the service the name Rename answers to the one it has
// being taken, and says no when it answers none.
func (a *Announcement) renamed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.refused++

	next, ok := rename(a.service.Rename, a.name, a.refused, false)
	if ok {
		a.name = next
	}

	return ok
}

// keep keeps the service announced: when a host turns up with its name,
// it takes another, until none is to be had or it is withdrawn.
func (a *Announcement) keep(ctx context.Context) {
	for {
		a.mu.Lock()
		published := a.published
		a.mu.Unlock()

		if published == nil {
			return
		}

		select {
		case <-published.Done():
		case <-a.done:
			return
		}

		if !errors.Is(published.Err(), engine.ErrConflict) {
			a.end(ErrClosed)

			return
		}

		if !a.renamed() || a.publish(ctx) != nil {
			a.end(ErrConflict)

			return
		}
	}
}

// retarget points the service at the host's name, when that is not
// where it points already.
func (a *Announcement) retarget(host Name) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// The engine says again whatever it is given, changed or not.
	if host.Equal(a.target) {
		return
	}

	a.target = host

	if a.published != nil {
		_ = a.published.Update(a.records())
	}
}

// end stops announcing the service, and says why.
func (a *Announcement) end(why error) {
	a.mu.Lock()

	if a.err != nil {
		a.mu.Unlock()

		return
	}

	a.err = why
	published := a.published
	a.published = nil
	a.mu.Unlock()

	a.stop()

	if published != nil {
		_ = published.Close()
	}

	if a.elsewhere != nil {
		a.peer.give(a.elsewhere)
	}

	a.peer.mu.Lock()
	a.peer.announced = slices.DeleteFunc(a.peer.announced, func(one *Announcement) bool { return one == a })
	a.peer.mu.Unlock()

	close(a.done)
}
