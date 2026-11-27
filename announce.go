package mdns

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	mu      sync.Mutex
	name    string
	refused int
	target  Name
	text    TXT
	// changes counts the times its host or its text changed: a name
	// takes a second to ask for, and what is published under it is what
	// the service was when the asking began.
	changes   int
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
// while it is announced: a new port is a new announcement. A text the
// service could not have been announced with is ErrInvalid, and the
// service keeps the one it has.
//
// A text that changes more than ten times a minute is more than the
// protocol means to carry: the neighbours are told of the last, not of
// each.
func (a *Announcement) Update(ctx context.Context, text TXT) error {
	if err := text.Validate(); err != nil {
		return err
	}

	if err := a.service.fits(text); err != nil {
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
	a.changes++

	err := a.published.Update(a.records())

	// The name was lost to another host, and the next is being asked
	// for: the text is said with it.
	if errors.Is(err, engine.ErrClosed) && errors.Is(a.published.Err(), engine.ErrConflict) {
		return nil
	}

	return translate(err)
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

// records is the service as its records, as it now is.
func (a *Announcement) records() []wire.Record {
	return a.service.records(a.kind, a.name, a.target, a.text)
}

// records is a service as its records, under a name, at a host and with
// a text: the PTR records that list it under its type, under each of
// its subtypes and its type among the types there are, which others may
// say too; and its SRV and TXT records, which are its own. kind is its
// type as a name.
func (s *Service) records(kind Name, name string, target Name, text TXT) []wire.Record {
	instance := append(Name{name}, kind...)
	long, short := ttlOf(s.TTL, otherTTL), ttlOf(s.TTL, hostTTL)

	records := []wire.Record{
		{Name: kind, TTL: long, Data: wire.Pointer{Target: instance}},
		{Name: Name{"_services", "_dns-sd", "_udp", local}, TTL: long, Data: wire.Pointer{Target: kind}},
	}

	for _, subtype := range s.Subtypes {
		records = append(
			records,
			wire.Record{
				Name: append(Name{subtype, "_sub"}, kind...),
				TTL:  long,
				Data: wire.Pointer{Target: instance},
			},
		)
	}

	return append(records,
		wire.Record{Name: instance, TTL: short, Flush: true, Data: wire.Service{
			Priority: s.Priority, Weight: s.Weight, Port: s.Port, Target: target,
		}},
		wire.Record{Name: instance, TTL: long, Flush: true, Data: text.wire()},
	)
}

// fits says whether the service can be said with a text, whatever names
// it comes to have: its own and its host's are each a label that Rename
// may make as long as a label can be, and a name that is asked for goes
// in one message with the records meant for it.
func (s *Service) fits(text TXT) error {
	label, proto, _ := serviceType(s.Type)
	longest := strings.Repeat("x", maxLabel)
	target := Name{longest, local}

	if s.Host != "" {
		named, err := hostName(s.Host)
		if err != nil {
			return err
		}

		target = named
	}

	set := engine.Set{Records: s.records(Name{label, proto, local}, longest, target, text)}
	if err := set.Check(); err != nil {
		return fmt.Errorf("%w: the text record is more than one message holds with the service's names", ErrInvalid)
	}

	return nil
}

// publish announces the service under the name it has, and under the
// next that Rename gives for as long as the one tried is taken.
//
// A service on this host is announced at a name the host holds: one the
// host has lost and not yet replaced is waited out, and the asking
// starts over when the host loses its name while the service's is asked
// for. The lost name is another host's, and a service said to be there
// sends its users to that host. A host that is not this one takes no
// other name: the service is not announced once its name is lost.
func (a *Announcement) publish(ctx context.Context) error {
	for {
		host, err := a.hosted(ctx)
		if err != nil {
			return err
		}

		a.mu.Lock()
		set := engine.Set{Records: a.records(), Interfaces: a.service.Interfaces}
		built := a.changes
		a.mu.Unlock()

		asking, done := during(ctx, host)
		published, err := a.peer.engine.Publish(asking, set)

		// Looked at before the asking is let go of, which ends it too.
		gone := ctx.Err() == nil && asking.Err() != nil

		done()

		switch {
		case err == nil:
			return a.install(published, built)
		case errors.Is(err, engine.ErrConflict):
			if !a.renamed() {
				return fmt.Errorf("%w: the service %q", ErrConflict, a.Name())
			}
		case gone:
			// The host's name went: again, at its next if it takes one.
		default:
			return translate(err)
		}
	}
}

// hosted is what holds the name of the host the service is on, which the
// service is pointed at: this host's, once it holds one, or the one
// announced for it.
func (a *Announcement) hosted(ctx context.Context) (*engine.Publication, error) {
	if a.elsewhere != nil {
		switch err := a.elsewhere.published.Err(); {
		case errors.Is(err, engine.ErrConflict):
			return nil, fmt.Errorf("%w: the host of %q", ErrConflict, a.Name())
		case err != nil:
			return nil, ErrClosed
		}

		return a.elsewhere.published, nil
	}

	held, err := a.peer.settled(ctx)
	if err != nil {
		return nil, err
	}

	a.retarget(Name{held.label, local})

	return held.published, nil
}

// install makes a publication the service's, built when the service
// had changed so many times. Its host renamed or its text changed while
// the name was asked for, it is brought to what the service now is; and
// a service withdrawn meanwhile stays withdrawn.
func (a *Announcement) install(published *engine.Publication, built int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.err != nil {
		_ = published.Close()

		return ErrClosed
	}

	a.published = published

	if a.changes != built {
		_ = published.Update(a.records())
	}

	return nil
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
		case <-a.elsewhere.gone():
			a.end(a.elsewhere.ended())

			return
		case <-a.done:
			return
		}

		if !errors.Is(published.Err(), engine.ErrConflict) {
			a.end(ErrClosed)

			return
		}

		if !a.renamed() {
			a.end(ErrConflict)

			return
		}

		// No name to be had is a conflict; anything else is the Peer
		// closing while one was asked for.
		if err := a.publish(ctx); err != nil {
			why := ErrClosed
			if errors.Is(err, ErrConflict) {
				why = ErrConflict
			}

			a.end(why)

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
	a.changes++

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
