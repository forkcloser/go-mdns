package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/transport"
)

// ErrConflict is a name that another host holds.
var ErrConflict = errors.New("the name is taken")

// Set is records to answer for, together: they are asked for together,
// said together, and withdrawn together.
type Set struct {
	// Records is the records. One with Flush set is this host's alone:
	// its name is asked for before it is used, and defended after. One
	// without may be said by others too, as a PTR that lists the
	// instances of a type is. Each says how long it may be remembered.
	Records []wire.Record

	// Host adds, on each interface, the interface's own addresses under
	// this name, as records that are this host's alone: a host's name,
	// which is at other addresses on each link. HostTTL is how long they
	// may be remembered, and Addresses which of an interface's are
	// said: nil is all of them.
	Host      []string
	HostTTL   uint32
	Addresses func(transport.Interface, netip.Addr) bool

	// Interfaces says which interfaces to answer on. Nil is all of them.
	Interfaces func(transport.Interface) bool
}

// Publication is a Set being answered for.
type Publication struct {
	engine *Engine
	// ready is closed when the set is said on every link there was when
	// it was published, or when it ended before; done when it ended,
	// err saying why.
	ready chan struct{}
	done  chan struct{}
	err   error

	// What follows is the loop's.
	set Set
	// stands is where it stands, link by link, and first how many of the
	// links there were at first have yet to hear it.
	stands map[*link]*standing
	first  int
	// updated is when its records were last changed and said.
	updated time.Time
	update  *timer
}

// standing is a Publication on a link.
type standing struct {
	pub     *Publication
	link    *link
	records []*owned
	// live says the records are answered for: their names are held.
	live bool
	// sent is how many times the names were asked for, while they are,
	// and said how many times the records were announced.
	sent  int
	said  int
	timer *timer
	// initial says the Publication waits for this link to be ready.
	initial bool
}

// owned is a record answered for on a link.
type owned struct {
	record wire.Record
	raw    []byte
	key    string
	// seq orders records as they were published.
	seq int
	// told is when it was last said to all on its link.
	told time.Time
}

func (o *owned) unique() bool { return o.record.Flush }

// is says whether the record is the same as another: name, type, data.
func (o *owned) is(key string, kind uint16, raw []byte) bool {
	return o.key == key && o.record.Type() == kind && bytes.Equal(o.raw, raw)
}

// defaultHostTTL is how long a host's addresses may be remembered when
// a Set does not say: what RFC 6762 section 10 recommends.
const defaultHostTTL = 120

// Publish answers for a set of records, on every link wanted, those
// that come up later included. It returns once the set has been said
// on each link there is: after the names that are to be this host's
// alone were asked for and no one had them, which takes about a
// second. It is ErrConflict when another host holds one; and when
// another set published here has a record of the same name and type
// as this host's alone on a link this one wants, which is said at
// once, or later, when such a link comes up, by Done; ErrInvalid
// for a set that cannot be said, ctx's error when ctx ends first.
func (e *Engine) Publish(ctx context.Context, set Set) (*Publication, error) {
	if err := set.check(); err != nil {
		return nil, err
	}

	set.Records = slices.Clone(set.Records)
	published := &Publication{
		engine: e,
		set:    set,
		ready:  make(chan struct{}),
		done:   make(chan struct{}),
		stands: map[*link]*standing{},
	}

	if err := e.do(func() { e.start(published) }); err != nil {
		return nil, err
	}

	select {
	case <-published.ready:
	case <-ctx.Done():
		_ = published.Close()

		return nil, fmt.Errorf("publishing: %w", context.Cause(ctx))
	case <-e.done:
		return nil, ErrClosed
	}

	if err := published.Err(); err != nil {
		return nil, err
	}

	return published, nil
}

// check says whether a set can be said at all.
func (s *Set) check() error {
	if len(s.Records) == 0 && len(s.Host) == 0 {
		return fmt.Errorf("%w: nothing to publish", ErrInvalid)
	}

	trial := wire.NewBuilder(nil, wire.Header{}, wire.Options{})

	for _, record := range s.Records {
		if len(record.Name) == 0 || record.TTL == 0 || trial.Answer(record) != nil {
			return fmt.Errorf("%w: a record for %q", ErrInvalid, record.Name)
		}
	}

	// Tried in a message of its own: a question does not follow answers
	// in one, and a set may have both records and a host.
	named := wire.NewBuilder(nil, wire.Header{}, wire.Options{})

	if s.Host != nil && (len(s.Host) == 0 || named.Question(wire.Question{Name: s.Host}) != nil) {
		return fmt.Errorf("%w: a host named %q", ErrInvalid, s.Host)
	}

	return nil
}

// Close withdraws the records: the neighbours are told goodbye.
func (p *Publication) Close() error {
	_ = p.engine.do(func() { p.engine.end(p, ErrClosed) })

	return nil
}

// Done is closed when the records are no longer answered for:
// withdrawn, or lost to another host that holds one of their names.
func (p *Publication) Done() <-chan struct{} { return p.done }

// Err is why, once Done is closed: ErrClosed, or ErrConflict. Nil until
// then.
func (p *Publication) Err() error {
	select {
	case <-p.done:
		return p.err
	default:
		return nil
	}
}

// Update changes what the records say: the neighbours are told of what
// is new, and goodbye for what is no more. The names that are this
// host's alone stay the ones it asked for; a set with another is
// ErrInvalid, and one with a record of a type another set published
// here has under such a name is ErrConflict, the set left as it was.
// Changes that come faster than ten a minute are said
// together, as RFC 6762 section 8.4 asks.
func (p *Publication) Update(records []wire.Record) error {
	next := p.set
	next.Records = slices.Clone(records)

	if err := next.check(); err != nil {
		return err
	}

	var refused error

	if err := p.engine.do(func() { refused = p.engine.update(p, next.Records) }); err != nil {
		return err
	}

	return refused
}

func (p *Publication) wants(iface transport.Interface) bool {
	return p.set.Interfaces == nil || p.set.Interfaces(iface)
}

// start starts answering for a Publication, on every link it wants.
func (e *Engine) start(published *Publication) {
	e.pubs = append(e.pubs, published)

	wanted := slices.DeleteFunc(e.sorted(), func(via *link) bool { return !published.wants(via.iface) })

	// Counted before any is raised: one that needs no asking is said at
	// once, and is not to be taken for the last.
	published.first = len(wanted)
	if published.first == 0 {
		close(published.ready)
	}

	for _, via := range wanted {
		// Ended on a link before this one: one this host has already.
		if published.ended() {
			return
		}

		e.raise(published, via, true)
	}
}

// raise puts a Publication on a link: its names are asked for there,
// and its records said when no one has them. initial says the
// Publication waits for that before it is ready.
func (e *Engine) raise(published *Publication, via *link, initial bool) {
	raised := &standing{pub: published, link: via, initial: initial}
	raised.records = e.resolve(raised)

	// A record that is to be this host's alone, of a name and a type
	// another set already has as such on this link, is taken as one
	// another host holds: asked for, no one would answer, and two sets
	// would then answer one question, each with its own.
	if raised.held() {
		e.end(published, ErrConflict)

		return
	}

	published.stands[via] = raised
	via.standing = append(via.standing, raised)

	e.claim(raised)
}

// held says whether a record a standing wants for this host alone is
// one another Publication has as such on the same link: the same name
// and the same type.
func (raised *standing) held() bool {
	return slices.ContainsFunc(raised.records, func(wanted *owned) bool {
		return wanted.unique() && raised.link.holds(raised, wanted.key, wanted.record.Type())
	})
}

// contended settles a host's standing whose records, brought up to the
// interface's addresses, now include one another set holds on the link.
// It says whether the standing is the one that ended, its records put
// back as they were so that nothing of the address is said for it.
func (e *Engine) contended(stood *standing, before []*owned) bool {
	for rival := stood.rival(); rival != nil; rival = stood.rival() {
		if e.second(stood.pub, rival.pub) {
			stood.records = before
			e.end(stood.pub, ErrConflict)

			return true
		}

		e.end(rival.pub, ErrConflict)
	}

	return false
}

// taken says whether one of the records a Publication would say is of a
// name and a type another has as this host's alone, on a link both
// stand on, and which name.
func (p *Publication) taken(records []wire.Record) ([]string, bool) {
	for _, stood := range p.stands {
		for _, record := range records {
			if record.Flush && stood.link.holds(stood, nameKey(record.Name), record.Type()) {
				return record.Name, true
			}
		}
	}

	return nil, false
}

// holds says whether a standing on the link, other than one, has a
// record of a name and a type as this host's alone.
func (l *link) holds(but *standing, key string, kind uint16) bool {
	return l.holder(but, key, kind) != nil
}

// holder is the standing on the link, other than one, that has a record
// of a name and a type as this host's alone; or none.
func (l *link) holder(but *standing, key string, kind uint16) *standing {
	found := slices.IndexFunc(l.standing, func(other *standing) bool {
		return other != but && slices.ContainsFunc(other.records, func(has *owned) bool {
			return has.unique() && has.key == key && has.record.Type() == kind
		})
	})
	if found < 0 {
		return nil
	}

	return l.standing[found]
}

// rival is a standing on the same link that has, as this host's alone,
// a record of a name and a type this one has as such too; or none.
func (raised *standing) rival() *standing {
	for _, wanted := range raised.records {
		if !wanted.unique() {
			continue
		}

		if other := raised.link.holder(raised, wanted.key, wanted.record.Type()); other != nil {
			return other
		}
	}

	return nil
}

// second says whether a Publication was published after another.
func (e *Engine) second(one, other *Publication) bool {
	return slices.Index(e.pubs, one) > slices.Index(e.pubs, other)
}

// resolve is a Publication's records as they are on a link: its own,
// and for a host the interface's addresses. A record that was there
// before is the same record still, with what is known of it.
func (e *Engine) resolve(stood *standing) []*owned {
	records := slices.Clone(stood.pub.set.Records)

	if host := stood.pub.set.Host; host != nil {
		ttl := stood.pub.set.HostTTL
		if ttl == 0 {
			ttl = defaultHostTTL
		}

		for _, addr := range e.addresses(stood.link.iface, stood.pub.set.Addresses) {
			records = append(records, wire.Record{Name: host, TTL: ttl, Flush: true, Data: wire.Address{Addr: addr}})
		}
	}

	resolved := make([]*owned, 0, len(records))

	for _, record := range records {
		record.Class = wire.ClassIN

		raw, err := wire.AppendData(nil, record.Data)
		if err != nil {
			continue
		}

		key := nameKey(record.Name)

		at := slices.IndexFunc(stood.records, func(old *owned) bool { return old.is(key, record.Type(), raw) })
		if at >= 0 {
			stood.records[at].record = record
			resolved = append(resolved, stood.records[at])

			continue
		}

		e.seq++
		resolved = append(resolved, &owned{record: record, raw: raw, key: key, seq: e.seq})
	}

	return resolved
}

// addresses is the addresses of an interface, of both families, that
// are to be said: RFC 6762 section 6.2 has all of an interface's said
// on it, and none of another's.
func (e *Engine) addresses(iface transport.Interface, said func(transport.Interface, netip.Addr) bool) []netip.Addr {
	var addrs []netip.Addr

	for _, via := range e.sorted() {
		if via.iface != iface {
			continue
		}

		for _, prefix := range via.addrs {
			addr := prefix.Addr().WithZone("")
			if (said == nil || said(iface, addr)) && !slices.Contains(addrs, addr) {
				addrs = append(addrs, addr)
			}
		}
	}

	return addrs
}

// readdress brings what is published on an interface to the addresses
// it now has, and says so where it changed.
func (e *Engine) readdress(iface transport.Interface) {
	for _, via := range e.sorted() {
		if via.iface != iface {
			continue
		}

		// Over a copy: a set that loses a record here ends, and one that
		// ended is not a host to bring up to anything.
		for _, stood := range slices.Clone(via.standing) {
			if stood.pub.set.Host != nil && !stood.pub.ended() {
				e.readdressed(stood)
			}
		}

		via.denials = nil
	}
}

// readdressed brings a host's standing to the addresses its interface
// now has.
func (e *Engine) readdressed(stood *standing) {
	before := stood.records
	stood.records = e.resolve(stood)

	// An address the host gains may be of a type another set holds under
	// its name here, with no link having come up to tell: the set
	// published second ends, as it would have had the address been there
	// when it was published.
	if e.contended(stood, before) {
		return
	}

	forget(stood, before)

	// A name the standing had nothing to say of alone, and now has: it
	// was never asked for on this link, and is before any of it is said
	// (8.1). A host with no address to say when it was published is one.
	// A standing that is still asking for its other names starts over,
	// with this one among them.
	named := func(records []*owned, key string) bool {
		return slices.ContainsFunc(records, func(one *owned) bool { return one.unique() && one.key == key })
	}

	if slices.ContainsFunc(stood.records, func(now *owned) bool { return now.unique() && !named(before, now.key) }) {
		e.claim(stood)

		return
	}

	if !stood.live || slices.Equal(before, stood.records) {
		return
	}

	// An address that went with others of its family left is taken back
	// by what is said of those; one that was the last of its family has
	// nothing to take it back, and is said goodbye to (RFC 6762 section
	// 10.1).
	last := slices.DeleteFunc(slices.Clone(before), func(old *owned) bool {
		return slices.ContainsFunc(stood.records, func(now *owned) bool {
			return now.key == old.key && now.record.Type() == old.record.Type()
		})
	})

	stood.link.respond(last, true)
	e.announce(stood)
}

// forget takes from what a link has to say the records a standing no
// longer has.
func forget(stood *standing, before []*owned) {
	for _, old := range before {
		if !slices.Contains(stood.records, old) {
			delete(stood.link.out, old)
		}
	}
}

// update changes a Publication's records, on the loop.
func (e *Engine) update(published *Publication, records []wire.Record) error {
	if published.ended() {
		return ErrClosed
	}

	held := func(key string) bool {
		return slices.ContainsFunc(
			published.set.Records,
			func(old wire.Record) bool { return old.Flush && nameKey(old.Name) == key },
		)
	}

	for _, record := range records {
		if record.Flush && !held(nameKey(record.Name)) {
			return fmt.Errorf("%w: %q was not asked for when the set was published", ErrInvalid, record.Name)
		}
	}

	// Taken as it would have been when the set was published; and the
	// set stays as it was.
	if name, taken := published.taken(records); taken {
		return fmt.Errorf("%w: %q is already published here", ErrConflict, strings.Join(name, "."))
	}

	published.set.Records = records

	for _, stood := range published.stands {
		before := stood.records
		stood.records = e.resolve(stood)
		stood.link.denials = nil
		forget(stood, before)

		// What others may say too is not replaced by what is new: it is
		// said goodbye to.
		gone := slices.DeleteFunc(slices.Clone(before), func(old *owned) bool {
			return old.unique() || slices.Contains(stood.records, old)
		})

		if stood.live {
			stood.link.respond(gone, true)
		}
	}

	// Said now, or as soon as ten a minute allows.
	if published.update == nil {
		published.update = e.after(max(0, updateEvery-e.now.Sub(published.updated)), func() { e.updated(published) })
	}

	return nil
}

// updated says a Publication's records as they now are.
func (e *Engine) updated(published *Publication) {
	published.update, published.updated = nil, e.now

	for _, stood := range published.stands {
		if stood.live {
			e.announce(stood)
		}
	}

	e.told(published)
}

// updateEvery is how far apart changes to a record are said: ten a
// minute.
const updateEvery = 6 * time.Second

func (p *Publication) ended() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// end stops answering for a Publication, and says why. Its neighbours
// are told goodbye where its records were said, but for the names
// another host took: those are no longer its to speak of.
func (e *Engine) end(published *Publication, why error) {
	if published.ended() {
		return
	}

	e.cancel(published.update)

	for via, stood := range published.stands {
		e.cancel(stood.timer)

		if stood.said > 0 {
			gone := stood.records
			if !stood.live {
				gone = slices.DeleteFunc(slices.Clone(gone), (*owned).unique)
			}

			via.respond(gone, true)
		}

		forget(&standing{link: via}, stood.records)
		via.standing = slices.DeleteFunc(via.standing, func(one *standing) bool { return one == stood })
		via.denials = nil
	}

	e.pubs = slices.DeleteFunc(e.pubs, func(one *Publication) bool { return one == published })
	published.err = why
	close(published.done)

	if published.first > 0 {
		published.first = 0
		close(published.ready)
	}

	e.told(published)
}

// told lets those who ask for what a Publication says know that it may
// no longer be what it was.
func (e *Engine) told(published *Publication) {
	keys := map[string]bool{}

	for _, record := range published.set.Records {
		keys[nameKey(record.Name)] = true
	}

	if published.set.Host != nil {
		keys[nameKey(published.set.Host)] = true
	}

	for key := range keys {
		for _, asked := range e.named[key] {
			asked.tell()
		}
	}
}
