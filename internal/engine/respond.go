package engine

import (
	"cmp"
	"errors"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/transport"
)

// How RFC 6762 section 6 has a host answer.
const (
	// What others may answer too is answered after 20 to 120 ms, so that
	// not all answer at once; what is this host's alone, at once.
	sharedLeast = 20 * time.Millisecond
	sharedMost  = 120 * time.Millisecond
	// A question cut short is answered after 400 to 500 ms: time for the
	// rest of what its asker knows to come (7.2).
	cutLeast = 400 * time.Millisecond
	cutMost  = 500 * time.Millisecond
	// No record is said to all twice in a second on a link; but to a
	// host asking for the name, to which it may be said again after
	// 250 ms.
	sayEvery    = time.Second
	defendEvery = 250 * time.Millisecond
	// A record said to all within a quarter of its life need not be
	// again for one host that would take an answer of its own (5.4).
	quarter = 4
	// A resolver that is not a Multicast DNS one is told no record lasts
	// over ten seconds (6.7).
	legacyTTL = 10
)

// held is what a link means to answer to a question that was cut short,
// once the rest of what its asker knows has come.
type held struct {
	records []*owned
	timer   *timer
}

// questioned takes a question another host asked, and answers it with
// what stands on the link.
func (e *Engine) questioned(heard *link, arrived arrival) {
	source := arrived.from.Addr().WithZone("")
	message := arrived.message
	legacy := arrived.from.Port() != transport.Port

	// A question sent to this host alone is taken from the link, and no
	// further (5.5).
	if !arrived.group && !heard.neighbour(source) {
		return
	}

	if !legacy {
		e.continued(heard, source, message)
	}

	planned := plan{all: true, whole: true}

	// A question a message repeats is one question, and a record one
	// answer whatever the number of questions it answers: what a message
	// has a host say, and what it costs it, goes by what is asked and
	// not by how often.
	asked := make(map[posed]struct{}, len(message.Questions))

	for _, question := range message.Questions {
		if question.Class != wire.ClassIN && question.Class != classANY {
			continue
		}

		one := posed{nameKey(question.Name), question.Type, question.Class, question.Unicast}
		if _, again := asked[one]; again {
			continue
		}

		asked[one] = struct{}{}

		// Another host asking for a name with what it means to say of
		// it: one of the two may have to yield.
		e.tiebreak(heard, question, message.Authorities)

		planned.take(heard, arrived, question, e.now, e.ours(source))
	}

	if legacy {
		heard.legacy(arrived, planned.alone)

		return
	}

	e.carry(heard, arrived, planned)
}

// carry does what was planned in answer to a message of questions.
func (e *Engine) carry(heard *link, arrived arrival, planned plan) {
	// At once when every question is answered with what is this host's
	// alone: no one else will answer.
	wait := time.Duration(0)
	if !planned.all || !planned.whole {
		wait = between(sharedLeast, sharedMost)
	}

	if len(planned.alone) > 0 {
		e.after(wait, func() {
			if e.links[heard.wire] == heard {
				heard.respondTo(heard.still(planned.alone), arrived.from)
			}
		})
	}

	if arrived.message.Header.Truncated && len(planned.answers) > 0 {
		e.hold(heard, arrived.from.Addr().WithZone(""), planned.answers)

		return
	}

	for _, record := range planned.answers {
		e.reply(heard, record, e.now.Add(wait), len(arrived.message.Authorities) > 0)
	}
}

// continued takes more of what a host knows, after a question of its
// that was cut short: what it knows is not said.
func (e *Engine) continued(heard *link, source netip.Addr, message wire.Message) {
	waiting := heard.held[source]
	if waiting == nil {
		return
	}

	waiting.records = slices.DeleteFunc(waiting.records, func(one *owned) bool { return knows(message.Answers, one) })

	if message.Header.Truncated {
		e.cancel(waiting.timer)
		waiting.timer = e.after(between(cutLeast, cutMost), func() { e.release(heard, source) })
	}
}

// posed is a question as a message may repeat it.
type posed struct {
	name    string
	kind    uint16
	class   uint16
	unicast bool
}

// plan is what is to be answered to a message of questions.
type plan struct {
	// answers is what is to be said to all, and alone what is to be
	// said to the asker; taken is what is in each already.
	answers []*owned
	alone   []*owned
	taken   map[taking]struct{}
	// all says every record is this host's alone, and whole that every
	// question has an answer.
	all   bool
	whole bool
}

// take adds what answers one question.
//
// local says the asker is another program on this host. What is said
// to this host alone reaches one of the programs on the port, the first
// to have bound it on most systems (RFC 6762 section 15.1), and not
// surely the one that asked: it is answered to all.
func (p *plan) take(heard *link, arrived arrival, question wire.Question, now time.Time, local bool) {
	source := arrived.from.Addr().WithZone("")
	legacy := arrived.from.Port() != transport.Port
	// defending is answering a host that asks for a name with what it
	// means to say of it.
	defending := len(arrived.message.Authorities) > 0
	matched := heard.matching(question)
	p.whole = p.whole && len(matched) > 0

	for _, record := range matched {
		if knows(arrived.message.Answers, record) {
			continue
		}

		p.all = p.all && record.unique()

		// To the asker alone, when it would take that and the record
		// was said to all not long ago.
		quiet := !local && (question.Unicast || !arrived.group) && heard.neighbour(source) &&
			!record.told.IsZero() && now.Sub(record.told) < time.Duration(record.record.TTL)*time.Second/quarter

		// And to a host asking for the name, always: it has 750 ms to
		// learn that the name is taken.
		defended := defending && question.Unicast && heard.neighbour(source)

		p.give(record, legacy || quiet || defended, !legacy && !quiet)
	}
}

// give adds a record to what is to be said, to the asker alone, to all
// or both.
func (p *plan) give(record *owned, alone, all bool) {
	if alone && p.once(record, true) {
		p.alone = append(p.alone, record)
	}

	if all && p.once(record, false) {
		p.answers = append(p.answers, record)
	}
}

// taking is a record in what is to be said, to the asker alone or to
// all.
type taking struct {
	record *owned
	alone  bool
}

// once says whether a record is not yet in what is to be said, and
// counts it in: a record is said once however often a message asks for
// it, and a name's records answer the question for any type as well.
func (p *plan) once(record *owned, alone bool) bool {
	if _, there := p.taken[taking{record, alone}]; there {
		return false
	}

	if p.taken == nil {
		p.taken = map[taking]struct{}{}
	}

	p.taken[taking{record, alone}] = struct{}{}

	return true
}

// between is a wait chosen at random between two.
func between(least, most time.Duration) time.Duration {
	return least + rand.N(most-least) // #nosec G404 -- a delay, not a secret
}

// knows says whether what an asker says it knows holds a record, with
// at least half its life left: such a record is not said again (7.1).
func knows(known []wire.Record, record *owned) bool {
	return slices.ContainsFunc(known, func(one wire.Record) bool {
		if 2*uint64(one.TTL) < uint64(record.record.TTL) || one.Type() != record.record.Type() ||
			nameKey(one.Name) != record.key {
			return false
		}

		raw, err := wire.AppendData(nil, one.Data)

		return err == nil && record.is(record.key, one.Type(), raw)
	})
}

// elsewhere says whether a record is one this Engine says itself on
// another of its links than the one it was heard on: heard round a
// bridge, it is this host, and no one to lose a name to (RFC 6762
// section 14). A record another program on the host says is not: it is
// told from this Engine's by what it says, not by where it comes from.
func (e *Engine) elsewhere(heard *link, record wire.Record) bool {
	raw, err := wire.AppendData(nil, record.Data)
	if err != nil {
		return false
	}

	key, kind := nameKey(record.Name), record.Type()
	same := func(one *owned) bool { return one.is(key, kind, raw) }

	for _, via := range e.links {
		if via == heard {
			continue
		}

		// What it says there of the types a name has is its own too.
		if denial := via.denials[key]; denial != nil && same(denial) {
			return true
		}

		for _, stood := range via.standing {
			if slices.ContainsFunc(stood.records, same) {
				return true
			}
		}
	}

	return false
}

// ours says whether an address is one of this host's: what comes from
// it is another program on the host.
func (e *Engine) ours(addr netip.Addr) bool {
	for _, via := range e.links {
		if slices.ContainsFunc(via.addrs, func(own netip.Prefix) bool { return own.Addr() == addr }) {
			return true
		}
	}

	return false
}

// matching is the records standing on a link that answer a question;
// or, for a name that is this host's alone and has no record of the
// type asked for, the record that says so (6.1).
func (l *link) matching(question wire.Question) []*owned {
	key := nameKey(question.Name)

	var (
		matched []*owned
		held    bool
	)

	for _, stood := range l.standing {
		if !stood.live {
			continue
		}

		for _, record := range stood.records {
			if record.key != key {
				continue
			}

			held = held || record.unique()

			if question.Type == wire.TypeANY || question.Type == record.record.Type() {
				matched = append(matched, record)
			}
		}
	}

	if len(matched) == 0 && held && question.Type != wire.TypeANY {
		return []*owned{l.denial(key)}
	}

	return matched
}

// denial is the record that says which types a name of this host's has
// on a link, and so which it has not.
func (l *link) denial(key string) *owned {
	if known := l.denials[key]; known != nil {
		return known
	}

	var (
		types []uint16
		first wire.Record
	)

	for _, stood := range l.standing {
		for _, record := range stood.records {
			if !stood.live || record.key != key || !record.unique() {
				continue
			}

			if len(types) == 0 {
				first = record.record
			}

			if !slices.Contains(types, record.record.Type()) {
				types = append(types, record.record.Type())
			}
		}
	}

	slices.Sort(types)

	said := &owned{
		record: wire.Record{
			Name: first.Name, Class: wire.ClassIN, Flush: true, TTL: first.TTL,
			Data: wire.NSEC{Next: first.Name, Types: types},
		},
		key: key,
	}
	said.raw, _ = wire.AppendData(nil, said.record.Data)

	if l.denials == nil {
		l.denials = map[string]*owned{}
	}

	l.denials[key] = said

	return said
}

// hold keeps what is to be answered to a question that was cut short,
// until the rest of what its asker knows has come.
func (e *Engine) hold(heard *link, source netip.Addr, answers []*owned) {
	if heard.held == nil {
		heard.held = map[netip.Addr]*held{}
	}

	waiting := heard.held[source]
	if waiting == nil {
		waiting = &held{}
		heard.held[source] = waiting
	}

	for _, record := range answers {
		if !slices.Contains(waiting.records, record) {
			waiting.records = append(waiting.records, record)
		}
	}

	e.cancel(waiting.timer)
	waiting.timer = e.after(between(cutLeast, cutMost), func() { e.release(heard, source) })
}

// release says what was held for a question cut short, less what its
// asker turned out to know.
func (e *Engine) release(heard *link, source netip.Addr) {
	waiting := heard.held[source]
	if waiting == nil {
		return
	}

	delete(heard.held, source)

	for _, record := range waiting.records {
		e.reply(heard, record, e.now, false)
	}
}

// reply puts a record among what a link is to say to all, at a time:
// not sooner than a second after it was last said there, or 250 ms to a
// host that is asking for the name.
func (e *Engine) reply(heard *link, record *owned, when time.Time, defending bool) {
	every := sayEvery
	if defending {
		every = defendEvery
	}

	if earliest := record.told.Add(every); !record.told.IsZero() && earliest.After(when) {
		when = earliest
	}

	if heard.out == nil {
		heard.out = map[*owned]time.Time{}
	}

	if planned, already := heard.out[record]; already && !planned.After(when) {
		return
	}

	heard.out[record] = when

	if heard.replying == nil || heard.replying.index < 0 || when.Before(heard.replying.at) {
		e.cancel(heard.replying)
		heard.replying = e.at(when, func() { e.replies(heard) })
	}
}

// replies says to all what a link has to say and whose time has come,
// in one message where it fits (6.4).
func (e *Engine) replies(heard *link) {
	heard.replying = nil

	var (
		due  []*owned
		next time.Time
	)

	for record, when := range heard.out {
		if when.After(e.now) {
			next = sooner(next, when)

			continue
		}

		due = append(due, record)
		delete(heard.out, record)
	}

	slices.SortFunc(due, func(one, other *owned) int { return cmp.Compare(one.seq, other.seq) })

	for _, record := range due {
		record.told = e.now
	}

	heard.respond(heard.still(due), false)

	if !next.IsZero() {
		heard.replying = e.at(next, func() { e.replies(heard) })
	}
}

// repeated takes a record another host said to all: what this host was
// about to say of the same, for as long or less, need not be (7.4).
func (l *link) repeated(record wire.Record) {
	raw, err := wire.AppendData(nil, record.Data)
	if err != nil {
		return
	}

	key := nameKey(record.Name)

	for planned := range l.out {
		if planned.is(key, record.Type(), raw) && record.TTL >= planned.record.TTL {
			delete(l.out, planned)
		}
	}
}

// still is the records that are still answered for on the link, of
// those given: one withdrawn since it was to be said is not said.
func (l *link) still(records []*owned) []*owned {
	return slices.DeleteFunc(slices.Clone(records), func(record *owned) bool {
		if l.denials[record.key] == record {
			return false
		}

		return !slices.ContainsFunc(l.standing, func(stood *standing) bool {
			return stood.live && slices.Contains(stood.records, record)
		})
	})
}

// with is the records standing on the link of a name and of one of
// some types.
func (l *link) with(key string, kinds ...uint16) []*owned {
	var found []*owned

	for _, stood := range l.standing {
		for _, record := range stood.records {
			if stood.live && record.key == key && slices.Contains(kinds, record.record.Type()) {
				found = append(found, record)
			}
		}
	}

	return found
}

// additional is the records that go with those answered, because who
// asked for these will ask for those next (RFC 6763 section 12, RFC
// 6762 section 6.2): a service's SRV and TXT records with its PTR, a
// host's addresses with an SRV, its addresses of the other family with
// those of one, or that it has none.
func (l *link) additional(answers []*owned) []*owned {
	said := slices.Clone(answers)

	// What is added is looked at in turn: an SRV that came with a PTR
	// brings its host's addresses.
	for index := 0; index < len(said); index++ {
		for _, record := range l.goes(said[index]) {
			if !slices.Contains(said, record) {
				said = append(said, record)
			}
		}
	}

	return said[len(answers):]
}

// goes is the records that go with one.
func (l *link) goes(record *owned) []*owned {
	switch data := record.record.Data.(type) {
	case wire.Pointer:
		return l.with(nameKey(data.Target), wire.TypeSRV, wire.TypeTXT)
	case wire.Service:
		return l.with(nameKey(data.Target), wire.TypeA, wire.TypeAAAA)
	case wire.Address:
		other := wire.TypeA
		if data.Addr.Is4() {
			other = wire.TypeAAAA
		}

		// A host with no address of the other family says so.
		if others := l.with(record.key, other); len(others) > 0 || !record.unique() {
			return others
		}

		return []*owned{l.denial(record.key)}
	default:
		return nil
	}
}

// respond says records to all on the link: as they are, with what goes
// with them, or as a goodbye.
func (l *link) respond(records []*owned, goodbye bool) {
	l.write(records, goodbye, l.say)
}

// respondTo says records to one host alone.
func (l *link) respondTo(records []*owned, dest netip.AddrPort) {
	l.write(records, false, func(message []byte) { _ = l.wire.Unicast(message, dest) })
}

// write writes records as an answer, in as many messages as it takes,
// and hands each to be sent.
func (l *link) write(records []*owned, goodbye bool, send func([]byte)) {
	if len(records) == 0 {
		return
	}

	header := wire.Header{Response: true, Authoritative: true}
	fresh := func() *wire.Builder { return wire.NewBuilder(nil, header, wire.Options{Limit: l.room()}) }
	message := fresh()

	for _, record := range records {
		said := record.record
		if goodbye {
			said.TTL, said.Flush = 0, false
		}

		if !errors.Is(message.Answer(said), wire.ErrFull) {
			continue
		}

		// The message is full: it goes, and the record starts the next.
		if !message.Empty() {
			send(message.Bytes())

			message = fresh()
		}

		if message.Answer(said) != nil {
			l.alone(said, send)
		}
	}

	if message.Empty() {
		return
	}

	// What goes with them, as far as there is room: it is asked for
	// when it is not there.
	if !goodbye {
		for _, record := range l.additional(records) {
			_ = message.Additional(record.record)
		}
	}

	send(message.Bytes())
}

// alone sends a record that fits no message of the link's in one of its
// own, as large as a message can be at all: more than one record in
// what has to be sent in pieces is what RFC 6762 section 17 forbids.
func (l *link) alone(said wire.Record, send func([]byte)) {
	header := wire.Header{Response: true, Authoritative: true}
	message := wire.NewBuilder(nil, header, wire.Options{Limit: transport.MaxPacket - l.headers()})

	if message.Answer(said) == nil {
		send(message.Bytes())
	}
}

// legacy answers a resolver that is not a Multicast DNS one: to it
// alone, as a DNS server would, the question said again, nothing marked
// as this host's alone or to be remembered over ten seconds (6.7).
func (l *link) legacy(arrived arrival, records []*owned) {
	if len(records) == 0 {
		return
	}

	header := wire.Header{
		ID: arrived.message.Header.ID, Response: true, Authoritative: true,
		RecursionDesired: arrived.message.Header.RecursionDesired,
	}
	message := wire.NewBuilder(nil, header, wire.Options{Limit: l.room(), Legacy: true})

	for _, question := range arrived.message.Questions {
		_ = message.Question(question)
	}

	plain := func(record *owned) wire.Record {
		said := record.record
		said.Flush, said.TTL = false, min(said.TTL, legacyTTL)

		return said
	}

	for _, record := range records {
		if errors.Is(message.Answer(plain(record)), wire.ErrFull) {
			message.Truncated()

			break
		}
	}

	for _, record := range l.additional(records) {
		_ = message.Additional(plain(record))
	}

	_ = l.wire.Unicast(message.Bytes(), arrived.from)
}
