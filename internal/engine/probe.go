package engine

import (
	"bytes"
	"cmp"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/transport"
)

// How RFC 6762 section 8 has a host take a name.
const (
	// It asks for the name three times, 250 ms apart, after a wait of up
	// to as long, and takes it 250 ms after the third (8.1).
	probes    = 3
	probeWait = 250 * time.Millisecond
	// A host that loses to another asking at the same moment waits a
	// second and asks again (8.2).
	yield = time.Second
	// Its records are then said, and said again a second later, and two
	// seconds after that (8.3): three times, each twice as far.
	announcements = 3
	// After fifteen conflicts in ten seconds it waits five before it
	// asks again (8.1).
	conflictsMany  = 15
	conflictsIn    = 10 * time.Second
	conflictsPause = 5 * time.Second
)

// claim starts a standing on its link: its names are asked for, if it
// has any that are to be this host's alone, and its records said.
func (e *Engine) claim(stood *standing) {
	e.cancel(stood.timer)
	stood.live, stood.sent = false, 0

	if !slices.ContainsFunc(stood.records, (*owned).unique) {
		e.settle(stood)

		return
	}

	wait := rand.N(probeWait) // #nosec G404 -- a delay, not a secret
	if e.conflicted() {
		wait += conflictsPause
	}

	stood.timer = e.after(wait, func() { e.probe(stood) })
}

// conflicted says whether names were lost too often of late to ask for
// another at once.
func (e *Engine) conflicted() bool {
	e.conflicts = slices.DeleteFunc(e.conflicts, func(at time.Time) bool { return e.now.Sub(at) > conflictsIn })

	return len(e.conflicts) >= conflictsMany
}

// probe asks for a standing's names, or takes them when it has asked
// three times and no one said they had them.
func (e *Engine) probe(stood *standing) {
	if stood.sent == probes {
		e.settle(stood)

		return
	}

	records := make([]wire.Record, len(stood.records))
	for index, record := range stood.records {
		records[index] = record.record
	}

	// What does not fit is left out: a host with more addresses than a
	// message holds still asks for its name.
	messages, _ := claiming(records, stood.link.room(), transport.MaxPacket-stood.link.headers())
	for _, message := range messages {
		stood.link.say(message)
	}

	stood.link.wished = e.now
	stood.sent++
	stood.timer = e.after(probeWait, func() { e.probe(stood) })
}

// claiming is the messages that ask for the names some records are to
// hold alone: for each name a question, and the records meant for it,
// so that another host asking for the same name at the same moment can
// tell which of the two is to yield (RFC 6762 sections 8.1 and 8.2).
// What a host means to say of a name is compared whole, so a name goes
// whole in one message; the names go in as many messages as that takes,
// of room bytes each, and a name that passes room alone in one of its
// own, of most bytes. It says whether every name is whole: one whose
// records pass most is asked for with those that fit.
func claiming(records []wire.Record, room, most int) (messages [][]byte, whole bool) {
	var order []string

	named := map[string][]wire.Record{}

	for _, record := range records {
		if !record.Flush {
			continue
		}

		key := nameKey(record.Name)
		if _, known := named[key]; !known {
			order = append(order, key)
		}

		record.Flush = false
		named[key] = append(named[key], record)
	}

	header, _ := asked(nil, most)
	whole = true

	var together [][]wire.Record

	size := len(header)
	send := func() {
		if len(together) > 0 {
			message, _ := asked(together, most)
			messages = append(messages, message)
			together, size = nil, len(header)
		}
	}

	// What the names of a message share is written once: together they
	// take no more than each alone does.
	for _, key := range order {
		alone, fit := asked([][]wire.Record{named[key]}, most)
		whole = whole && fit

		if size+len(alone)-len(header) > room {
			send()
		}

		together = append(together, named[key])
		size += len(alone) - len(header)
	}

	send()

	return messages, whole
}

// asked is one message that asks for names, each with its records, and
// whether all of it fit in limit bytes.
func asked(names [][]wire.Record, limit int) (message []byte, fit bool) {
	built := wire.NewBuilder(nil, wire.Header{}, wire.Options{Limit: limit})
	fit = true

	for _, name := range names {
		question := wire.Question{Name: name[0].Name, Type: wire.TypeANY, Class: wire.ClassIN, Unicast: true}
		fit = built.Question(question) == nil && fit
	}

	for _, name := range names {
		for _, record := range name {
			fit = built.Authority(record) == nil && fit
		}
	}

	return built.Bytes(), fit
}

// settle makes a standing's records answered for, and says them.
func (e *Engine) settle(stood *standing) {
	stood.live, stood.sent, stood.said = true, 0, 0
	stood.link.denials = nil

	e.announce(stood)
	e.told(stood.pub)
}

// announce says a standing's records to all, now and twice more.
func (e *Engine) announce(stood *standing) {
	e.cancel(stood.timer)

	said := 0

	var again func()

	again = func() {
		stood.link.respond(stood.records, false)

		for _, record := range stood.records {
			record.told = e.now
			delete(stood.link.out, record)
		}

		stood.said++
		stood.heard()

		said++
		if said < announcements {
			stood.timer = e.after(time.Second<<(said-1), again)
		}
	}

	again()
}

// contested takes a record another host said, against what stands on
// the link it was heard on.
//
// local says the record comes from this host itself: another program on
// it. Such a one says where the host is as truly as this one does, and
// what it says of a name that this Engine has no record of the type of
// takes nothing from it: the system's own responder holds the host's
// name too, and is not to be lost a name to for it. What it says in
// place of a record this Engine has, of a service, is a conflict as any
// other host's is.
func (e *Engine) contested(heard *link, record wire.Record, local bool) {
	raw, err := wire.AppendData(nil, record.Data)
	if err != nil {
		return
	}

	key, kind := nameKey(record.Name), record.Type()

	for _, stood := range slices.Clone(heard.standing) {
		// Another host says the same, as one that answers for this one
		// may: no conflict. Should it say so for less than half as long,
		// or goodbye, this host says its own again (6.6).
		if same := slices.IndexFunc(stood.records, func(one *owned) bool { return one.is(key, kind, raw) }); same >= 0 {
			if stood.live && 2*uint64(record.TTL) < uint64(stood.records[same].record.TTL) {
				e.reply(heard, stood.records[same], e.now, false)
			}

			continue
		}

		if record.TTL != 0 {
			e.taken(stood, record, key, local)
		}
	}
}

// taken takes a record another says of a name, that is not one this
// standing has: someone having a name it holds or asks for, or not. A
// goodbye is no one having anything, and never comes here.
func (e *Engine) taken(stood *standing, record wire.Record, key string, local bool) {
	held := func(one *owned) bool { return one.unique() && one.key == key }
	typed := slices.ContainsFunc(
		stood.records,
		func(one *owned) bool { return held(one) && one.record.Type() == record.Type() },
	)

	if _, address := record.Data.(wire.Address); local && (address || !typed) {
		return
	}

	switch {
	case !slices.ContainsFunc(stood.records, held):
		// A name that is not this host's alone: no one having it.
	case !stood.live && stood.sent > 0:
		// While asking: any record of the name is someone having it.
		e.conflicts = append(e.conflicts, e.now)
		e.end(stood.pub, ErrConflict)
	case stood.live && typed:
		// While answering: the name is asked for again, which says
		// which of the two keeps it (section 9).
		e.conflicts = append(e.conflicts, e.now)
		e.claim(stood)
	}
}

// tiebreak takes a question another host asks for a name, with what it
// means to say of it, against a standing that is asking for the same
// name: the one whose records come first yields, and asks again a
// second later (RFC 6762 section 8.2).
func (e *Engine) tiebreak(heard *link, question wire.Question, theirs []wire.Record) {
	key := nameKey(question.Name)
	theirs = slices.DeleteFunc(
		slices.Clone(theirs),
		func(record wire.Record) bool { return nameKey(record.Name) != key },
	)

	// What this Engine asks for itself on another link, heard round a
	// bridge, is no one to yield to.
	if len(theirs) == 0 ||
		!slices.ContainsFunc(theirs, func(record wire.Record) bool { return !e.elsewhere(heard, record) }) {
		return
	}

	for _, stood := range heard.standing {
		if stood.live || stood.sent == 0 {
			continue
		}

		var mine []wire.Record

		for _, record := range stood.records {
			if record.unique() && record.key == key {
				mine = append(mine, record.record)
			}
		}

		if len(mine) > 0 && earlier(mine, theirs) {
			e.cancel(stood.timer)
			stood.sent = 0
			stood.timer = e.after(yield, func() { e.probe(stood) })
		}
	}
}

// earlier says whether one set of records comes before another, as RFC
// 6762 section 8.2.1 orders them: each sorted by class, type and data,
// then compared record by record, the set that runs out first coming
// first.
func earlier(mine, theirs []wire.Record) bool {
	ours, others := ordered(mine), ordered(theirs)

	for index := range min(len(ours), len(others)) {
		if order := compare(ours[index], others[index]); order != 0 {
			return order < 0
		}
	}

	return len(ours) < len(others)
}

// ranked is a record as it is compared: its class, its type, its data.
type ranked struct {
	class uint16
	kind  uint16
	raw   []byte
}

func ordered(records []wire.Record) []ranked {
	sorted := make([]ranked, 0, len(records))

	for _, record := range records {
		raw, err := wire.AppendData(nil, record.Data)
		if err == nil {
			sorted = append(sorted, ranked{class: record.Class, kind: record.Type(), raw: raw})
		}
	}

	slices.SortFunc(sorted, compare)

	return sorted
}

func compare(one, other ranked) int {
	return cmp.Or(
		cmp.Compare(one.class, other.class),
		cmp.Compare(one.kind, other.kind),
		bytes.Compare(one.raw, other.raw),
	)
}

// heard takes note that the standing's link has heard its records, or
// never will: a Publication that waited for it waits no more, and is
// ready when it waits for none.
func (s *standing) heard() {
	if !s.initial {
		return
	}

	s.initial = false
	s.pub.first--

	if s.pub.first == 0 {
		close(s.pub.ready)
	}
}
