package engine

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/forkcloser/go-mdns/internal/wire"
)

// What RFC 6762 has a cache do, and when.
const (
	// A record said goodbye to, or replaced, is kept this long: time for
	// another host that has it to say so (sections 10.1 and 10.2).
	grace = time.Second
	// A record that is still looked for is asked about again at 80% of
	// its life, and three more times 5% apart, each up to 2% late
	// (section 5.2).
	refreshFirst = 80
	refreshStep  = 5
	refreshes    = 4
	refreshLate  = 2
	percent      = 100
	// A record in doubt is forgotten when no one confirms it this long
	// (sections 10.4 and 10.5), after two questions went unanswered.
	doubt        = 10 * time.Second
	unanswered   = 2
	reconfirmTwo = time.Second
	// maxLife is the longest a record is remembered, whatever it says:
	// more is no lifetime Multicast DNS has a use for.
	maxLife = 7 * 24 * time.Hour
	// maxCached is how many records are remembered on a link that no one
	// asks about: a neighbour cannot make a host remember without end.
	maxCached = 4096
	// maxHeld is how many are remembered on a link at all, asked about
	// or not: what is browsed for is a neighbour's to fill as well.
	maxHeld = 4 * maxCached
)

// entry is a record heard on a link.
type entry struct {
	record wire.Record
	// raw is its data with no name compressed: what tells it from
	// another record of its name and type.
	raw []byte
	// heard is when it was last said, life for how long it was said to
	// last then, and expires when it is forgotten.
	heard   time.Time
	life    time.Duration
	expires time.Time
	// late is how late its refreshes are, and asked how many were sent.
	late  time.Duration
	asked int
	// missed is how many questions of other hosts should have brought
	// it and did not, since when.
	missed int
	since  time.Time
	// doubted is when it is forgotten for want of a confirmation, when
	// it was said not to be true.
	doubted time.Time
}

// refresh is when the record is next asked about, if it is looked for.
func (n *entry) refresh() (time.Time, bool) {
	if n.asked >= refreshes {
		return time.Time{}, false
	}

	return n.heard.Add(n.life*time.Duration(refreshFirst+refreshStep*n.asked)/percent + n.late), true
}

// gone is when the record is forgotten whatever happens, and whether
// that time has come.
func (n *entry) gone(now time.Time) (time.Time, bool) {
	when := n.expires
	if !n.doubted.IsZero() && n.doubted.Before(when) {
		when = n.doubted
	}

	if lost := n.since.Add(doubt); n.missed >= unanswered && lost.Before(when) {
		when = lost
	}

	return when, !now.Before(when)
}

// alive says whether the record can still be told of.
func (n *entry) alive(now time.Time) bool {
	_, gone := n.gone(now)

	return !gone
}

// learn takes a record a link heard in an answer.
func (e *Engine) learn(heard *link, record wire.Record) {
	raw, err := wire.AppendData(nil, record.Data)
	if err != nil {
		return
	}

	key, kind := nameKey(record.Name), record.Type()
	set := heard.cache[key][kind]
	known := slices.IndexFunc(set, func(one *entry) bool { return bytes.Equal(one.raw, raw) })

	// A goodbye: what is known goes in a second, and nothing is learned.
	if record.TTL == 0 {
		if known >= 0 {
			e.shorten(set[known])
		}

		return
	}

	// The record is its holder's alone: what else was heard of its name
	// and type more than a second ago goes with it.
	for index, other := range set {
		if record.Flush && index != known && e.now.Sub(other.heard) > grace {
			e.shorten(other)
		}
	}

	life := min(time.Duration(record.TTL)*time.Second, maxLife)

	var fresh *entry

	switch {
	case known >= 0:
		fresh = set[known]
	case heard.cached >= maxCached && !e.interested(heard, key, kind), heard.cached >= maxHeld:
		return
	default:
		fresh = &entry{raw: raw, late: rand.N(life*refreshLate/percent + 1)} // #nosec G404 -- a delay, not a secret

		if heard.cache[key] == nil {
			heard.cache[key] = map[uint16][]*entry{}
		}

		heard.cache[key][kind] = append(set, fresh)
		heard.cached++

		defer e.touched(heard, key)
	}

	fresh.record, fresh.heard, fresh.life, fresh.expires = record, e.now, life, e.now.Add(life)
	fresh.asked, fresh.missed, fresh.doubted = 0, 0, time.Time{}

	e.soon(fresh.next(e.now, e.interested(heard, key, kind)))
}

// shorten leaves a record a second to live, if it had more.
func (e *Engine) shorten(short *entry) {
	if last := e.now.Add(grace); last.Before(short.expires) {
		short.expires = last
		e.soon(last)
	}
}

// next is when the record next needs looking at: when it is forgotten,
// or sooner when it is looked for and to be asked about again. A record
// no one looks for wakes no one until it goes.
func (n *entry) next(now time.Time, wanted bool) time.Time {
	when, _ := n.gone(now)
	if at, more := n.refresh(); wanted && more && at.Before(when) {
		return at
	}

	return when
}

// soon makes sure the cache is looked at by a time.
func (e *Engine) soon(when time.Time) {
	if e.sweep != nil && e.sweep.index >= 0 && !when.Before(e.sweep.at) {
		return
	}

	e.cancel(e.sweep)
	e.sweep = e.at(when, e.swept)
}

// swept looks at every record: forgets those whose time has come, asks
// again about those that are looked for and getting old, and says when
// to look next.
func (e *Engine) swept() {
	e.sweep = nil

	var next time.Time

	for _, heard := range e.links {
		for key, kinds := range heard.cache {
			lost := 0

			for kind := range kinds {
				forgot, at := e.sweepSet(heard, key, kinds, kind)
				lost, next = lost+forgot, sooner(next, at)
			}

			if len(kinds) == 0 {
				delete(heard.cache, key)
			}

			if heard.cached -= lost; lost > 0 {
				e.touched(heard, key)
			}
		}
	}

	if !next.IsZero() {
		e.soon(next)
	}
}

// sooner is the sooner of two times, no time being later than any.
func sooner(one, other time.Time) time.Time {
	if one.IsZero() || !other.IsZero() && other.Before(one) {
		return other
	}

	return one
}

// sweepSet looks at the records of a name, of one type. It says how many
// it forgot, and when those it kept next need looking at: no time, when
// it kept none.
func (e *Engine) sweepSet(heard *link, key string, kinds map[uint16][]*entry, kind uint16) (int, time.Time) {
	set := kinds[kind]
	kept := slices.DeleteFunc(set, func(one *entry) bool { return !one.alive(e.now) })

	if kinds[kind] = kept; len(kept) == 0 {
		delete(kinds, kind)
	}

	var next time.Time

	wanted := e.interested(heard, key, kind)

	for _, one := range kept {
		if wanted {
			e.refresh(heard, one)
		}

		next = sooner(next, one.next(e.now, wanted))
	}

	return len(set) - len(kept), next
}

// refresh asks again about a record that is looked for, when its time
// to be asked about has come: once, however many of its times have.
func (e *Engine) refresh(heard *link, old *entry) {
	due := false

	for at, more := old.refresh(); more && !e.now.Before(at); at, more = old.refresh() {
		old.asked++
		due = true
	}

	if due {
		e.enqueue(heard, wire.Question{Name: old.record.Name, Type: old.record.Type(), Class: wire.ClassIN})
	}
}

// lookup is the records a link has heard that answer a question, and
// that can still be told of.
func (l *link) lookup(key string, kind uint16, now time.Time) []*entry {
	var found []*entry

	for held, set := range l.cache[key] {
		if kind != wire.TypeANY && kind != held {
			continue
		}

		for _, one := range set {
			if one.alive(now) {
				found = append(found, one)
			}
		}
	}

	// A map has no order, and what is told of has to have one.
	slices.SortFunc(found, func(one, other *entry) int {
		if one.record.Type() != other.record.Type() {
			return int(one.record.Type()) - int(other.record.Type())
		}

		return bytes.Compare(one.raw, other.raw)
	})

	return found
}

// Reconfirm says that a record was acted on and was wrong. It is asked
// about again on every link that heard it, and forgotten where no one
// confirms it within ten seconds.
func (e *Engine) Reconfirm(record wire.Record) error {
	raw, err := wire.AppendData(nil, record.Data)
	if err != nil {
		return ErrInvalid
	}

	return e.do(func() {
		for _, heard := range e.links {
			for _, one := range heard.cache[nameKey(record.Name)][record.Type()] {
				// A text record is its name's one: whichever was heard is
				// the one doubted, as what a program read of it need not
				// be every byte it had.
				if (bytes.Equal(one.raw, raw) || record.Type() == wire.TypeTXT) && one.doubted.IsZero() {
					e.doubt(heard, one)
				}
			}
		}
	})
}

// doubt gives a record ten seconds to be confirmed, and asks about it:
// twice, as RFC 6762 section 10.4 has it, and once more.
func (e *Engine) doubt(heard *link, doubted *entry) {
	doubted.doubted = e.now.Add(doubt)
	e.soon(doubted.doubted)

	question := wire.Question{Name: doubted.record.Name, Type: doubted.record.Type(), Class: wire.ClassIN}

	for _, wait := range []time.Duration{0, reconfirmTwo, reconfirmTwo * (unanswered + 1)} {
		e.after(wait, func() {
			if e.links[heard.wire] == heard && !doubted.doubted.IsZero() {
				e.enqueue(heard, question)
			}
		})
	}
}
