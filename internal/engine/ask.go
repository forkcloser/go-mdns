package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/transport"
)

// Question is what is asked: the records of a type that a name has.
type Question struct {
	Name []string
	// Type is the type, or wire.TypeANY.
	Type uint16
	// Interfaces says which interfaces to ask on. Nil is all of them.
	Interfaces func(transport.Interface) bool
}

// Answer is a record that answers a question, and the interfaces it is
// heard on, in the order of their indexes.
type Answer struct {
	Record     wire.Record
	Interfaces []transport.Interface
}

// Change is what happened to an answer.
type Change uint8

// The changes.
const (
	// Found: it was not known, and is.
	Found Change = iota + 1
	// Changed: the interfaces it is heard on are no longer what they
	// were.
	Changed
	// Lost: it is heard on none.
	Lost
)

// How RFC 6762 section 5.2 has a question asked again and again.
const (
	// The first time after a short while, so that hosts that ask at one
	// signal do not all ask at once.
	firstLeast = 20 * time.Millisecond
	firstMost  = 120 * time.Millisecond
	// Then a second later, and after twice as long each time, up to an
	// hour.
	askAgain = time.Second
	askMost  = time.Hour
	// classANY is the class of a question for records of any class.
	classANY = 255
)

// askKey is what makes two questions the same.
type askKey struct {
	name string
	kind uint16
}

// asking is a question being asked, for everyone who asks it.
type asking struct {
	key      askKey
	question wire.Question
	watchers []*watcher
	// paces is when it is next asked, on each link it is asked on.
	paces map[*link]*pace
}

// pace is a question's schedule on a link.
type pace struct {
	timer *timer
	// wait is how long after the next time it is asked the one after
	// comes.
	wait time.Duration
	// alone asks for an answer to this host alone, the first time.
	alone bool
	// idle is a question that has its answer and is not asked, until it
	// has not.
	idle bool
}

// watcher is one Ask under way.
type watcher struct {
	asking     *asking
	interfaces func(transport.Interface) bool
	// told is what its handler has been told, and order the order it
	// was told in.
	told  map[string]Answer
	order []string
	// dirty has something in it when there may be more to tell.
	dirty chan struct{}
}

func (a *asking) wants(iface transport.Interface) bool {
	return slices.ContainsFunc(a.watchers, func(one *watcher) bool {
		return one.interfaces == nil || one.interfaces(iface)
	})
}

// tell lets everyone who asks know that there may be more to tell.
func (a *asking) tell() {
	for _, one := range a.watchers {
		select {
		case one.dirty <- struct{}{}:
		default:
		}
	}
}

// Ask tells handle of the records that answer a question: first those
// already known, each as found, and then each as it is found, changes
// or is lost, until ctx ends. Calls come one at a time, on the
// goroutine that called Ask. It returns ctx's error, ErrClosed from an
// Engine that is closed, and ErrInvalid for a name that is not one.
func (e *Engine) Ask(ctx context.Context, question Question, handle func(Change, Answer)) error {
	asked := wire.Question{Name: question.Name, Type: question.Type, Class: wire.ClassIN}
	if len(question.Name) == 0 || wire.NewBuilder(nil, wire.Header{}, wire.Options{}).Question(asked) != nil {
		return fmt.Errorf("%w: a question for %q", ErrInvalid, question.Name)
	}

	watching := &watcher{interfaces: question.Interfaces, told: map[string]Answer{}, dirty: make(chan struct{}, 1)}

	if err := e.do(func() { e.watch(watching, asked) }); err != nil {
		return err
	}

	defer func() { _ = e.do(func() { e.unwatch(watching) }) }()

	for {
		var news []news

		if err := e.do(func() { news = e.news(watching) }); err != nil {
			return err
		}

		for _, one := range news {
			handle(one.change, one.answer)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("asking: %w", context.Cause(ctx))
		case <-e.done:
			return ErrClosed
		case <-watching.dirty:
		}
	}
}

// Group is questions asked together, for one who puts what they bring
// together: what several questions have to tell is told at once, as it
// stands at one moment, and not one question after another. It is one
// goroutine's to use.
type Group struct {
	engine *Engine
	dirty  chan struct{}
	// What follows is the loop's.
	watchers map[int]*watcher
	last     int
}

// Told is what a question of a Group has to tell.
type Told struct {
	// Question is the question, as Add numbered it.
	Question int
	Change   Change
	Answer   Answer
}

// Group makes a Group with no question in it.
func (e *Engine) Group() *Group {
	return &Group{engine: e, dirty: make(chan struct{}, 1), watchers: map[int]*watcher{}}
}

// Add asks one more question, and gives it a number. What is already
// known of it is told by the next Poll.
func (g *Group) Add(question Question) (int, error) {
	asked := wire.Question{Name: question.Name, Type: question.Type, Class: wire.ClassIN}
	if len(question.Name) == 0 || wire.NewBuilder(nil, wire.Header{}, wire.Options{}).Question(asked) != nil {
		return 0, fmt.Errorf("%w: a question for %q", ErrInvalid, question.Name)
	}

	number := 0

	err := g.engine.do(func() {
		g.last++
		number = g.last
		g.watchers[number] = &watcher{interfaces: question.Interfaces, told: map[string]Answer{}, dirty: g.dirty}
		g.engine.watch(g.watchers[number], asked)

		// What is already known of it is something to tell: whoever
		// waits is not to wait for the next thing heard.
		select {
		case g.dirty <- struct{}{}:
		default:
		}
	})

	return number, err
}

// Remove asks a question no more. Nothing more is told of it.
func (g *Group) Remove(question int) {
	_ = g.engine.do(func() {
		if watching := g.watchers[question]; watching != nil {
			g.engine.unwatch(watching)
			delete(g.watchers, question)
		}
	})
}

// Close asks none of the questions any more.
func (g *Group) Close() {
	_ = g.engine.do(func() {
		for question, watching := range g.watchers {
			g.engine.unwatch(watching)
			delete(g.watchers, question)
		}
	})
}

// Poll is what the questions have to tell since the last Poll, as they
// all stand at one moment, in the order they were added. It is nothing
// when nothing changed.
func (g *Group) Poll() ([]Told, error) {
	var told []Told

	err := g.engine.do(func() {
		questions := make([]int, 0, len(g.watchers))
		for question := range g.watchers {
			questions = append(questions, question)
		}

		slices.Sort(questions)

		for _, question := range questions {
			for _, one := range g.engine.news(g.watchers[question]) {
				told = append(told, Told{Question: question, Change: one.change, Answer: one.answer})
			}
		}
	})

	return told, err
}

// Wait waits until a Poll may have something to tell, and returns ctx's
// error when ctx ends first, ErrClosed when the Engine does.
func (g *Group) Wait(ctx context.Context) error {
	select {
	case <-g.dirty:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for answers: %w", context.Cause(ctx))
	case <-g.engine.done:
		return ErrClosed
	}
}

// watch adds someone who asks to a question, and starts asking it where
// it was not asked.
func (e *Engine) watch(watching *watcher, question wire.Question) {
	key := askKey{name: nameKey(question.Name), kind: question.Type}

	asked := e.asked[key]
	if asked == nil {
		asked = &asking{key: key, question: question, paces: map[*link]*pace{}}
		e.asked[key] = asked
		e.named[key.name] = append(e.named[key.name], asked)
	}

	watching.asking = asked
	asked.watchers = append(asked.watchers, watching)

	for _, via := range e.links {
		if asked.paces[via] == nil && asked.wants(via.iface) {
			e.pace(asked, via, false)
		}
	}

	// What was heard and not looked for is looked for now: its times to
	// be asked about are to be counted from here.
	e.soon(e.now)
}

// unwatch takes someone who asks from a question, which is asked no
// more where no one is left to ask it.
func (e *Engine) unwatch(watching *watcher) {
	asked := watching.asking
	asked.watchers = slices.DeleteFunc(asked.watchers, func(one *watcher) bool { return one == watching })

	for via, paced := range asked.paces {
		if !asked.wants(via.iface) {
			e.cancel(paced.timer)
			delete(asked.paces, via)
		}
	}

	if len(asked.watchers) > 0 {
		return
	}

	delete(e.asked, asked.key)

	e.named[asked.key.name] = slices.DeleteFunc(e.named[asked.key.name], func(one *asking) bool { return one == asked })
	if len(e.named[asked.key.name]) == 0 {
		delete(e.named, asked.key.name)
	}
}

// pace starts asking a question on a link.
func (e *Engine) pace(asked *asking, via *link, alone bool) {
	paced := &pace{wait: askAgain, alone: alone}
	asked.paces[via] = paced

	paced.timer = e.after(
		firstLeast+rand.N(firstMost-firstLeast),
		func() { e.due(asked, via) },
	) // #nosec G404 -- a delay, not a secret
}

// due asks a question on a link, its time having come, unless it has
// its answer: RFC 6762 section 5.2 has a question whose one holder
// answered asked only to keep the answer.
func (e *Engine) due(asked *asking, via *link) {
	paced := asked.paces[via]
	if paced == nil {
		return
	}

	paced.timer = nil

	if e.complete(asked, via) {
		paced.idle = true

		return
	}

	question := asked.question
	question.Unicast, paced.alone = paced.alone, false

	e.enqueue(via, question)

	paced.timer = e.after(paced.wait, func() { e.due(asked, via) })
	paced.wait = min(2*paced.wait, askMost)
}

// complete says whether a link has heard all there is to hear of a
// question: a record that is its holder's alone, or that its name has
// no record of the type.
func (e *Engine) complete(asked *asking, via *link) bool {
	if asked.key.kind == wire.TypeANY {
		return false
	}

	for _, one := range via.lookup(asked.key.name, asked.key.kind, e.now) {
		if one.record.Flush {
			return true
		}
	}

	for _, one := range via.lookup(asked.key.name, wire.TypeNSEC, e.now) {
		if denial, ok := one.record.Data.(wire.NSEC); ok && one.record.Flush &&
			!slices.Contains(denial.Types, asked.key.kind) {
			return true
		}
	}

	return false
}

// interested says whether anyone asks, on a link, for records of a name
// and a type.
func (e *Engine) interested(via *link, key string, kind uint16) bool {
	return slices.ContainsFunc(e.named[key], func(asked *asking) bool {
		return (asked.key.kind == kind || asked.key.kind == wire.TypeANY) && asked.paces[via] != nil
	})
}

// touched takes note that what a link has heard of a name is no longer
// what it was: those who ask are told, and a question that had its
// answer and has it no more is asked again.
func (e *Engine) touched(via *link, key string) {
	for _, asked := range e.named[key] {
		asked.tell()

		if paced := asked.paces[via]; paced != nil && paced.idle && !e.complete(asked, via) {
			e.pace(asked, via, false)
		}
	}
}

// news is a change to tell someone who asks.
type news struct {
	change Change
	answer Answer
}

// news is what there is to tell someone who asks, since they were last
// told: where things stand, not every step they took to get there.
func (e *Engine) news(watching *watcher) []news {
	stand, order := e.stand(watching)

	var changes []news

	kept := watching.order[:0]

	for _, ident := range watching.order {
		before, now := watching.told[ident], stand[ident]

		switch {
		case now.Interfaces == nil:
			changes = append(changes, news{change: Lost, answer: before})

			delete(watching.told, ident)

			continue
		case !slices.Equal(before.Interfaces, now.Interfaces):
			changes = append(changes, news{change: Changed, answer: now})
		}

		watching.told[ident] = now
		kept = append(kept, ident)
	}

	watching.order = kept

	for _, ident := range order {
		if _, told := watching.told[ident]; !told {
			changes = append(changes, news{change: Found, answer: stand[ident]})
			watching.told[ident] = stand[ident]
			watching.order = append(watching.order, ident)
		}
	}

	return changes
}

// stand is the answers to what someone asks as they stand now, each
// with the interfaces it is heard on, and the order they are to be told
// in.
func (e *Engine) stand(watching *watcher) (map[string]Answer, []string) {
	stand := map[string]Answer{}

	var order []string

	for _, via := range e.sorted() {
		if watching.interfaces != nil && !watching.interfaces(via.iface) {
			continue
		}

		for _, one := range e.answers(via, watching.asking) {
			// The type as its two bytes: as a character, the types from
			// 0xD800 to 0xDFFF would all be the same one.
			ident := string(binary.BigEndian.AppendUint16(nil, one.record.Type())) + string(one.raw)

			answer, known := stand[ident]
			if !known {
				answer.Record = one.record

				order = append(order, ident)
			}

			if !slices.Contains(answer.Interfaces, via.iface) {
				answer.Interfaces = append(answer.Interfaces, via.iface)
			}

			stand[ident] = answer
		}
	}

	return stand, order
}

// answers is what answers a question on a link: what was heard there,
// and what this host answers for itself.
func (e *Engine) answers(via *link, asked *asking) []*entry {
	found := via.lookup(asked.key.name, asked.key.kind, e.now)

	for _, mine := range via.matching(asked.question) {
		// The word that a name has no record of a type is no record.
		if via.denials[mine.key] != mine {
			found = append(found, &entry{record: mine.record, raw: mine.raw})
		}
	}

	return found
}

// enqueue puts a question in the next message a link sends, which goes as
// soon as everything due now has been looked at: questions that come
// due together go together.
func (e *Engine) enqueue(via *link, question wire.Question) {
	same := func(one wire.Question) bool {
		return one.Type == question.Type && nameKey(one.Name) == nameKey(question.Name)
	}

	if slices.ContainsFunc(via.asking, same) {
		return
	}

	via.asking = append(via.asking, question)

	if via.send == nil {
		via.send = e.after(0, func() { e.send(via) })
	}
}

// The headers a message travels under, which count against what a link
// carries.
const (
	ipv4Headers = 28
	ipv6Headers = 48
	usualMTU    = 1500
)

// room is how large a message may be on a link.
func (l *link) room() int {
	mtu := l.wire.MTU()
	if mtu <= 0 {
		mtu = usualMTU
	}

	if l.family == transport.IPv6 {
		return mtu - ipv6Headers
	}

	return mtu - ipv4Headers
}

// headers is how many bytes of headers a message travels under on the
// link.
func (l *link) headers() int {
	if l.family == transport.IPv6 {
		return ipv6Headers
	}

	return ipv4Headers
}

// send sends the questions a link has to ask, with what it already knows
// of their answers, so that it is not told again (RFC 6762 section 7.1).
// What it knows that does not fit follows in messages of its own, the
// one before marked as cut short (section 7.2).
func (e *Engine) send(via *link) {
	via.send = nil
	questions := via.asking
	via.asking = nil

	for len(questions) > 0 {
		message := wire.NewBuilder(nil, wire.Header{}, wire.Options{Limit: via.room()})

		var known []wire.Record

		for len(questions) > 0 && message.Question(questions[0]) == nil {
			if questions[0].Unicast {
				via.wished = e.now
			}

			known = append(known, e.known(via, questions[0])...)
			questions = questions[1:]
		}

		// A question that fits no message is one that cannot be asked.
		if message.Empty() {
			questions = questions[1:]

			continue
		}

		via.say(via.sayKnown(message, known).Bytes())
	}
}

// sayKnown adds what is known to a message of questions, and sends the
// message and starts another each time one is full. It returns the
// last, which is not sent yet and is not empty.
func (l *link) sayKnown(message *wire.Builder, known []wire.Record) *wire.Builder {
	for _, record := range known {
		if !errors.Is(message.Answer(record), wire.ErrFull) {
			continue
		}

		following := wire.NewBuilder(nil, wire.Header{}, wire.Options{Limit: l.room()})

		// A record that fits no message is left out of what is known,
		// and is answered again: nothing worse.
		if following.Answer(record) != nil {
			continue
		}

		message.Truncated()
		l.say(message.Bytes())

		message = following
	}

	return message
}

// say sends a message to everyone on the link. One that cannot be sent
// is one that was lost, which the protocol expects of any.
func (l *link) say(message []byte) {
	err := l.wire.Multicast(message)

	// Said once for a link that goes on refusing: a host that cannot
	// speak at all should know, and not in every line of its log.
	if (err != nil) != l.refused {
		l.refused = err != nil

		if err != nil {
			slog.Warn("a link refuses what is said on it", "interface", l.iface.Name, "error", err)
		}
	}
}

// known is what a link has heard that answers a question and has more
// than half its life left: a record with less is answered again
// anyway. A record in doubt is left out, so that whoever has it says
// so.
func (e *Engine) known(via *link, question wire.Question) []wire.Record {
	var known []wire.Record

	for _, one := range via.lookup(nameKey(question.Name), question.Type, e.now) {
		left := one.expires.Sub(e.now)
		if 2*left <= one.life || !one.doubted.IsZero() {
			continue
		}

		record := one.record
		record.Flush = false
		record.TTL = uint32(left / time.Second) // #nosec G115 -- at most a week of seconds

		known = append(known, record)
	}

	return known
}

// overheard takes a question another host asked: its own questions are
// then not asked again when they would say the same (RFC 6762 section
// 7.3), and what it has heard that should have been answered and is
// not comes into doubt (section 10.5).
func (e *Engine) overheard(heard *link, arrived arrival) {
	// A question cut short has more to say of what its asker knows, in a
	// message this one cannot be read without; one that is not said to
	// all, or not from port 5353, is not the kind others answer to all.
	if arrived.message.Header.Truncated || !arrived.group || arrived.from.Port() != transport.Port {
		return
	}

	for _, question := range arrived.message.Questions {
		if question.Unicast || question.Class != wire.ClassIN && question.Class != classANY {
			continue
		}

		key := askKey{name: nameKey(question.Name), kind: question.Type}
		e.asKnown(heard, key, arrived.message.Answers)
		e.missing(heard, key, arrived.message.Answers)
	}
}

// asKnown counts a question of our own as asked when another host has
// just asked it, saying to know nothing we would not say we know.
func (e *Engine) asKnown(heard *link, key askKey, theirs []wire.Record) {
	asked := e.asked[key]
	if asked == nil || asked.paces[heard] == nil || asked.paces[heard].timer == nil {
		return
	}

	ours := e.known(heard, asked.question)

	for _, record := range theirs {
		if nameKey(record.Name) != key.name || key.kind != wire.TypeANY && record.Type() != key.kind {
			continue
		}

		if !slices.ContainsFunc(ours, func(one wire.Record) bool { return same(one, record) }) {
			return
		}
	}

	paced := asked.paces[heard]
	e.cancel(paced.timer)

	paced.alone = false
	paced.timer = e.after(paced.wait, func() { e.due(asked, heard) })
	paced.wait = min(2*paced.wait, askMost)
}

// missing counts, against each record a link has heard that answers a
// question of another host and that the asker does not say it knows,
// one question it should be answered to. Two of them and ten seconds
// with no answer, and the record is forgotten.
func (e *Engine) missing(heard *link, key askKey, theirs []wire.Record) {
	for _, one := range heard.lookup(key.name, key.kind, e.now) {
		if slices.ContainsFunc(theirs, func(record wire.Record) bool { return same(one.record, record) }) {
			continue
		}

		if one.missed == 0 || e.now.Sub(one.since) > doubt {
			one.missed, one.since = 0, e.now
		}

		one.missed++

		if one.missed >= unanswered {
			e.soon(one.since.Add(doubt))
		}
	}
}

// same says whether two records are one: the name, the type and the
// data.
func same(one, other wire.Record) bool {
	if one.Type() != other.Type() || nameKey(one.Name) != nameKey(other.Name) {
		return false
	}

	mine, err := wire.AppendData(nil, one.Data)
	theirs, other2 := wire.AppendData(nil, other.Data)

	return err == nil && other2 == nil && bytes.Equal(mine, theirs)
}
