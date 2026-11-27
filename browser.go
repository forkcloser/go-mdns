package mdns

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
)

// browser is a Browse under way: the questions it asks, what they have
// brought, and what its handler has been told. All of it is the
// goroutine's that called Browse.
type browser struct {
	query Query
	// kind is the type as a name, and said the type as it is told.
	kind Name
	said string

	// asked is the questions, asked together so that what they bring is
	// told as it stands at one moment; takers is who takes what each
	// brings.
	asked  *engine.Group
	takers map[int]func(engine.Change, engine.Answer)

	// only is the one instance looked for among those its type lists,
	// when there is one.
	only Name

	// instances is the instances heard of, by name, in the order they
	// were; hosts the hosts their services are on.
	instances map[string]*sighting
	order     []string
	hosts     map[string]*whereabouts

	// told is what the handler was told, by instance and host and port,
	// in the order it was.
	told    map[string]Instance
	telling []string
}

// sighting is an instance heard of: where, and what was heard of it.
type sighting struct {
	name  Name
	label string
	// listed is the interfaces its type lists it on; direct says it was
	// asked for by name, and is listed nowhere.
	listed []Interface
	direct bool
	srvs   map[string]engine.Answer
	texts  map[string]engine.Answer
	// asked is the questions asked about it.
	asked []int
}

// whereabouts is a host's addresses, for the services that are on it.
type whereabouts struct {
	users int
	addrs map[string]engine.Answer
	// order is the addresses in the order they were learned, and asked
	// the questions asked for them.
	order []string
	asked []int
}

// asked is what a query asks for, as names: the type, what lists its
// instances, and the one instance when it asks for one.
type asked struct {
	kind     Name
	listing  Name
	instance Name
}

func (q *Query) names() (asked, error) {
	service, proto, err := serviceType(q.Type)
	if err != nil {
		return asked{}, err
	}

	names := asked{kind: Name{service, proto, local}}
	names.listing = names.kind

	if q.Subtype != "" {
		if len(q.Subtype) > maxLabel {
			return asked{}, fmt.Errorf("%w: the subtype %q is not one label", ErrInvalid, q.Subtype)
		}

		names.listing = append(Name{q.Subtype, "_sub"}, names.kind...)
	}

	// Any label: what is looked for is what another host announced, and
	// not every host holds its names to text.
	if q.Name != "" {
		names.instance = append(Name{q.Name}, names.kind...)

		if err = names.instance.Validate(); err != nil {
			return asked{}, err
		}
	}

	return names, nil
}

// search runs a query until ctx ends, telling handle of what it finds.
func (p *Peer) search(ctx context.Context, query Query, handle func(Change, Instance)) error {
	names, err := query.names()
	if err != nil {
		return err
	}

	browsing := &browser{
		query: query, kind: names.kind, said: names.kind[:2].String(),
		asked: p.engine.Group(), takers: map[int]func(engine.Change, engine.Answer){},
		instances: map[string]*sighting{}, hosts: map[string]*whereabouts{}, told: map[string]Instance{},
	}

	defer browsing.asked.Close()

	// An instance looked for by its name is asked for directly. Not when
	// nothing is asked about instances: it is then found as any is, when
	// its type lists it.
	if names.instance != nil && !query.Unresolved {
		browsing.sight(names.instance, nil, true)
	} else {
		browsing.only = names.instance
		browsing.ask(names.listing, wire.TypePTR, browsing.listed)
	}

	for {
		if err = browsing.take(); err != nil {
			return err
		}

		browsing.tell(handle)

		if err = browsing.asked.Wait(ctx); err != nil {
			return translate(err)
		}
	}
}

// take takes everything the questions have to tell, and what the
// questions that leads to already know, before anything is told: an
// instance whose records came together, as they do, is found whole.
func (b *browser) take() error {
	for {
		told, err := b.asked.Poll()
		if err != nil || len(told) == 0 {
			return translate(err)
		}

		for _, one := range told {
			if taker := b.takers[one.Question]; taker != nil {
				taker(one.Change, one.Answer)
			}
		}
	}
}

// ask asks a question, and says who takes what it brings.
func (b *browser) ask(name Name, kind uint16, take func(engine.Change, engine.Answer)) int {
	question, err := b.asked.Add(engine.Question{Name: name, Type: kind, Interfaces: b.query.Interfaces})
	if err != nil {
		return 0
	}

	b.takers[question] = take

	return question
}

// drop asks questions no more.
func (b *browser) drop(questions []int) {
	for _, question := range questions {
		b.asked.Remove(question)
		delete(b.takers, question)
	}
}

// listed takes an instance its type lists, or lists no more.
func (b *browser) listed(change engine.Change, answer engine.Answer) {
	pointer, ok := answer.Record.Data.(wire.Pointer)
	// An instance is one label under the type, and nothing else is.
	if !ok || len(pointer.Target) == 0 || !Name(pointer.Target[1:]).Equal(b.kind) {
		return
	}

	name := Name(pointer.Target)
	if b.only != nil && !name.Equal(b.only) {
		return
	}

	if change == engine.Lost {
		b.unsight(name)

		return
	}

	b.sight(name, answer.Interfaces, false)
}

// sight takes note of an instance, and asks for what is to be known of
// it when it was not known.
func (b *browser) sight(name Name, listed []Interface, direct bool) {
	key := name.key()

	seen := b.instances[key]
	if seen == nil {
		seen = &sighting{
			name: name, label: name[0], direct: direct,
			srvs: map[string]engine.Answer{}, texts: map[string]engine.Answer{},
		}
		b.instances[key] = seen
		b.order = append(b.order, key)

		if !b.query.Unresolved {
			seen.asked = []int{
				b.ask(
					name,
					wire.TypeSRV,
					func(change engine.Change, answer engine.Answer) { b.located(seen, change, answer) },
				),
				b.ask(
					name,
					wire.TypeTXT,
					func(change engine.Change, answer engine.Answer) { keep(seen.texts, change, answer) },
				),
			}
		}
	}

	seen.listed = listed
}

// unsight forgets an instance its type lists no more.
func (b *browser) unsight(name Name) {
	key := name.key()

	seen := b.instances[key]
	if seen == nil {
		return
	}

	b.drop(seen.asked)

	for _, srv := range seen.srvs {
		b.leave(srv)
	}

	delete(b.instances, key)
	b.order = slices.DeleteFunc(b.order, func(one string) bool { return one == key })
}

// keep keeps an answer, or lets it go.
func keep(answers map[string]engine.Answer, change engine.Change, answer engine.Answer) {
	raw, err := wire.AppendData(nil, answer.Record.Data)
	if err != nil {
		return
	}

	if change == engine.Lost {
		delete(answers, string(raw))

		return
	}

	answers[string(raw)] = answer
}

// located takes where an instance is, and asks where that host is when
// it is not known.
func (b *browser) located(seen *sighting, change engine.Change, answer engine.Answer) {
	raw, err := wire.AppendData(nil, answer.Record.Data)
	if err != nil {
		return
	}

	_, known := seen.srvs[string(raw)]
	keep(seen.srvs, change, answer)

	switch {
	case change == engine.Lost && known:
		b.leave(answer)
	case change != engine.Lost && !known:
		b.reach(answer)
	}
}

// reach asks for the addresses of the host a service is on, for one
// more service.
func (b *browser) reach(srv engine.Answer) {
	service, ok := srv.Record.Data.(wire.Service)
	if !ok {
		return
	}

	target := Name(service.Target)
	key := target.key()

	found := b.hosts[key]
	if found == nil {
		found = &whereabouts{addrs: map[string]engine.Answer{}}
		found.asked = []int{b.ask(target, wire.TypeA, found.take), b.ask(target, wire.TypeAAAA, found.take)}
		b.hosts[key] = found
	}

	found.users++
}

// leave gives up the addresses of a host for one service.
func (b *browser) leave(srv engine.Answer) {
	service, ok := srv.Record.Data.(wire.Service)
	if !ok {
		return
	}

	key := Name(service.Target).key()

	found := b.hosts[key]
	if found == nil {
		return
	}

	found.users--

	if found.users == 0 {
		b.drop(found.asked)
		delete(b.hosts, key)
	}
}

// take keeps an address of the host, in the order it was learned, or
// lets it go.
func (w *whereabouts) take(change engine.Change, answer engine.Answer) {
	raw, err := wire.AppendData(nil, answer.Record.Data)
	if err != nil {
		return
	}

	keep(w.addrs, change, answer)

	switch known := slices.Contains(w.order, string(raw)); {
	case change == engine.Lost:
		w.order = slices.DeleteFunc(w.order, func(one string) bool { return one == string(raw) })
	case !known:
		w.order = append(w.order, string(raw))
	}
}

// tell tells the handler what there is to tell since it was last told:
// where things stand, not every step.
func (b *browser) tell(handle func(Change, Instance)) {
	stand, order := b.stand()
	kept := b.telling[:0]

	for _, ident := range b.telling {
		before := b.told[ident]
		now, known := stand[ident]

		switch {
		case !known:
			handle(Lost, before)
			delete(b.told, ident)

			continue
		case !sameInstance(before, now):
			handle(Changed, now)
		}

		b.told[ident] = now
		kept = append(kept, ident)
	}

	b.telling = kept

	for _, ident := range order {
		if _, told := b.told[ident]; !told {
			handle(Found, stand[ident])
			b.told[ident] = stand[ident]
			b.telling = append(b.telling, ident)
		}
	}
}

// stand is the instances as they stand now, and the order they are to
// be told in.
func (b *browser) stand() (map[string]Instance, []string) {
	stand := map[string]Instance{}

	var order []string

	for _, key := range b.order {
		seen := b.instances[key]
		if seen == nil {
			continue
		}

		if b.query.Unresolved {
			stand[key] = Instance{Name: seen.label, Type: b.said, Interfaces: seen.listed}
			order = append(order, key)

			continue
		}

		for _, raw := range sortedKeys(seen.srvs) {
			if found, ok := b.resolved(seen, seen.srvs[raw]); ok {
				stand[key+raw] = found
				order = append(order, key+raw)
			}
		}
	}

	return stand, order
}

// resolved is an instance as it is told, from where it is and what is
// known of it; and no instance while its text is not known.
func (b *browser) resolved(seen *sighting, srv engine.Answer) (Instance, bool) {
	service, ok := srv.Record.Data.(wire.Service)
	if !ok {
		return Instance{}, false
	}

	// It is where it says it is, on the interfaces its type lists it
	// on: what is heard of an instance elsewhere is another's.
	interfaces := srv.Interfaces
	if !seen.direct {
		interfaces = slices.DeleteFunc(
			slices.Clone(interfaces),
			func(one Interface) bool { return !slices.Contains(seen.listed, one) },
		)
	}

	text, ok := heardOn(seen.texts, interfaces)
	if !ok {
		return Instance{}, false
	}

	found := Instance{
		Name: seen.label, Type: b.said, Interfaces: interfaces,
		Host: Name(service.Target).String(), Port: service.Port, Priority: service.Priority, Weight: service.Weight,
	}

	if said, isText := text.Record.Data.(wire.Text); isText {
		found.Text = textOf(said)
	}

	if host := b.hosts[Name(service.Target).key()]; host != nil {
		found.Addrs = host.reached(interfaces)
	}

	return found, true
}

// heardOn is the first of some answers, in the order of their data,
// that is heard on one of some interfaces.
func heardOn(answers map[string]engine.Answer, interfaces []Interface) (engine.Answer, bool) {
	for _, raw := range sortedKeys(answers) {
		if slices.ContainsFunc(
			answers[raw].Interfaces,
			func(one Interface) bool { return slices.Contains(interfaces, one) },
		) {
			return answers[raw], true
		}
	}

	return engine.Answer{}, false
}

// reached is a host's addresses by some interfaces, or by any when none
// is given, each once, in the order they were learned. An IPv6
// link-local address is one for each interface it is heard on, and
// carries which as its zone.
func (w *whereabouts) reached(interfaces []Interface) []netip.Addr {
	var addrs []netip.Addr

	for _, raw := range w.order {
		answer := w.addrs[raw]

		data, ok := answer.Record.Data.(wire.Address)
		if !ok {
			continue
		}

		for _, via := range answer.Interfaces {
			if addr := zoned(
				data.Addr,
				via,
			); (interfaces == nil || slices.Contains(interfaces, via)) &&
				!slices.Contains(addrs, addr) {
				addrs = append(addrs, addr)
			}
		}
	}

	return addrs
}

// zoned is an address as it is good on an interface: an IPv6 link-local
// one with the interface as its zone, any other as it is.
func zoned(addr netip.Addr, via Interface) netip.Addr {
	if addr.Is6() && addr.IsLinkLocalUnicast() {
		return addr.WithZone(via.Name)
	}

	return addr
}

func sortedKeys(answers map[string]engine.Answer) []string {
	keys := make([]string, 0, len(answers))
	for key := range answers {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}

// sameInstance says whether two instances are told the same.
func sameInstance(one, other Instance) bool {
	return one.Name == other.Name && one.Type == other.Type && one.Host == other.Host && one.Port == other.Port &&
		one.Priority == other.Priority && one.Weight == other.Weight &&
		slices.Equal(one.Interfaces, other.Interfaces) && slices.Equal(one.Addrs, other.Addrs) &&
		slices.EqualFunc(one.Text, other.Text, func(mine, theirs Entry) bool {
			return mine.Key == theirs.Key && (mine.Value == nil) == (theirs.Value == nil) &&
				bytes.Equal(mine.Value, theirs.Value)
		})
}
