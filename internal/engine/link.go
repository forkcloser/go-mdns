package engine

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/transport"
)

// link is one link the Engine is on, and what it has heard there.
type link struct {
	wire   transport.Link
	iface  transport.Interface
	family transport.Family
	addrs  []netip.Prefix

	// cache is what was heard, by name and then by type.
	cache  map[string]map[uint16][]*entry
	cached int

	// asking is the questions to go out in the next message, and send
	// the timer that sends it.
	asking []wire.Question
	send   *timer
	// wished is when an answer of our own was last asked for: one sent
	// to this host alone is taken for two seconds after.
	wished time.Time

	// standing is what is published on the link; out the records it has
	// to say to all and when, and replying the timer that says them;
	// held what waits for the rest of a question cut short, by who asked
	// it; denials the records that say which types its names have.
	standing []*standing
	out      map[*owned]time.Time
	replying *timer
	held     map[netip.Addr]*held
	denials  map[string]*owned
}

// linked takes a link that came up, changed or went down.
func (e *Engine) linked(event transport.Event) {
	known := e.links[event.Link]

	switch {
	case event.Change == transport.Up && known == nil:
		e.up(event.Link)
	case event.Change == transport.Changed && known != nil:
		known.addrs = event.Link.Addrs()
		e.readdress(known.iface)
	case event.Change == transport.Down && known != nil:
		e.down(known)
	}
}

func (e *Engine) up(arrived transport.Link) {
	iface, family := arrived.Interface(), arrived.Family()

	if e.cfg.Families != 0 && e.cfg.Families&family == 0 || e.cfg.Interfaces != nil && !e.cfg.Interfaces(iface) {
		_ = arrived.Close()

		return
	}

	added := &link{
		wire:   arrived,
		iface:  iface,
		family: family,
		addrs:  arrived.Addrs(),
		cache:  map[string]map[uint16][]*entry{},
	}
	e.links[arrived] = added

	e.running.Go(func() { e.read(arrived) })

	// What is published is published here too, and the interface's
	// other links learn of the addresses this one brings.
	for _, published := range e.pubs {
		if published.wants(iface) {
			e.raise(published, added, false)
		}
	}

	e.readdress(iface)

	// What was already asked is asked here too, and may be answered to
	// this host alone: it has just come, and the link has heard it all
	// before.
	for _, question := range e.asked {
		if question.wants(iface) {
			e.pace(question, added, true)
		}
	}
}

// down forgets a link and what was heard on it.
func (e *Engine) down(gone *link) {
	delete(e.links, gone.wire)
	e.cancel(gone.send)
	e.cancel(gone.replying)

	for _, waiting := range gone.held {
		e.cancel(waiting.timer)
	}

	for _, stood := range gone.standing {
		e.cancel(stood.timer)
		delete(stood.pub.stands, gone)

		// A set that waited for this link to hear it waits no more.
		stood.heard()

		e.told(stood.pub)
	}

	e.readdress(gone.iface)

	for _, question := range e.asked {
		if paced := question.paces[gone]; paced != nil {
			e.cancel(paced.timer)
			delete(question.paces, gone)
			question.tell()
		}
	}
}

// read hands the loop what a link hears, until the link is closed.
func (e *Engine) read(from transport.Link) {
	buf := make([]byte, transport.MaxPacket)

	for {
		size, sender, group, err := from.Read(buf)
		if err != nil {
			return
		}

		message, err := wire.Parse(buf[:size])
		if err != nil {
			continue
		}

		select {
		case e.packets <- arrival{link: from, message: message, from: sender, group: group}:
		case <-e.done:
			return
		}
	}
}

// How long after asking for an answer of its own a host takes one.
const wishedFor = 2 * time.Second

// receive takes a message a link heard.
func (e *Engine) receive(arrived arrival) {
	heard := e.links[arrived.link]

	switch {
	// A message that is not a plain question or answer, or that says
	// something went wrong, is not Multicast DNS (RFC 6762 sections
	// 18.3 and 18.11).
	case heard == nil || arrived.message.Header.Opcode != 0 || arrived.message.Header.RCode != 0:
	case !arrived.message.Header.Response:
		e.overheard(heard, arrived)
		e.questioned(heard, arrived)
	// An answer comes from port 5353; and one sent to this host alone
	// from the link, to a question that asked for it.
	case arrived.from.Port() != transport.Port:
	case !arrived.group && (!heard.neighbour(arrived.from.Addr()) || e.now.Sub(heard.wished) > wishedFor):
	default:
		e.answered(heard, arrived)
	}
}

// answered takes an answer a link heard.
func (e *Engine) answered(heard *link, arrived arrival) {
	// Another program on this host, the system's own responder first of
	// all, speaks from the host's addresses.
	local := e.ours(arrived.from.Addr().WithZone(""))

	for _, section := range [][]wire.Record{arrived.message.Answers, arrived.message.Authorities, arrived.message.Additionals} {
		for _, record := range section {
			if record.Class != wire.ClassIN || record.Type() == wire.TypeOPT {
				continue
			}

			e.contested(heard, record, local)

			if arrived.group {
				heard.repeated(record)
			}

			e.learn(heard, record)
		}
	}
}

// neighbour says whether an address is on the link: RFC 6762 section 11
// has nothing taken from further.
func (l *link) neighbour(addr netip.Addr) bool {
	addr = addr.WithZone("")
	if addr.Is6() && addr.IsLinkLocalUnicast() {
		return true
	}

	return slices.ContainsFunc(l.addrs, func(own netip.Prefix) bool { return own.Contains(addr) })
}

// sorted is the links in an order that does not change: by interface,
// IPv4 first.
func (e *Engine) sorted() []*link {
	links := make([]*link, 0, len(e.links))
	for _, one := range e.links {
		links = append(links, one)
	}

	slices.SortFunc(links, func(one, other *link) int {
		return cmp.Or(cmp.Compare(one.iface.Index, other.iface.Index), cmp.Compare(one.family, other.family))
	})

	return links
}

// nameKey is a name as names are compared: without the case of ASCII
// letters, and with every label's length, so that no two names make one
// key.
func nameKey(labels []string) string {
	var key strings.Builder

	for _, label := range labels {
		key.WriteByte(byte(len(label))) // #nosec G115 -- a label is at most 63 bytes

		for _, char := range []byte(label) {
			if char >= 'A' && char <= 'Z' {
				char += 'a' - 'A'
			}

			key.WriteByte(char)
		}
	}

	return key.String()
}
