package mdns

import (
	"context"
	"net/netip"
	"time"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
)

// Type is a record's type, as DNS numbers them.
type Type uint16

// The types Multicast DNS is made of. Any other is carried as Raw.
const (
	TypeA    Type = 1
	TypePTR  Type = 12
	TypeTXT  Type = 16
	TypeAAAA Type = 28
	TypeSRV  Type = 33
	TypeNSEC Type = 47
	// TypeANY is a question's alone: every record of a name.
	TypeANY Type = 255
)

// Record is a resource record of class IN: a name, what is said of it,
// and for how long it may be remembered.
type Record struct {
	Name Name
	// TTL is how long. Published, zero is what RFC 6762 recommends for
	// the record's type.
	TTL time.Duration
	// Data is what is said: one of the types below.
	Data Data
}

// Data is a record's data: Addr, PTR, SRV, TXT, NSEC or Raw, and no
// other.
type Data interface {
	// Type is the record type the data is of.
	Type() Type
	data()
}

type (
	// Addr is an A or an AAAA record, by the address it holds.
	Addr struct{ Addr netip.Addr }
	// PTR is a pointer to another name.
	PTR struct{ Target Name }
	// SRV is where a service is: a host and a port.
	SRV struct {
		Priority uint16
		Weight   uint16
		Port     uint16
		Target   Name
	}
	// NSEC says which types a name has, and so which it has not: how a
	// host says "no such record" in Multicast DNS.
	NSEC struct {
		Next  Name
		Types []Type
	}
	// Raw is a record of a type this package has no word for, as its
	// bytes.
	Raw struct {
		Kind  Type
		Bytes []byte
	}
)

// Type is A for an IPv4 address and AAAA for an IPv6 one.
func (a Addr) Type() Type {
	if a.Addr.Is4() {
		return TypeA
	}

	return TypeAAAA
}

// Type is PTR.
func (PTR) Type() Type { return TypePTR }

// Type is SRV.
func (SRV) Type() Type { return TypeSRV }

// Type is TXT.
func (TXT) Type() Type { return TypeTXT }

// Type is NSEC.
func (NSEC) Type() Type { return TypeNSEC }

// Type is the type the record was.
func (r Raw) Type() Type { return r.Kind }

func (Addr) data() {}
func (PTR) data()  {}
func (SRV) data()  {}
func (TXT) data()  {}
func (NSEC) data() {}
func (Raw) data()  {}

// Question is what is asked: the records of a type that a name has.
type Question struct {
	Name Name
	// Type is the type, or TypeANY.
	Type Type

	// Interfaces says which interfaces to ask on, of those the Peer is
	// on: On("en0"), or any rule. Nil is all of them.
	Interfaces func(Interface) bool
}

// Answer is a record that answers a question. The same record heard on
// two interfaces is one answer.
type Answer struct {
	// Record is the record, its TTL as it was last said.
	Record Record
	// Interfaces is the interfaces it is heard on, as an Instance's
	// are.
	Interfaces []Interface
}

// Ask tells handle of the records that answer a question: first those
// the Peer already knows, each as found, and then each as it is found or
// lost, until ctx ends. A record does not change, another takes its
// place; an answer is changed when the interfaces it is heard on are. It asks as Browse does, and returns as Browse
// does. It is what
// Browse, Resolve, LookupHost and ServiceTypes are made of, and is there
// for what they have no word for: a reverse lookup, a record of another
// type.
func (p *Peer) Ask(ctx context.Context, question Question, handle func(Change, Answer)) error {
	if err := question.Name.Validate(); err != nil {
		return err
	}

	asked := engine.Question{Name: question.Name, Type: uint16(question.Type), Interfaces: question.Interfaces}

	return translate(p.engine.Ask(ctx, asked, func(change engine.Change, answer engine.Answer) {
		handle(Change(change), Answer{Record: recordOf(answer.Record), Interfaces: answer.Interfaces})
	}))
}

// ReconfirmRecord is Reconfirm for one record: it was acted on, and was
// wrong.
func (p *Peer) ReconfirmRecord(doubted Record) error {
	written, err := doubted.wire()
	if err != nil {
		return err
	}

	return translate(p.engine.Reconfirm(written))
}

// Records is a set of records to publish.
type Records struct {
	Records []Record

	// Shared says other hosts may publish records of the same names and
	// types, as they do a PTR record that lists the instances of a type.
	// Unset, the names are this host's alone: asked for before they are
	// used, and defended after.
	Shared bool

	// Interfaces says which interfaces to publish on, as a Service's
	// does.
	Interfaces func(Interface) bool
}

// Publication is a set of records being published.
type Publication struct {
	published *engine.Publication
}

// Publish answers for a set of records on every link the Peer is on, as
// Announce does for a service: names that are the host's alone are
// first asked for, and a name another host holds is ErrConflict, there
// being no one name to try in its place; so is a record of a name and a
// type the Peer already has as the host's alone on an interface these
// are wanted on, a service's and the host's own addresses included. It is what Announce is made
// of, and is there for what it has no word for.
func (p *Peer) Publish(ctx context.Context, records Records) (*Publication, error) {
	set := engine.Set{Interfaces: records.Interfaces}

	for _, record := range records.Records {
		written, err := record.wire()
		if err != nil {
			return nil, err
		}

		written.Flush = !records.Shared
		if written.TTL == 0 {
			written.TTL = defaultTTL(written)
		}

		set.Records = append(set.Records, written)
	}

	published, err := p.engine.Publish(ctx, set)
	if err != nil {
		return nil, translate(err)
	}

	return &Publication{published: published}, nil
}

// What RFC 6762 section 10 recommends a record be remembered for: two
// minutes for one whose name is a host's or whose data holds a host's
// name, 75 minutes for the rest.
const (
	hostTTL  = 120
	otherTTL = 75 * 60
	// typeHINFO is the type of a record that says what a host is.
	typeHINFO = 13
)

// defaultTTL is how long a record is remembered when it does not say:
// two minutes for an address, a host's description, a service's
// whereabouts, and a pointer from an address back to its host.
func defaultTTL(record wire.Record) uint32 {
	switch record.Type() {
	case wire.TypeA, wire.TypeAAAA, wire.TypeSRV, typeHINFO:
		return hostTTL
	case wire.TypePTR:
		if reverse(record.Name) {
			return hostTTL
		}
	}

	return otherTTL
}

// reverse says whether a name is one that maps an address back to a
// host: under in-addr.arpa or ip6.arpa.
func reverse(name []string) bool {
	const depth = 2

	if len(name) < depth || !sameLabel(name[len(name)-1], "arpa") {
		return false
	}

	return sameLabel(name[len(name)-depth], "in-addr") || sameLabel(name[len(name)-depth], "ip6")
}

// Close withdraws the records: the neighbours are told goodbye.
func (b *Publication) Close() error {
	return translate(b.published.Close())
}

// Done is closed when the records are no longer published: withdrawn,
// or lost. They are lost to another host that holds one of their names;
// and, long after they were published, to this Peer's own host when an
// interface comes up or gains an address that makes one of them a
// record the host already says there, whichever of the two was
// published first keeping it.
func (b *Publication) Done() <-chan struct{} {
	return b.published.Done()
}

// Err is why, once Done is closed: ErrClosed, or ErrConflict. Nil until
// then.
func (b *Publication) Err() error {
	return translate(b.published.Err())
}
