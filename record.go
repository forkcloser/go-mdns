package mdns

import (
	"context"
	"net/netip"
	"time"

	"github.com/forkcloser/go-mdns/internal/todo"
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
	return todo.ImplementMe(p, ctx, question, handle)
}

// ReconfirmRecord is Reconfirm for one record: it was acted on, and was
// wrong.
func (p *Peer) ReconfirmRecord(doubted Record) error {
	return todo.ImplementMe(p, doubted)
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
type Publication struct{}

// Publish answers for a set of records on every link the Peer is on, as
// Announce does for a service: names that are the host's alone are
// first asked for, and a name another host holds is ErrConflict, there
// being no one name to try in its place. It is what Announce is made
// of, and is there for what it has no word for.
func (p *Peer) Publish(ctx context.Context, records Records) (*Publication, error) {
	return nil, todo.ImplementMe(p, ctx, records)
}

// Close withdraws the records: the neighbours are told goodbye.
func (b *Publication) Close() error {
	return todo.ImplementMe(b)
}

// Done is closed when the records are no longer published: withdrawn,
// or lost to another host that holds one of their names.
func (b *Publication) Done() <-chan struct{} {
	_ = todo.ImplementMe(b)

	return nil
}

// Err is why, once Done is closed: ErrClosed, or ErrConflict. Nil until
// then.
func (b *Publication) Err() error {
	return todo.ImplementMe(b)
}
