// Package wire reads and writes Multicast DNS messages: DNS messages
// (RFC 1035) as RFC 6762 has them, with the two bits it takes from the
// class, names compressed in the data of the records it says to, and
// NSEC records in the form it uses.
//
// It knows nothing of the protocol: what to ask, what to answer and
// when are the caller's. Names are their labels, any bytes, in the case
// they were written in.
package wire

import (
	"errors"
	"net/netip"
)

// What can go wrong.
var (
	// ErrMalformed is a packet that is not a message.
	ErrMalformed = errors.New("not a DNS message")
	// ErrInvalid is something that cannot be written: a label too long,
	// an address that is none.
	ErrInvalid = errors.New("cannot be written in a DNS message")
	// ErrFull is a message with no room left for what was to be added.
	// The message is as it was before.
	ErrFull = errors.New("no room left in the message")
)

// ClassIN is the Internet class, the one Multicast DNS uses.
const ClassIN uint16 = 1

// The record types this package knows the data of. Any other is Opaque.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeRP    uint16 = 17
	TypeAFSDB uint16 = 18
	TypeRT    uint16 = 21
	TypePX    uint16 = 26
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeKX    uint16 = 36
	TypeDNAME uint16 = 39
	TypeOPT   uint16 = 41
	TypeNSEC  uint16 = 47
	TypeANY   uint16 = 255
)

// Header is what a message says of itself.
type Header struct {
	// ID is zero in everything said to all, and a question's own in an
	// answer to a resolver that is not a Multicast DNS one.
	ID uint16
	// Response says the message answers; unset, it asks.
	Response bool
	Opcode   uint8
	// Authoritative is set in every answer.
	Authoritative bool
	// Truncated, in a question, says more of what the asker knows
	// follows in another message.
	Truncated        bool
	RecursionDesired bool
	RCode            uint8
}

// Question is one question of a message.
type Question struct {
	Name  []string
	Type  uint16
	Class uint16
	// Unicast is the top bit of the class: an answer sent to the asker
	// alone will do.
	Unicast bool
}

// Record is one resource record of a message.
type Record struct {
	Name  []string
	Class uint16
	// Flush is the top bit of the class: the record is its holder's
	// alone, and what was heard before of its name and type is to be
	// forgotten. It is never set for an OPT record, whose class is a
	// size and is kept whole.
	Flush bool
	// TTL is in seconds, as it is written.
	TTL uint32
	// Data is what the record says, and what makes its type.
	Data Data
}

// Type is the record's type: its data's.
func (r Record) Type() uint16 {
	if r.Data == nil {
		return 0
	}

	return r.Data.Type()
}

// Message is a message read.
type Message struct {
	Header      Header
	Questions   []Question
	Answers     []Record
	Authorities []Record
	Additionals []Record
	// Dropped is how many records were left out because their data was
	// not what their type has: the rest of the message stands.
	Dropped int
}

// Data is a record's data: Address, Pointer, Service, Text, NSEC or
// Opaque.
type Data interface {
	// Type is the record type the data makes.
	Type() uint16
	sealed()
}

// Address is an A record for an IPv4 address and an AAAA record for an
// IPv6 one.
type Address struct{ Addr netip.Addr }

// Pointer is a record whose data is one name: PTR, and NS, CNAME and
// DNAME.
type Pointer struct {
	// Kind is the type. Zero is PTR.
	Kind   uint16
	Target []string
}

// Service is an SRV record.
type Service struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   []string
}

// Text is a TXT record: its strings, each of up to 255 bytes. None is
// written as one empty string, which is what a text record with nothing
// to say holds.
type Text struct{ Strings []string }

// NSEC says which types a name has. It is written in the form RFC 6762
// asks for when no type is over 255, and in whole otherwise.
type NSEC struct {
	Next  []string
	Types []uint16
}

// Opaque is the data of any other type, as its bytes. Names in the data
// of the types that may compress them (SOA, MX, RP, AFSDB, RT, PX, KX)
// are read in full, so that the bytes mean the same outside the message
// they came in.
type Opaque struct {
	Kind  uint16
	Bytes []byte
}

// Type is A or AAAA, and zero for an address that is none.
func (a Address) Type() uint16 {
	switch {
	case a.Addr.Is4():
		return TypeA
	case a.Addr.Is6():
		return TypeAAAA
	default:
		return 0
	}
}

// Type is the kind, and PTR for none.
func (p Pointer) Type() uint16 {
	if p.Kind == 0 {
		return TypePTR
	}

	return p.Kind
}

// Type is SRV.
func (Service) Type() uint16 { return TypeSRV }

// Type is TXT.
func (Text) Type() uint16 { return TypeTXT }

// Type is NSEC.
func (NSEC) Type() uint16 { return TypeNSEC }

// Type is the kind.
func (o Opaque) Type() uint16 { return o.Kind }

func (Address) sealed() {}
func (Pointer) sealed() {}
func (Service) sealed() {}
func (Text) sealed()    {}
func (NSEC) sealed()    {}
func (Opaque) sealed()  {}

// What a message is made of.
const (
	headerSize = 12
	// maxLabel is the most bytes a label holds, and maxName the most a
	// name is, its length bytes included and the zero that ends it not:
	// one more than the DNS has it, as RFC 6762 appendix C does.
	maxLabel = 63
	maxName  = 255
	// maxString is the most bytes a string of a text record holds.
	maxString = 255
	// maxMessage is the most a message can be: what a length of sixteen
	// bits counts.
	maxMessage = 65535

	// topBit is the bit of a class that is not the class.
	topBit uint16 = 0x8000

	// A length byte with both of its top bits set is the first byte of
	// a pointer; the other fourteen bits are where it points.
	pointerMark byte   = 0xC0
	pointerBits uint16 = 0xC000
	maxPointer         = 0x3FFF
)
