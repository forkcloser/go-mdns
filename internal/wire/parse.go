package wire

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Parse reads a message. A packet that cannot be read to its end is
// ErrMalformed, and nothing of it is to be used. A record whose data is
// not what its type has is left out and counted, the rest standing:
// RFC 6762 has a message survive a record its reader cannot make out.
//
// Nothing read keeps a hold on the packet.
func Parse(packet []byte) (Message, error) {
	if len(packet) < headerSize {
		return Message{}, fmt.Errorf("%w: %d bytes, less than a header", ErrMalformed, len(packet))
	}

	flags := binary.BigEndian.Uint16(packet[flagsAt:])
	read := reader{msg: packet, at: headerSize}
	parsed := Message{Header: Header{
		ID:               binary.BigEndian.Uint16(packet),
		Response:         flags&flagResponse != 0,
		Opcode:           uint8(flags >> opcodeShift & nibble), // #nosec G115 -- four bits
		Authoritative:    flags&flagAuthoritative != 0,
		Truncated:        flags&flagTruncated != 0,
		RecursionDesired: flags&flagRecursion != 0,
		RCode:            uint8(flags & nibble), // #nosec G115 -- four bits
	}}

	for range binary.BigEndian.Uint16(packet[countsAt:]) {
		question, err := read.question()
		if err != nil {
			return Message{}, err
		}

		parsed.Questions = append(parsed.Questions, question)
	}

	for section, into := range []*[]Record{&parsed.Answers, &parsed.Authorities, &parsed.Additionals} {
		for range binary.BigEndian.Uint16(packet[countsAt+2*(section+1):]) {
			record, kept, err := read.record()
			if err != nil {
				return Message{}, err
			}

			if kept {
				*into = append(*into, record)
			} else {
				parsed.Dropped++
			}
		}
	}

	return parsed, nil
}

// reader is a message being read.
type reader struct {
	msg []byte
	at  int
}

// take is the next size bytes, or an error when there are not as many.
func (r *reader) take(size int) ([]byte, error) {
	if size > len(r.msg)-r.at {
		return nil, fmt.Errorf("%w: cut short at byte %d", ErrMalformed, len(r.msg))
	}

	taken := r.msg[r.at : r.at+size]
	r.at += size

	return taken, nil
}

func (r *reader) name() ([]string, error) {
	labels, next, err := readName(r.msg, r.at)
	if err != nil {
		return nil, err
	}

	r.at = next

	return labels, nil
}

// What follows a name: a question's type and class, and a record's
// type, class, TTL and length.
const (
	questionRest = 4
	recordRest   = 10
	classAt      = 2
	ttlAt        = 4
	sizeAt       = 8
)

func (r *reader) question() (Question, error) {
	name, err := r.name()
	if err != nil {
		return Question{}, err
	}

	rest, err := r.take(questionRest)
	if err != nil {
		return Question{}, err
	}

	class := binary.BigEndian.Uint16(rest[classAt:])

	return Question{
		Name:    name,
		Type:    binary.BigEndian.Uint16(rest),
		Class:   class &^ topBit,
		Unicast: class&topBit != 0,
	}, nil
}

// record reads one record. It is not kept when its data is not what its
// type has; it is an error when the record itself does not hold in the
// message.
func (r *reader) record() (Record, bool, error) {
	name, err := r.name()
	if err != nil {
		return Record{}, false, err
	}

	rest, err := r.take(recordRest)
	if err != nil {
		return Record{}, false, err
	}

	kind, class := binary.BigEndian.Uint16(rest), binary.BigEndian.Uint16(rest[classAt:])
	from := r.at

	if _, err = r.take(int(binary.BigEndian.Uint16(rest[sizeAt:]))); err != nil {
		return Record{}, false, err
	}

	data, kept := readData(kind, r.msg, from, r.at)
	read := Record{Name: name, Class: class, TTL: binary.BigEndian.Uint32(rest[ttlAt:]), Data: data}

	// An OPT record's class is the size of what its sender can take.
	if kind != TypeOPT {
		read.Class, read.Flush = class&^topBit, class&topBit != 0
	}

	return read, kept, nil
}

// readName reads the name at a place in a message, and says where what
// follows it begins.
//
// A pointer has to point before the stretch of labels it ends: a
// stretch then always begins before the last one did, and no name goes
// round in circles.
func readName(msg []byte, offset int) ([]string, int, error) {
	var labels []string

	next, size, before := -1, 1, offset

	for {
		label, target, err := piece(msg, offset, before)
		if err != nil {
			return nil, 0, err
		}

		switch {
		case label != nil:
			if size += 1 + len(label); size > maxName {
				return nil, 0, fmt.Errorf("%w: a name of over %d bytes", ErrMalformed, maxName)
			}

			labels = append(labels, string(label))
			offset += 1 + len(label)
		case target < 0:
			if next < 0 {
				next = offset + 1
			}

			return labels, next, nil
		default:
			// The first pointer is where the name ends in its place.
			if next < 0 {
				next = offset + 2
			}

			offset, before = target, target
		}
	}
}

// piece is what a name has at a place: a label; or the root, as no label
// and no target; or a pointer, as the place it points to.
func piece(msg []byte, offset, before int) ([]byte, int, error) {
	if offset >= len(msg) {
		return nil, 0, fmt.Errorf("%w: a name runs off the end", ErrMalformed)
	}

	length := int(msg[offset])

	switch {
	case length == 0:
		return nil, -1, nil
	case msg[offset]&pointerMark == pointerMark:
		target, err := pointer(msg, offset, before)

		return nil, target, err
	case length > maxLabel || offset+1+length > len(msg):
		return nil, 0, fmt.Errorf("%w: a label that is none at byte %d", ErrMalformed, offset)
	default:
		return msg[offset+1 : offset+1+length], 0, nil
	}
}

// pointer is where the pointer at a place points, which has to be
// before a given place.
func pointer(msg []byte, offset, before int) (int, error) {
	if offset+1 >= len(msg) {
		return 0, fmt.Errorf("%w: a pointer runs off the end", ErrMalformed)
	}

	target := int(binary.BigEndian.Uint16(msg[offset:])) & maxPointer
	if target >= before {
		return 0, fmt.Errorf("%w: a pointer at byte %d that does not point back", ErrMalformed, offset)
	}

	return target, nil
}

// The sizes of what data is made of.
const (
	ipv4Size = 4
	// serviceFixed is an SRV record's priority, weight and port.
	serviceFixed = 6
	// windowHead is a window's number and its length.
	windowHead = 2
)

// readData reads a record's data, which is msg[start:end], as its type
// has it. It says no for data that is not that.
func readData(kind uint16, msg []byte, start, end int) (Data, bool) {
	switch kind {
	case 0:
		// No type at all: nothing a Record could say it is.
		return nil, false
	case TypeA, TypeAAAA:
		addr, ok := netip.AddrFromSlice(msg[start:end])

		return Address{Addr: addr}, ok && (kind == TypeA) == (end-start == ipv4Size)
	case TypePTR, TypeNS, TypeCNAME, TypeDNAME:
		target, next, ok := nameWithin(msg, start, end)

		return Pointer{Kind: kind, Target: target}, ok && next == end
	case TypeSRV:
		service, ok := readService(msg, start, end)

		return service, ok
	case TypeTXT:
		text, ok := readText(msg[start:end])

		return text, ok
	case TypeNSEC:
		nsec, ok := readNSEC(msg, start, end)

		return nsec, ok
	default:
		opaque, ok := readOpaque(kind, msg, start, end)

		return opaque, ok
	}
}

// nameWithin reads a name that has to end, pointers aside, before a
// place: a name in a record's data.
func nameWithin(msg []byte, offset, end int) ([]string, int, bool) {
	labels, next, err := readName(msg[:end], offset)

	return labels, next, err == nil
}

func readService(msg []byte, start, end int) (Service, bool) {
	if end-start < serviceFixed {
		return Service{}, false
	}

	target, next, ok := nameWithin(msg, start+serviceFixed, end)
	fixed := msg[start:]

	return Service{
		Priority: binary.BigEndian.Uint16(fixed),
		Weight:   binary.BigEndian.Uint16(fixed[2:]),
		Port:     binary.BigEndian.Uint16(fixed[4:]),
		Target:   target,
	}, ok && next == end
}

func readText(data []byte) (Text, bool) {
	var read Text

	for len(data) > 0 {
		size := int(data[0])
		if size >= len(data) {
			return Text{}, false
		}

		read.Strings = append(read.Strings, string(data[1:1+size]))
		data = data[1+size:]
	}

	// One empty string is how a text record says nothing.
	if len(read.Strings) == 1 && read.Strings[0] == "" {
		read.Strings = nil
	}

	return read, true
}

// readNSEC reads the types a name has. The windows have to come in
// order, as RFC 4034 has them, so that a type is said once.
func readNSEC(msg []byte, start, end int) (NSEC, bool) {
	next, offset, ok := nameWithin(msg, start, end)
	if !ok {
		return NSEC{}, false
	}

	read := NSEC{Next: next}

	for last := -1; offset < end; {
		if end-offset < windowHead {
			return NSEC{}, false
		}

		window, size := int(msg[offset]), int(msg[offset+1])
		if window <= last || size == 0 || size > windowBytes || offset+windowHead+size > end {
			return NSEC{}, false
		}

		read.Types = appendTypes(read.Types, window, msg[offset+windowHead:offset+windowHead+size])
		last, offset = window, offset+windowHead+size
	}

	return read, true
}

// appendTypes adds the types a window's bytes have a bit set for.
func appendTypes(types []uint16, window int, bits []byte) []uint16 {
	for index, eight := range bits {
		for bit := range byteTypes {
			if eight&(firstBit>>bit) != 0 {
				types = append(types, uint16(window*windowTypes+index*byteTypes+bit)) // #nosec G115 -- under 65536
			}
		}
	}

	return types
}

// shape is how the data of a type that may compress its names is laid
// out: so many bytes, so many names, so many bytes.
type shape struct{ before, names, after int }

// shapes is the types RFC 6762 has names compressed in the data of,
// that this package has no type of its own for.
func shapes(kind uint16) (shape, bool) {
	const (
		preference = 2
		soaNumbers = 20
	)

	switch kind {
	case TypeSOA:
		return shape{names: 2, after: soaNumbers}, true
	case TypeMX, TypeAFSDB, TypeRT, TypeKX:
		return shape{before: preference, names: 1}, true
	case TypeRP:
		return shape{names: 2}, true
	case TypePX:
		return shape{before: preference, names: 2}, true
	default:
		return shape{}, false
	}
}

// readOpaque reads the data of a type this package has no type for: as
// it is, or with its names in full when it may hold compressed ones.
func readOpaque(kind uint16, msg []byte, start, end int) (Opaque, bool) {
	laid, known := shapes(kind)
	if !known {
		return Opaque{Kind: kind, Bytes: append([]byte(nil), msg[start:end]...)}, true
	}

	if end-start < laid.before+laid.names+laid.after {
		return Opaque{}, false
	}

	out := writer{buf: append([]byte(nil), msg[start:start+laid.before]...)}
	offset := start + laid.before

	for range laid.names {
		labels, next, ok := nameWithin(msg, offset, end)
		if !ok || out.name(labels, false) != nil {
			return Opaque{}, false
		}

		offset = next
	}

	if end-offset != laid.after {
		return Opaque{}, false
	}

	return Opaque{Kind: kind, Bytes: append(out.buf, msg[offset:end]...)}, true
}
