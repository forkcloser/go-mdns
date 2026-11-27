package wire

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"
)

// The header's flags.
const (
	flagResponse      uint16 = 0x8000
	flagAuthoritative uint16 = 0x0400
	flagTruncated     uint16 = 0x0200
	flagRecursion     uint16 = 0x0100
	opcodeShift              = 11
	nibble            uint16 = 0x0F
	// flagsAt and countsAt are where the flags and the four counts are
	// in a header.
	flagsAt  = 2
	countsAt = 4
)

// The sections of a message, in the order they are written.
const (
	questions = iota
	answers
	authorities
	additionals
	sections
)

// Options is how a message is to be written.
type Options struct {
	// Limit is the most bytes the message may be. Zero is the most a
	// message can be at all.
	Limit int
	// Legacy writes for a resolver that is not a Multicast DNS one,
	// which may not read a compressed SRV target.
	Legacy bool
}

// Builder writes one message, a question or a record at a time, in the
// order of the sections. What does not fit is refused with ErrFull and
// leaves the message as it was, so a caller fills a message and starts
// the next.
type Builder struct {
	out     writer
	limit   int
	legacy  bool
	section int
	counts  [sections]uint16
}

// NewBuilder starts a message after what buf holds.
func NewBuilder(buf []byte, header Header, options Options) *Builder {
	limit := options.Limit
	if limit <= 0 || limit > maxMessage {
		limit = maxMessage
	}

	built := &Builder{
		out:    writer{buf: buf, start: len(buf)},
		limit:  limit,
		legacy: options.Legacy,
	}

	flags := uint16(header.Opcode)&nibble<<opcodeShift | uint16(header.RCode)&nibble

	for flag, set := range map[uint16]bool{
		flagResponse:      header.Response,
		flagAuthoritative: header.Authoritative,
		flagTruncated:     header.Truncated,
		flagRecursion:     header.RecursionDesired,
	} {
		if set {
			flags |= flag
		}
	}

	built.out.u16(header.ID)
	built.out.u16(flags)
	built.out.buf = append(built.out.buf, make([]byte, headerSize-countsAt)...)

	return built
}

// Question adds a question.
func (b *Builder) Question(question Question) error {
	return b.add(questions, func(out *writer) error {
		if err := out.name(question.Name, true); err != nil {
			return err
		}

		class := question.Class &^ topBit
		if question.Unicast {
			class |= topBit
		}

		out.u16(question.Type)
		out.u16(class)

		return nil
	})
}

// Answer adds a record to the answers.
func (b *Builder) Answer(record Record) error { return b.record(answers, record) }

// Authority adds a record to the authorities: where a probe says what
// it means to hold.
func (b *Builder) Authority(record Record) error { return b.record(authorities, record) }

// Additional adds a record to the additionals.
func (b *Builder) Additional(record Record) error { return b.record(additionals, record) }

// Truncated marks the message as cut short, after the fact: what was to
// be said did not all fit.
func (b *Builder) Truncated() {
	flags := b.out.buf[b.out.start+flagsAt:]
	binary.BigEndian.PutUint16(flags, binary.BigEndian.Uint16(flags)|flagTruncated)
}

// Empty says whether nothing was added yet.
func (b *Builder) Empty() bool { return b.counts == [sections]uint16{} }

// Bytes is what buf held and the message after it. The Builder can go
// on being added to.
func (b *Builder) Bytes() []byte {
	counts := b.out.buf[b.out.start+countsAt:]
	for section, count := range b.counts {
		binary.BigEndian.PutUint16(counts[2*section:], count)
	}

	return b.out.buf
}

func (b *Builder) record(section int, record Record) error {
	return b.add(section, func(out *writer) error {
		kind := record.Type()
		if kind == 0 {
			return fmt.Errorf("%w: a record with no data", ErrInvalid)
		}

		if err := out.name(record.Name, true); err != nil {
			return err
		}

		// An OPT record's class is a size, and is written whole.
		class := record.Class
		if kind != TypeOPT {
			class &^= topBit
		}

		if record.Flush {
			class |= topBit
		}

		out.u16(kind)
		out.u16(class)
		out.u32(record.TTL)

		sizeAt := len(out.buf)
		out.u16(0)

		if err := out.data(record.Data, true, !b.legacy); err != nil {
			return err
		}

		size := len(out.buf) - sizeAt - 2
		if size > math.MaxUint16 {
			return fmt.Errorf("%w: a record of %d bytes", ErrInvalid, size)
		}

		binary.BigEndian.PutUint16(
			out.buf[sizeAt:],
			uint16(size),
		) // #nosec G115 -- at most MaxUint16, by the check above

		return nil
	})
}

// add writes one thing into a section, and takes it back whole when it
// cannot be written or does not fit.
func (b *Builder) add(section int, write func(*writer) error) error {
	if section < b.section {
		return fmt.Errorf("%w: a section that was already left", ErrInvalid)
	}

	if b.counts[section] == math.MaxUint16 {
		return ErrFull
	}

	size, seen := len(b.out.buf), len(b.out.seen)

	err := write(&b.out)
	if err == nil && len(b.out.buf)-b.out.start > b.limit {
		err = ErrFull
	}

	if err != nil {
		b.out.buf = b.out.buf[:size]
		b.out.forget(seen)

		return err
	}

	b.section = section
	b.counts[section]++

	return nil
}

// AppendData writes a record's data after buf as it is with no name
// compressed: what two hosts that want the same name compare.
func AppendData(buf []byte, data Data) ([]byte, error) {
	if data == nil || data.Type() == 0 {
		return buf, fmt.Errorf("%w: no data", ErrInvalid)
	}

	out := writer{buf: buf, start: len(buf)}
	if err := out.data(data, false, false); err != nil {
		return buf, err
	}

	return out.buf, nil
}

// writer is a message being written.
type writer struct {
	buf []byte
	// start is where the message begins in buf: what a pointer counts
	// from.
	start int
	// at is where the end of a name was first written, for those a
	// pointer can reach, by the digest of its labels, and seen those
	// digests in the order they were written.
	at   map[uint64]uint16
	seen []uint64
}

func (w *writer) u8(value byte)    { w.buf = append(w.buf, value) }
func (w *writer) u16(value uint16) { w.buf = binary.BigEndian.AppendUint16(w.buf, value) }
func (w *writer) u32(value uint32) { w.buf = binary.BigEndian.AppendUint32(w.buf, value) }

// name writes a name, and with compress the most of its end that was
// written before as a pointer to it.
func (w *writer) name(labels []string, compress bool) error {
	if err := checkName(labels); err != nil {
		return err
	}

	// The digest of each end of the name, the shortest first: one pass
	// over the name, where looking for each end among all those written
	// was the names written times the labels of this one, squared when
	// they share a long end.
	var ends [maxName/2 + 1]uint64

	digest := uint64(digestBasis)

	for index, label := range slices.Backward(labels) {
		digest = (digest ^ uint64(len(label))) * digestPrime

		for _, char := range []byte(label) {
			digest = (digest ^ uint64(char)) * digestPrime
		}

		ends[index] = digest
	}

	for index, label := range labels {
		// Two ends may share a digest: the labels decide.
		if at, found := w.at[ends[index]]; compress && found && w.same(int(at), labels[index:]) {
			w.u16(pointerBits | at)

			return nil
		}

		w.note(ends[index])
		w.u8(byte(len(label))) // #nosec G115 -- at most maxLabel, by checkName
		w.buf = append(w.buf, label...)
	}

	w.u8(0)

	return nil
}

// The 64-bit FNV-1a digest's constants.
const (
	digestBasis = 14695981039346656037
	digestPrime = 1099511628211
)

// note remembers that the end of a name with this digest begins here,
// when a pointer can reach it and none is remembered: the first place a
// name was written is the one pointed to.
func (w *writer) note(digest uint64) {
	offset := len(w.buf) - w.start
	if _, held := w.at[digest]; held || offset > maxPointer {
		return
	}

	if w.at == nil {
		w.at = map[uint64]uint16{}
	}

	w.at[digest] = uint16(offset) // #nosec G115 -- at most maxPointer
	w.seen = append(w.seen, digest)
}

// forget takes back what was noted after the first kept: the names of a
// record that was not written.
func (w *writer) forget(kept int) {
	for _, digest := range w.seen[kept:] {
		delete(w.at, digest)
	}

	w.seen = w.seen[:kept]
}

// same says whether the name written at a place is these labels, to its
// end. The name being written is among those seen and has no end yet:
// running off the message is a name that is not the same.
func (w *writer) same(offset int, labels []string) bool {
	msg := w.buf[w.start:]

	for offset < len(msg) {
		size := int(msg[offset])

		switch {
		case size == 0:
			return len(labels) == 0
		case msg[offset]&pointerMark == pointerMark:
			offset = int(binary.BigEndian.Uint16(msg[offset:])) & maxPointer

			continue
		case len(labels) == 0 || offset+1+size > len(msg) || string(msg[offset+1:offset+1+size]) != labels[0]:
			return false
		}

		labels = labels[1:]
		offset += 1 + size
	}

	return false
}

// data writes a record's data. names says whether names in it may be
// compressed at all, and target whether an SRV record's may.
func (w *writer) data(data Data, names, target bool) error {
	switch data := data.(type) {
	case Address:
		return w.address(data)
	case Pointer:
		return w.name(data.Target, names)
	case Service:
		w.u16(data.Priority)
		w.u16(data.Weight)
		w.u16(data.Port)

		return w.name(data.Target, names && target)
	case Text:
		return w.text(data)
	case NSEC:
		if err := w.name(data.Next, names); err != nil {
			return err
		}

		w.bitmap(data.Types)

		return nil
	case Opaque:
		w.buf = append(w.buf, data.Bytes...)

		return nil
	default:
		return fmt.Errorf("%w: data of a kind that is not known", ErrInvalid)
	}
}

func (w *writer) address(data Address) error {
	switch {
	case data.Addr.Is4():
		addr := data.Addr.As4()
		w.buf = append(w.buf, addr[:]...)
	case data.Addr.Is6():
		addr := data.Addr.As16()
		w.buf = append(w.buf, addr[:]...)
	default:
		return fmt.Errorf("%w: an address that is none", ErrInvalid)
	}

	return nil
}

func (w *writer) text(data Text) error {
	if len(data.Strings) == 0 {
		w.u8(0)

		return nil
	}

	for _, one := range data.Strings {
		if len(one) > maxString {
			return fmt.Errorf("%w: a string of %d bytes in a text record", ErrInvalid, len(one))
		}

		w.u8(byte(len(one))) // #nosec G115 -- at most maxString, by the check above
		w.buf = append(w.buf, one...)
	}

	return nil
}

// What a type bitmap is made of: windows of 256 types, each a number,
// a length and up to 32 bytes of eight types each.
const (
	windowTypes = 256
	windowBytes = 32
	byteTypes   = 8
	firstBit    = 0x80
)

// bitmap writes the types a name has, as NSEC has them: in windows, in
// order, each as long as its last type needs.
func (w *writer) bitmap(types []uint16) {
	sorted := slices.Clone(types)
	slices.Sort(sorted)

	for len(sorted) > 0 {
		window := sorted[0] / windowTypes

		var (
			bits [windowBytes]byte
			size int
		)

		for len(sorted) > 0 && sorted[0]/windowTypes == window {
			low := sorted[0] % windowTypes
			bits[low/byteTypes] |= firstBit >> (low % byteTypes)
			size = int(low/byteTypes) + 1
			sorted = sorted[1:]
		}

		w.u8(byte(window)) // #nosec G115 -- a sixteen-bit type over 256
		w.u8(byte(size))   // #nosec G115 -- at most windowBytes
		w.buf = append(w.buf, bits[:size]...)
	}
}

// checkName holds a name to what DNS can carry.
func checkName(labels []string) error {
	size := 1

	for _, label := range labels {
		if label == "" || len(label) > maxLabel {
			return fmt.Errorf("%w: a label of %d bytes", ErrInvalid, len(label))
		}

		size += 1 + len(label)
	}

	if size > maxName {
		return fmt.Errorf("%w: a name of %d bytes", ErrInvalid, size)
	}

	return nil
}
