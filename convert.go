package mdns

import (
	"fmt"
	"strings"
	"time"

	"github.com/forkcloser/go-mdns/internal/wire"
)

// recordOf is a record read from the network, in this package's words.
func recordOf(read wire.Record) Record {
	return Record{Name: read.Name, TTL: time.Duration(read.TTL) * time.Second, Data: dataOf(read.Data)}
}

// dataOf is a record's data in this package's words: the types it has a
// word for, and Raw for every other, with no name compressed.
func dataOf(read wire.Data) Data {
	switch data := read.(type) {
	case wire.Address:
		return Addr{Addr: data.Addr}
	case wire.Service:
		return SRV{Priority: data.Priority, Weight: data.Weight, Port: data.Port, Target: data.Target}
	case wire.Text:
		return textOf(data)
	case wire.NSEC:
		types := make([]Type, len(data.Types))
		for index, kind := range data.Types {
			types[index] = Type(kind)
		}

		return NSEC{Next: data.Next, Types: types}
	case wire.Opaque:
		return Raw{Kind: Type(data.Kind), Bytes: data.Bytes}
	case wire.Pointer:
		if data.Type() == wire.TypePTR {
			return PTR{Target: data.Target}
		}
	}

	// A name where this package has no word for one: NS, CNAME, DNAME.
	bytes, _ := wire.AppendData(nil, read)

	return Raw{Kind: Type(read.Type()), Bytes: bytes}
}

// textOf reads a text record as RFC 6763 section 6 has one read: a
// string with no key is passed over, and of two entries of one key the
// first stands.
func textOf(read wire.Text) TXT {
	text := TXT{}

	for _, one := range read.Strings {
		key, value, valued := strings.Cut(one, "=")
		if key == "" {
			continue
		}

		if _, twice := text.Get(key); twice {
			continue
		}

		entry := Entry{Key: key}
		if valued {
			entry.Value = []byte(value)
		}

		text = append(text, entry)
	}

	return text
}

// wire is a record as it is written to the network. It is ErrInvalid
// for a record that cannot be.
func (r Record) wire() (wire.Record, error) {
	if err := r.Name.Validate(); err != nil {
		return wire.Record{}, err
	}

	data, err := wireData(r.Data)
	if err != nil {
		return wire.Record{}, err
	}

	if r.TTL < 0 {
		return wire.Record{}, fmt.Errorf("%w: a TTL of %s", ErrInvalid, r.TTL)
	}

	return wire.Record{
		Name:  r.Name,
		Class: wire.ClassIN,
		TTL:   uint32(min(r.TTL/time.Second, maxTTL)), // #nosec G115 -- at most maxTTL
		Data:  data,
	}, nil
}

// maxTTL is the longest a record can say it lasts, in seconds: what 31
// bits hold, as RFC 2181 has it.
const maxTTL = 1<<31 - 1

func wireData(written Data) (wire.Data, error) {
	switch data := written.(type) {
	case Addr:
		if !data.Addr.IsValid() {
			return nil, fmt.Errorf("%w: an address that is none", ErrInvalid)
		}

		return wire.Address{Addr: data.Addr.WithZone("")}, nil
	case PTR:
		return wire.Pointer{Target: data.Target}, data.Target.Validate()
	case SRV:
		return wire.Service{
			Priority: data.Priority,
			Weight:   data.Weight,
			Port:     data.Port,
			Target:   data.Target,
		}, data.Target.Validate()
	case TXT:
		return data.wire(), data.Validate()
	case NSEC:
		types := make([]uint16, len(data.Types))
		for index, kind := range data.Types {
			types[index] = uint16(kind)
		}

		return wire.NSEC{Next: data.Next, Types: types}, data.Next.Validate()
	case Raw:
		if data.Kind == 0 || data.Kind == TypeANY {
			return nil, fmt.Errorf("%w: a record of type %d", ErrInvalid, data.Kind)
		}

		return wire.Opaque{Kind: uint16(data.Kind), Bytes: data.Bytes}, nil
	default:
		return nil, fmt.Errorf("%w: a record with no data", ErrInvalid)
	}
}

// wire is a text record as its strings.
func (t TXT) wire() wire.Text {
	var written wire.Text

	for _, entry := range t {
		one := entry.Key
		if entry.Value != nil {
			one += "=" + string(entry.Value)
		}

		written.Strings = append(written.Strings, one)
	}

	return written
}
