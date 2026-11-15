package wire_test

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/forkcloser/go-mdns/internal/wire"
)

// header is a response's, with so many answers.
func header(answers byte) string {
	return "\x00\x00\x84\x00\x00\x00\x00" + string([]byte{answers}) + "\x00\x00\x00\x00"
}

// record is a record of class IN, with a TTL of 120 seconds.
func record(name string, kind byte, data string) string {
	return name + string([]byte{0, kind, 0, 1, 0, 0, 0, 120, 0, byte(len(data))}) + data
}

const kitchen = "\x07kitchen\x05local\x00"

func TestWhatIsNotAMessage(t *testing.T) {
	t.Parallel()

	for what, packet := range map[string]string{
		"nothing":                           "",
		"less than a header":                "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00",
		"an answer that is not there":       header(1),
		"a name that runs off":              header(1) + "\x07kitchen",
		"a label that runs off":             header(1) + "\x07kit",
		"a pointer that runs off":           header(1) + "\xc0",
		"a pointer to itself":               header(1) + "\xc0\x0c" + "\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\xc0\x00\x02\x07",
		"a pointer forward":                 header(1) + "\xc0\x0e" + "\x01a\x00",
		"two pointers in a circle":          header(1) + "\x01a\xc0\x0e\xc0\x0c",
		"a name that ends in itself":        header(1) + "\x01a\xc0\x0c",
		"a label of a kind long gone":       header(1) + "\x41a\x00",
		"a record cut in its fixed part":    header(1) + kitchen + "\x00\x01\x00\x01\x00\x00",
		"data longer than the packet":       header(1) + kitchen + "\x00\x01\x00\x01\x00\x00\x00\x78\x00\x05\xc0\x00\x02\x07",
		"a second answer that is not there": header(2) + record(kitchen, 1, "\xc0\x00\x02\x07"),
	} {
		if got, err := wire.Parse(
			[]byte(packet),
		); !errors.Is(err, wire.ErrMalformed) ||
			!reflect.DeepEqual(got, wire.Message{}) {
			t.Errorf("%s: read as %+v, %v", what, got, err)
		}
	}
}

// A name may be no longer than 255 bytes, however it is pieced
// together with pointers.
func TestANameTooLongByItsPointers(t *testing.T) {
	t.Parallel()

	label := "\x3f" + strings.Repeat("x", 63)

	// Three labels and the root are 193 bytes, and fit; a fourth before a
	// pointer to them makes 257.
	fits := header(1) + record(label+label+label+"\x00", 16, "\x00")
	if _, err := wire.Parse([]byte(fits)); err != nil {
		t.Fatalf("a name of 193 bytes: %v", err)
	}

	packet := header(2) + record(label+label+label+"\x00", 16, "\x00") + record(label+"\xc0\x0c", 16, "\x00")
	if _, err := wire.Parse([]byte(packet)); !errors.Is(err, wire.ErrMalformed) {
		t.Errorf("a name of 257 bytes: %v", err)
	}
}

// A record whose data is not what its type has is left out, and the
// records around it stand.
func TestARecordThatCannotBeMadeOutIsLeftOut(t *testing.T) {
	t.Parallel()

	good := record(kitchen, 1, "\xc0\x00\x02\x07")
	want := wire.Record{
		Name:  []string{"kitchen", "local"},
		Class: wire.ClassIN,
		TTL:   120,
		Data:  wire.Address{Addr: netip.MustParseAddr("192.0.2.7")},
	}

	for what, bad := range map[string]string{
		"an address of three bytes":        record(kitchen, 1, "\xc0\x00\x02"),
		"an IPv6 address of four bytes":    record(kitchen, 28, "\xc0\x00\x02\x07"),
		"a pointer with bytes after it":    record(kitchen, 12, "\x01a\x00\x00"),
		"a pointer that runs off its data": record(kitchen, 12, "\x05a"),
		"a service with no target":         record(kitchen, 33, "\x00\x00\x00\x00\x00\x50"),
		"a service cut short":              record(kitchen, 33, "\x00\x00\x00"),
		"a string that runs off its data":  record(kitchen, 16, "\x05abc"),
		"a window of no length":            record(kitchen, 47, "\xc0\x0c\x00\x00"),
		"a window of 33 bytes":             record(kitchen, 47, "\xc0\x0c\x00\x21"+strings.Repeat("\x01", 33)),
		"a window cut short":               record(kitchen, 47, "\xc0\x0c\x00\x04\x40"),
		"windows out of order":             record(kitchen, 47, "\xc0\x0c\x01\x01\x40\x00\x01\x40"),
		"half a window":                    record(kitchen, 47, "\xc0\x0c\x00"),
		"a mail exchanger with no name":    record(kitchen, 15, "\x00\x0a"),
		"a start of authority cut short":   record(kitchen, 6, "\x01a\x00\x01b\x00\x00\x00"),
		"a record of no type":              record(kitchen, 0, "abc"),
	} {
		packet := header(3) + good + bad + good

		got, err := wire.Parse([]byte(packet))
		if err != nil || got.Dropped != 1 || !reflect.DeepEqual(got.Answers, []wire.Record{want, want}) {
			t.Errorf("%s: read as %+v, %v", what, got, err)
		}
	}
}

// RFC 6762 has names compressed in the data of more types than have a
// use here. They are read in full, so that the bytes still mean what
// they did once they are out of their message.
func TestNamesInOtherDataAreReadInFull(t *testing.T) {
	t.Parallel()

	const mail, authority, alias = 15, 6, 5

	packet := header(4) +
		record(kitchen, 1, "\xc0\x00\x02\x07") +
		record("\xc0\x0c", mail, "\x00\x0a\x04mail\xc0\x14") +
		record("\xc0\x0c", authority, "\xc0\x0c\x04root\xc0\x14"+strings.Repeat("\x01", 20)) +
		record("\x05other\xc0\x14", alias, "\xc0\x0c")

	got, err := wire.Parse([]byte(packet))
	if err != nil || got.Dropped != 0 || len(got.Answers) != 4 {
		t.Fatalf("read as %+v, %v", got, err)
	}

	for index, want := range map[int]wire.Data{
		1: wire.Opaque{Kind: mail, Bytes: []byte("\x00\x0a\x04mail\x05local\x00")},
		2: wire.Opaque{Kind: authority, Bytes: []byte(kitchen + "\x04root\x05local\x00" + strings.Repeat("\x01", 20))},
		3: wire.Pointer{Kind: alias, Target: []string{"kitchen", "local"}},
	} {
		if !reflect.DeepEqual(got.Answers[index].Data, want) {
			t.Errorf("answer %d read as %+v, want %+v", index, got.Answers[index].Data, want)
		}
	}
}

// The top bit of a class is a question's wish for an answer of its own
// and a record's claim to be alone, and is neither in an OPT record,
// whose class is a size.
func TestTheTopBitOfAClass(t *testing.T) {
	t.Parallel()

	const opt = 41

	packet := "\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x01" +
		kitchen + "\x00\xff\x80\x01" +
		"\xc0\x0c\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\x00\x02\x07" +
		"\x00\x00" + string([]byte{opt}) + "\x90\x00\x00\x00\x00\x00\x00\x00"

	got, err := wire.Parse([]byte(packet))
	if err != nil {
		t.Fatal(err)
	}

	name := []string{"kitchen", "local"}
	want := wire.Message{
		Questions: []wire.Question{{Name: name, Type: wire.TypeANY, Class: wire.ClassIN, Unicast: true}},
		Answers: []wire.Record{
			{
				Name:  name,
				Class: wire.ClassIN,
				Flush: true,
				TTL:   120,
				Data:  wire.Address{Addr: netip.MustParseAddr("192.0.2.7")},
			},
		},
		Additionals: []wire.Record{{Class: 0x9000, Data: wire.Opaque{Kind: opt}}},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("read as\n%+v\nwant\n%+v", got, want)
	}

	// And written back as it came.
	builder := wire.NewBuilder(nil, want.Header, wire.Options{})
	if builder.Question(want.Questions[0]) != nil || builder.Answer(want.Answers[0]) != nil ||
		builder.Additional(want.Additionals[0]) != nil {
		t.Fatal("refused")
	}

	if string(builder.Bytes()) != packet {
		t.Errorf("written as %q, want %q", builder.Bytes(), packet)
	}
}

// Whatever a packet holds, reading it ends, without a panic; and what
// is read can be written, and is read again as the same.
func FuzzParse(f *testing.F) {
	f.Add([]byte(header(1) + record(kitchen, 1, "\xc0\x00\x02\x07")))
	f.Add(
		[]byte(
			header(
				2,
			) + record(
				kitchen,
				47,
				"\xc0\x0c\x00\x04\x40\x00\x00\x08",
			) + record(
				"\x05other\xc0\x14",
				33,
				"\x00\x00\x00\x00\x00\x50\xc0\x0c",
			),
		),
	)
	f.Add([]byte(header(1) + record(kitchen, 16, "\x06path=/\x06secure")))
	f.Add([]byte(header(1) + record("\x01a\xc0\x0c", 12, "\xc0\x0c")))
	f.Add(
		[]byte(
			"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00" + kitchen + "\x00\xff\x80\x01" + "\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x78\x00\x18\xc0\x0c\xc0\x14" + strings.Repeat(
				"\x00",
				20,
			),
		),
	)

	f.Fuzz(func(t *testing.T, packet []byte) {
		read, err := wire.Parse(packet)
		if err != nil {
			return
		}

		builder := wire.NewBuilder(nil, read.Header, wire.Options{})

		for _, question := range read.Questions {
			err = errors.Join(err, builder.Question(question))
		}

		for section, records := range [][]wire.Record{read.Answers, read.Authorities, read.Additionals} {
			for _, one := range records {
				err = errors.Join(
					err,
					[]func(wire.Record) error{builder.Answer, builder.Authority, builder.Additional}[section](one),
				)
			}
		}

		// Names in full may make a message of more than can be one.
		if errors.Is(err, wire.ErrFull) {
			return
		}

		if err != nil {
			t.Fatalf("what was read cannot be written: %v", err)
		}

		again, err := wire.Parse(builder.Bytes())
		read.Dropped = 0

		if err != nil || !reflect.DeepEqual(again, read) {
			t.Fatalf("read as\n%+v\nthen as\n%+v, %v", read, again, err)
		}
	})
}
