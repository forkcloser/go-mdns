package wire_test

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/forkcloser/go-mdns/internal/wire"
)

// Each bound of the reader and of the writer, held to the byte: a packet
// or a call for each side of it. The packets are cut to their length,
// so that reading past one is a panic and not a quiet read of what the
// buffer had room for.

// head is a response's header, with so many questions and answers.
func head(questions, answers byte) []byte {
	return []byte{0, 0, 0x84, 0, 0, questions, 0, answers, 0, 0, 0, 0}
}

// rooted is a record of the root's name, class IN, good for two minutes,
// with this data.
func rooted(kind byte, data ...byte) []byte {
	return append([]byte{0, 0, kind, 0, 1, 0, 0, 0, 120, 0, byte(len(data))}, data...)
}

// packet is its parts end to end, with no room after them.
func packet(parts ...[]byte) []byte {
	whole := bytes.Join(parts, nil)

	return slices.Clip(whole)
}

// labels is a name of three labels of 63 bytes and one of so many, as
// it is written.
func labels(last int) []byte {
	var name []byte

	for _, size := range []int{63, 63, 63, last} {
		name = append(name, byte(size))
		name = append(name, bytes.Repeat([]byte{'a'}, size)...)
	}

	return name
}

func TestTheBoundsOfWhatIsNotAMessage(t *testing.T) {
	t.Parallel()

	question := []byte{0, 0, 1, 0, 1}

	for what, read := range map[string][]byte{
		"eleven bytes":                      make([]byte, 11),
		"a label longer than what is left":  packet(head(1, 0), []byte{5, 'a', 'b'}),
		"a length byte of 64":               packet(head(1, 0), []byte{0x40}, bytes.Repeat([]byte{'a'}, 64), question),
		"a name of 256 bytes":               packet(head(1, 0), labels(62), question),
		"a pointer into the labels it ends": packet(head(1, 0), []byte{3, 1, 'a', 0, 0xC0, 13}, question),
	} {
		if _, err := wire.Parse(read); !errors.Is(err, wire.ErrMalformed) {
			t.Errorf("%s: %v", what, err)
		}
	}

	// A name of 255 bytes is one.
	if read, err := wire.Parse(packet(head(1, 0), labels(61), question)); err != nil || len(read.Questions) != 1 {
		t.Errorf("a name of 255 bytes: %v", err)
	}
}

func TestTheBoundsOfARecordsData(t *testing.T) {
	t.Parallel()

	address := rooted(1, 1, 2, 3, 4)

	// Alone and last in its packet: nothing after it to read by mistake.
	for what, data := range map[string][]byte{
		"a window that says more bytes than are left": rooted(47, 0, 0, 2, 0x40),
		"half a window's head":                        rooted(47, 0, 0),
		"windows out of order":                        rooted(47, 0, 1, 1, 0x80, 0, 1, 0x40),
		"a window twice":                              rooted(47, 0, 0, 1, 0x40, 0, 1, 0x40),
		"a service of five bytes":                     rooted(33, 0, 0, 0, 0, 0),
		"a mail exchanger of one byte":                rooted(15, 0),
		"a mail exchanger with a byte after its name": rooted(15, 0, 10, 0, 9),
		"a pointer with a byte after its name":        rooted(12, 1, 'a', 0, 9),
	} {
		if read, err := wire.Parse(
			packet(head(0, 1), data),
		); err != nil || read.Dropped != 1 ||
			len(read.Answers) != 0 {
			t.Errorf("%s: %v, dropped %d, %d answers", what, err, read.Dropped, len(read.Answers))
		}
	}

	// Followed by a record of the root's name, whose first byte is the
	// end of a name the data did not hold.
	for what, data := range map[string][]byte{
		"a string one byte longer than what is left": rooted(16, 2, 'a'),
		"a denial whose name has no end in its data": rooted(47, 1, 'a'),
	} {
		if read, err := wire.Parse(
			packet(head(0, 2), data, address),
		); err != nil || read.Dropped != 1 ||
			len(read.Answers) != 1 {
			t.Errorf("%s: %v, dropped %d, %d answers", what, err, read.Dropped, len(read.Answers))
		}
	}
}

func TestTheBoundsOfAName(t *testing.T) {
	t.Parallel()

	address := wire.Address{Addr: netip.MustParseAddr("1.2.3.4")}

	// A name already written is pointed at for the whole of its end, and
	// for nothing else.
	for what, names := range map[string][][]string{
		"a name that goes on after one already written":    {{"local"}, {"local", "x"}},
		"a name that ends before one already written does": {{"a", "local"}, {"a"}},
	} {
		message := wire.NewBuilder(nil, wire.Header{}, wire.Options{})

		for _, name := range names {
			if err := message.Answer(wire.Record{Name: name, Class: wire.ClassIN, Data: address}); err != nil {
				t.Fatalf("%s: %v", what, err)
			}
		}

		read, err := wire.Parse(message.Bytes())
		if err != nil || len(read.Answers) != len(names) {
			t.Fatalf("%s: %v, %d answers", what, err, len(read.Answers))
		}

		for index, name := range names {
			if !slices.Equal(read.Answers[index].Name, name) {
				t.Errorf("%s: name %d read as %q, written as %q", what, index, read.Answers[index].Name, name)
			}
		}
	}

	long := strings.Repeat("a", 63)
	message := wire.NewBuilder(nil, wire.Header{}, wire.Options{})

	if err := message.Question(
		wire.Question{Name: []string{long, long, long, long[:61]}, Type: wire.TypeA},
	); err != nil {
		t.Errorf("a name of 255 bytes: %v", err)
	}

	if err := message.Question(
		wire.Question{Name: []string{long, long, long, long[:62]}, Type: wire.TypeA},
	); !errors.Is(
		err,
		wire.ErrInvalid,
	) {
		t.Errorf("a name of 256 bytes: %v", err)
	}
}

// The last place a pointer can reach is byte 16383: a label there is
// pointed at, and one a byte further is written again.
func TestTheLastPlaceAPointerReaches(t *testing.T) {
	t.Parallel()

	filler := func(size int) wire.Record {
		return wire.Record{Class: wire.ClassIN, Data: wire.Text{Strings: []string{strings.Repeat("t", size)}}}
	}

	edge := wire.Record{
		Name:  []string{"edge"},
		Class: wire.ClassIN,
		Data:  wire.Address{Addr: netip.MustParseAddr("1.2.3.4")},
	}

	for place, again := range map[int]int{16383: 2, 16384: 6} {
		message := wire.NewBuilder(nil, wire.Header{}, wire.Options{})

		for range 61 {
			if err := message.Answer(filler(255)); err != nil {
				t.Fatal(err)
			}
		}

		if err := message.Answer(filler(72 + place - 16383)); err != nil || len(message.Bytes()) != place {
			t.Fatalf("the filler ends at %d, not %d: %v", len(message.Bytes()), place, err)
		}

		if err := message.Answer(edge); err != nil {
			t.Fatal(err)
		}

		before := len(message.Bytes())

		if err := message.Answer(edge); err != nil {
			t.Fatal(err)
		}

		// A record is its name and fourteen bytes.
		if took := len(message.Bytes()) - before - 14; took != again {
			t.Errorf("a label at %d: the same name after it took %d bytes, want %d", place, took, again)
		}

		read, err := wire.Parse(message.Bytes())
		if err != nil || len(read.Answers) != 64 || !slices.Equal(read.Answers[63].Name, []string{"edge"}) {
			t.Errorf("a label at %d: read back as %v", place, err)
		}
	}
}

func TestTheBoundsOfAMessage(t *testing.T) {
	t.Parallel()

	record := wire.Record{
		Name:  []string{"a", "bc"},
		Class: wire.ClassIN,
		Data:  wire.Address{Addr: netip.MustParseAddr("1.2.3.4")},
	}

	// A header, a name of six bytes, ten of what a record always has,
	// and four of address: 32 bytes.
	if err := wire.NewBuilder(nil, wire.Header{}, wire.Options{Limit: 32}).Answer(record); err != nil {
		t.Errorf("a record that fits to the byte: %v", err)
	}

	if err := wire.NewBuilder(nil, wire.Header{}, wire.Options{Limit: 31}).
		Answer(record); !errors.Is(
		err,
		wire.ErrFull,
	) {
		t.Errorf("a record one byte too long: %v", err)
	}

	// A limit over what a message can be is what a message can be.
	message := wire.NewBuilder(nil, wire.Header{}, wire.Options{Limit: 70000})
	filler := wire.Record{Class: wire.ClassIN, Data: wire.Text{Strings: []string{strings.Repeat("t", 255)}}}

	var err error

	for range 400 {
		if err = message.Answer(filler); err != nil {
			break
		}
	}

	if !errors.Is(err, wire.ErrFull) || len(message.Bytes()) > 65535 {
		t.Errorf("a limit of 70000: %v, %d bytes", err, len(message.Bytes()))
	}

	// The top bit of a class is not the class: it is said by Flush.
	message = wire.NewBuilder(nil, wire.Header{}, wire.Options{})
	record.Class = 0x8001

	if err = message.Answer(record); err != nil {
		t.Fatal(err)
	}

	read, err := wire.Parse(message.Bytes())
	if err != nil || read.Answers[0].Flush || read.Answers[0].Class != wire.ClassIN {
		t.Errorf("a class with its top bit set and no Flush: read as %+v, %v", read.Answers, err)
	}

	// And of a question's, by Unicast.
	message = wire.NewBuilder(nil, wire.Header{}, wire.Options{})

	if err = message.Question(wire.Question{Name: []string{"a"}, Type: wire.TypeA, Class: 0x8001}); err != nil {
		t.Fatal(err)
	}

	asked, err := wire.Parse(message.Bytes())
	if err != nil || asked.Questions[0].Unicast || asked.Questions[0].Class != wire.ClassIN {
		t.Errorf("a question's class with its top bit set and no Unicast: read as %+v, %v", asked.Questions, err)
	}
}

// A record that is refused takes back the places it noted of its name:
// the names that follow are not held to labels that are gone.
func TestARefusalForgetsItsLabels(t *testing.T) {
	t.Parallel()

	message := wire.NewBuilder(nil, wire.Header{}, wire.Options{Limit: 60})
	refused := wire.Record{
		Name: []string{"aaaaaaaaaaaaa", "name"}, Class: wire.ClassIN,
		Data: wire.Text{Strings: []string{strings.Repeat("0123456789", 4)}},
	}

	if err := message.Answer(refused); !errors.Is(err, wire.ErrFull) {
		t.Fatalf("want a refusal, got %v", err)
	}

	// The address's last byte, which is a pointer's first, lands where
	// the refused name's second label was.
	for _, record := range []wire.Record{
		{Class: wire.ClassIN, Data: wire.Address{Addr: netip.MustParseAddr("1.2.3.192")}},
		{Name: []string{"x"}, Class: wire.ClassIN, Data: wire.Address{Addr: netip.MustParseAddr("1.2.3.4")}},
	} {
		if err := message.Answer(record); err != nil {
			t.Fatal(err)
		}
	}

	read, err := wire.Parse(message.Bytes())
	if err != nil || len(read.Answers) != 2 || !slices.Equal(read.Answers[1].Name, []string{"x"}) {
		t.Errorf("after a refusal the message reads as %+v, %v", read.Answers, err)
	}
}
