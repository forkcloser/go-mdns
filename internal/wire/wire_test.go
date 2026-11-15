package wire_test

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/forkcloser/go-mdns/internal/wire"
)

// The names of a service, its instance and the host it is on.
func typeName() []string { return []string{"_http", "_tcp", "local"} }
func instance() []string { return []string{"Living Room 2.4GHz", "_http", "_tcp", "local"} }
func host() []string     { return []string{"kitchen", "local"} }

// build writes a message of answers, and fails the test when one is
// refused.
func build(t *testing.T, header wire.Header, options wire.Options, records ...wire.Record) []byte {
	t.Helper()

	builder := wire.NewBuilder(nil, header, options)

	for _, record := range records {
		if err := builder.Answer(record); err != nil {
			t.Fatalf("adding %v: %v", record, err)
		}
	}

	return builder.Bytes()
}

// A browsing question, byte for byte as RFC 1035 and RFC 6762 have it.
func TestAQuestionIsWrittenAsTheRFCsHaveIt(t *testing.T) {
	t.Parallel()

	builder := wire.NewBuilder(nil, wire.Header{}, wire.Options{})

	for _, question := range []wire.Question{
		{Name: typeName(), Type: wire.TypePTR, Class: wire.ClassIN, Unicast: true},
		{Name: []string{"_ipp", "_tcp", "local"}, Type: wire.TypePTR, Class: wire.ClassIN},
	} {
		if err := builder.Question(question); err != nil {
			t.Fatal(err)
		}
	}

	want := "\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00" +
		"\x05_http\x04_tcp\x05local\x00\x00\x0c\x80\x01" +
		// The second name ends as the first does: a pointer to "_tcp".
		"\x04_ipp\xc0\x12\x00\x0c\x00\x01"

	if got := builder.Bytes(); string(got) != want {
		t.Errorf("written as %q, want %q", got, want)
	}
}

// What a host says of a service, there and back: every kind of data,
// the bits taken from the class, a label with a dot in it.
func TestAMessageIsReadAsItWasWritten(t *testing.T) {
	t.Parallel()

	header := wire.Header{Response: true, Authoritative: true}
	records := []wire.Record{
		{Name: typeName(), Class: wire.ClassIN, TTL: 4500, Data: wire.Pointer{Kind: wire.TypePTR, Target: instance()}},
		{
			Name:  instance(),
			Class: wire.ClassIN,
			Flush: true,
			TTL:   120,
			Data:  wire.Service{Priority: 1, Weight: 2, Port: 8080, Target: host()},
		},
		{
			Name:  instance(),
			Class: wire.ClassIN,
			Flush: true,
			TTL:   4500,
			Data:  wire.Text{Strings: []string{"path=/", "secure", "empty="}},
		},
		{
			Name:  host(),
			Class: wire.ClassIN,
			Flush: true,
			TTL:   120,
			Data:  wire.Address{Addr: netip.MustParseAddr("192.0.2.7")},
		},
		{
			Name:  host(),
			Class: wire.ClassIN,
			Flush: true,
			TTL:   120,
			Data:  wire.Address{Addr: netip.MustParseAddr("fe80::1")},
		},
		{
			Name:  host(),
			Class: wire.ClassIN,
			Flush: true,
			TTL:   120,
			Data:  wire.NSEC{Next: host(), Types: []uint16{wire.TypeA, wire.TypeAAAA}},
		},
		{
			Name:  host(),
			Class: wire.ClassIN,
			TTL:   120,
			Data:  wire.NSEC{Next: host(), Types: []uint16{wire.TypeA, 300, 65535}},
		},
		{Name: host(), Class: wire.ClassIN, TTL: 120, Data: wire.Pointer{Kind: wire.TypeCNAME, Target: instance()}},
		{Name: host(), Class: wire.ClassIN, TTL: 7, Data: wire.Opaque{Kind: 13, Bytes: []byte("\x03ARM\x05Linux")}},
	}

	packet := build(t, header, wire.Options{}, records...)

	got, err := wire.Parse(packet)
	if err != nil {
		t.Fatal(err)
	}

	if want := (wire.Message{Header: header, Answers: records}); !reflect.DeepEqual(got, want) {
		t.Errorf("read as\n%+v\nwant\n%+v", got, want)
	}

	// Written out, the names alone are more than the whole message is.
	if plain := 2*len(
		"_http._tcp.local.",
	) + 4*len(
		"Living Room 2.4GHz._http._tcp.local.",
	) + 7*len(
		"kitchen.local.",
	); len(
		packet,
	) >= plain+len(
		records,
	)*10 {
		t.Errorf("%d bytes: the names were not compressed", len(packet))
	}
}

// The form of NSEC RFC 6762 asks for: the name it is of as two bytes,
// one window, as long as its last type needs.
func TestNSECIsWrittenInTheRestrictedForm(t *testing.T) {
	t.Parallel()

	packet := build(t, wire.Header{Response: true}, wire.Options{}, wire.Record{
		Name:  host(),
		Class: wire.ClassIN,
		TTL:   120,
		Data:  wire.NSEC{Next: host(), Types: []uint16{wire.TypeAAAA, wire.TypeA, wire.TypeA}},
	})

	// A is the second bit of the first byte, AAAA the fifth of the fourth.
	if want := "\x00\x08\xc0\x0c\x00\x04\x40\x00\x00\x08"; !strings.HasSuffix(string(packet), want) {
		t.Errorf("written as %q, to end in %q", packet, want)
	}
}

// A text record always says something, if only one empty string; and
// one that says nothing is read as none, however it was written.
func TestATextRecordWithNothingToSay(t *testing.T) {
	t.Parallel()

	packet := build(
		t,
		wire.Header{Response: true},
		wire.Options{},
		wire.Record{Name: host(), Class: wire.ClassIN, Data: wire.Text{}},
	)

	if !bytes.HasSuffix(packet, []byte("\x00\x01\x00")) {
		t.Errorf("written as %q, to end in a length of one and an empty string", packet)
	}

	// The same record with no data at all, which is not allowed and is
	// seen.
	empty := append(bytes.Clone(packet[:len(packet)-3]), 0, 0)

	for _, read := range [][]byte{packet, empty} {
		got, err := wire.Parse(read)
		if err != nil || len(got.Answers) != 1 || !reflect.DeepEqual(got.Answers[0].Data, wire.Text{}) {
			t.Errorf("%q read as %+v, %v", read, got, err)
		}
	}
}

// A resolver that is not a Multicast DNS one may not read a compressed
// SRV target: for it the target is written in full, and nothing else.
func TestAnSRVTargetIsNotCompressedForALegacyResolver(t *testing.T) {
	t.Parallel()

	records := []wire.Record{
		{Name: host(), Class: wire.ClassIN, TTL: 10, Data: wire.Address{Addr: netip.MustParseAddr("192.0.2.7")}},
		{Name: instance(), Class: wire.ClassIN, TTL: 10, Data: wire.Service{Port: 80, Target: host()}},
	}

	usual := build(t, wire.Header{Response: true}, wire.Options{}, records...)
	legacy := build(t, wire.Header{Response: true, ID: 77}, wire.Options{Legacy: true}, records...)

	if !bytes.HasSuffix(legacy, []byte("\x00\x50\x07kitchen\x05local\x00")) {
		t.Errorf("written as %q, to end in the target in full", legacy)
	}

	if grown := len(legacy) - len(usual); grown != len("\x07kitchen\x05local\x00")-2 {
		t.Errorf("%d bytes more than the usual: more than the target was written in full", grown)
	}

	got, err := wire.Parse(legacy)
	if err != nil || !reflect.DeepEqual(got.Answers, records) || got.Header.ID != 77 {
		t.Errorf("read as %+v, %v", got, err)
	}
}

// A record that does not fit is refused and leaves no trace: not a
// byte, and not a name for a later record to point at.
func TestWhatDoesNotFitLeavesTheMessageAsItWas(t *testing.T) {
	t.Parallel()

	small := wire.Record{
		Name:  host(),
		Class: wire.ClassIN,
		TTL:   120,
		Data:  wire.Address{Addr: netip.MustParseAddr("192.0.2.7")},
	}
	large := wire.Record{
		Name:  []string{"elsewhere", "local"},
		Class: wire.ClassIN,
		Data:  wire.Text{Strings: []string{strings.Repeat("x", 200)}},
	}
	after := wire.Record{
		Name:  []string{"elsewhere", "local"},
		Class: wire.ClassIN,
		Data:  wire.Address{Addr: netip.MustParseAddr("192.0.2.8")},
	}

	builder := wire.NewBuilder(nil, wire.Header{Response: true}, wire.Options{Limit: 100})
	if !builder.Empty() {
		t.Error("a message with nothing in it is not empty")
	}

	if err := builder.Answer(small); err != nil {
		t.Fatal(err)
	}

	before := bytes.Clone(builder.Bytes())

	if err := builder.Answer(large); !errors.Is(err, wire.ErrFull) {
		t.Fatalf("a record that does not fit: %v", err)
	}

	if !bytes.Equal(builder.Bytes(), before) {
		t.Error("a record that was refused changed the message")
	}

	if err := builder.Answer(after); err != nil {
		t.Fatal(err)
	}

	builder.Truncated()

	got, err := wire.Parse(builder.Bytes())
	if err != nil || !reflect.DeepEqual(got.Answers, []wire.Record{small, after}) || !got.Header.Truncated ||
		builder.Empty() {
		t.Errorf("read as %+v, %v", got, err)
	}
}

// A message is written after what the buffer holds, and its pointers
// count from where it begins.
func TestAMessageIsWrittenAfterWhatTheBufferHolds(t *testing.T) {
	t.Parallel()

	records := []wire.Record{
		{Name: typeName(), Class: wire.ClassIN, Data: wire.Pointer{Kind: wire.TypePTR, Target: instance()}},
		{Name: instance(), Class: wire.ClassIN, Data: wire.Service{Target: host()}},
	}

	builder := wire.NewBuilder([]byte("before"), wire.Header{Response: true}, wire.Options{})
	for _, record := range records {
		if err := builder.Answer(record); err != nil {
			t.Fatal(err)
		}
	}

	whole := builder.Bytes()
	if !bytes.Equal(whole[len("before"):], build(t, wire.Header{Response: true}, wire.Options{}, records...)) {
		t.Error("the message is not the one written alone")
	}
}

func TestWhatCannotBeWritten(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 63)

	for what, record := range map[string]wire.Record{
		"no data":                 {Name: host()},
		"an address that is none": {Name: host(), Data: wire.Address{}},
		"an empty label":          {Name: []string{"a", "", "local"}, Data: wire.Text{}},
		"a label of 64 bytes":     {Name: []string{long + "x"}, Data: wire.Text{}},
		"a name of 256 bytes":     {Name: []string{long, long, long, long}, Data: wire.Text{}},
		"a string of 256":         {Name: host(), Data: wire.Text{Strings: []string{strings.Repeat("x", 256)}}},
		"a target too long":       {Name: host(), Data: wire.Pointer{Target: []string{long + "x"}}},
	} {
		builder := wire.NewBuilder(nil, wire.Header{}, wire.Options{})
		if err := builder.Answer(record); !errors.Is(err, wire.ErrInvalid) || !builder.Empty() {
			t.Errorf("%s: %v", what, err)
		}
	}

	// A name of 255 bytes is the longest there is.
	fits := wire.Record{Name: []string{long, long, long, long[:61]}, Data: wire.Text{}}
	if err := wire.NewBuilder(nil, wire.Header{}, wire.Options{}).Answer(fits); err != nil {
		t.Errorf("a name of 255 bytes: %v", err)
	}

	// The sections come in order.
	builder := wire.NewBuilder(nil, wire.Header{}, wire.Options{})
	if err := builder.Additional(fits); err != nil {
		t.Fatal(err)
	}

	if err := builder.Question(wire.Question{Name: host()}); !errors.Is(err, wire.ErrInvalid) {
		t.Errorf("a question after an additional record: %v", err)
	}
}

// What two hosts that want one name compare: the data, no name in it
// compressed.
func TestDataIsWrittenAloneWithNothingCompressed(t *testing.T) {
	t.Parallel()

	got, err := wire.AppendData([]byte("kitchen"), wire.Service{Port: 80, Target: host()})
	if want := "kitchen\x00\x00\x00\x00\x00\x50\x07kitchen\x05local\x00"; err != nil || string(got) != want {
		t.Errorf("written as %q, %v", got, err)
	}

	if _, err = wire.AppendData(nil, nil); !errors.Is(err, wire.ErrInvalid) {
		t.Errorf("no data: %v", err)
	}
}
