package mdns_test

import (
	"errors"
	"testing"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// A record given as its bytes is held to what a record of its type
// holds, for the types whose data has a shape: an address of three
// bytes, a name that does not end, a string longer than what is left,
// are bytes every host hearing them drops, this package's own reader
// first, and they were published, asked for and defended. A name
// written as a pointer into a message is refused too: it points nowhere
// in the message the record is said in. A type with no shape takes any
// bytes.
func TestARawRecordIsHeldToItsType(t *testing.T) {
	t.Parallel()

	var network mdnstest.Network

	peer, err := mdns.Open(t.Context(), mdns.Config{Network: network.Host()})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = peer.Close() }()

	const (
		ns, cname, soa, null, hinfo, mx, dname = 2, 5, 6, 10, 13, 15, 39
	)

	host := mdns.Name{"kitchen", "local"}
	name := "\x07kitchen\x05local\x00"

	for what, raw := range map[string]mdns.Raw{
		"an address":                    {Kind: mdns.TypeA, Bytes: []byte{192, 0, 2, 1}},
		"an IPv6 address":               {Kind: mdns.TypeAAAA, Bytes: make([]byte, 16)},
		"a pointer":                     {Kind: mdns.TypePTR, Bytes: []byte(name)},
		"a service":                     {Kind: mdns.TypeSRV, Bytes: []byte("\x00\x00\x00\x00\x00\x50" + name)},
		"a text":                        {Kind: mdns.TypeTXT, Bytes: []byte("\x03a=b\x01c")},
		"a name server":                 {Kind: ns, Bytes: []byte(name)},
		"an alias":                      {Kind: cname, Bytes: []byte(name)},
		"an alias of names below":       {Kind: dname, Bytes: []byte(name)},
		"a mail exchanger":              {Kind: mx, Bytes: []byte("\x00\x0a" + name)},
		"a start of authority":          {Kind: soa, Bytes: []byte(name + name + "\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05")},
		"what a host is":                {Kind: hinfo, Bytes: []byte("\x03ARM\x05Linux")},
		"bytes of no shape":             {Kind: null, Bytes: []byte{1, 2, 3}},
		"a type no one has a name for":  {Kind: 65280, Bytes: []byte{0xC0, 0x0C}},
		"a type no one has, of nothing": {Kind: 65280},
	} {
		if err = peer.ReconfirmRecord(mdns.Record{Name: host, Data: raw}); err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}

	for what, raw := range map[string]mdns.Raw{
		"an address of three bytes":           {Kind: mdns.TypeA, Bytes: []byte{192, 0, 2}},
		"an address of five bytes":            {Kind: mdns.TypeA, Bytes: []byte{192, 0, 2, 1, 0}},
		"an IPv6 address of fifteen bytes":    {Kind: mdns.TypeAAAA, Bytes: make([]byte, 15)},
		"a pointer whose name does not end":   {Kind: mdns.TypePTR, Bytes: []byte("\x07kitchen")},
		"a pointer with a byte after":         {Kind: mdns.TypePTR, Bytes: []byte(name + "\x00")},
		"a pointer into the message":          {Kind: mdns.TypePTR, Bytes: []byte{0xC0, 0x0C}},
		"a service of five bytes":             {Kind: mdns.TypeSRV, Bytes: []byte{0, 0, 0, 0, 0}},
		"a service whose host points away":    {Kind: mdns.TypeSRV, Bytes: []byte{0, 0, 0, 0, 0, 80, 0xC0, 0x0C}},
		"a text longer than what is left":     {Kind: mdns.TypeTXT, Bytes: []byte("\x05a=b")},
		"an alias that does not end":          {Kind: cname, Bytes: []byte("\x07kitchen")},
		"an alias into the message":           {Kind: cname, Bytes: []byte{0xC0, 0x0C}},
		"a mail exchanger of one byte":        {Kind: mx, Bytes: []byte{0}},
		"a mail exchanger into the message":   {Kind: mx, Bytes: []byte{0, 10, 0xC0, 0x0C}},
		"a start of authority with no number": {Kind: soa, Bytes: []byte(name + name)},
		"a denial of nothing":                 {Kind: mdns.TypeNSEC, Bytes: []byte{1, 'a'}},
	} {
		if err = peer.ReconfirmRecord(mdns.Record{Name: host, Data: raw}); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("%s: %v", what, err)
		}
	}
}
