package mdns_test

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/forkcloser/go-mdns"
)

func TestServicesAreHeldToTheirRules(t *testing.T) {
	t.Parallel()

	addr := []netip.Addr{netip.MustParseAddr("192.0.2.1")}

	for name, service := range map[string]mdns.Service{
		"the least":           {Type: "_http._tcp"},
		"over UDP":            {Type: "_matter._udp"},
		"a name with dots":    {Name: "Living Room 2.4GHz", Type: "_http._tcp"},
		"a name not ASCII":    {Name: "Café ☕", Type: "_http._tcp"},
		"a name of 63 bytes":  {Name: strings.Repeat("n", 63), Type: "_http._tcp"},
		"fifteen characters":  {Type: "_fifteen-letters._tcp"},
		"digits and a hyphen": {Type: "_a-1._tcp"},
		"upper case":          {Type: "_HTTP._TCP"},
		"a trailing dot":      {Type: "_http._tcp."},
		"subtypes":            {Type: "_http._tcp", Subtypes: []string{"_printer", "plain"}},
		"no port":             {Type: "_http._tcp", Port: 0},
		"another host":        {Type: "_http._tcp", Host: "elsewhere.local", Addrs: addr},
		"a TTL":               {Type: "_http._tcp", TTL: 2 * time.Minute},
		"text": {Type: "_http._tcp", Text: mdns.TXT{
			{Key: "path", Value: []byte("/")}, {Key: "flag"}, {Key: "empty", Value: []byte{}},
		}},
	} {
		if err := service.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, service := range map[string]mdns.Service{
		"no type":                  {},
		"one label":                {Type: "_http"},
		"three labels":             {Type: "_http._tcp.local"},
		"no underscore":            {Type: "http._tcp"},
		"neither TCP nor UDP":      {Type: "_http._sctp"},
		"an underscore alone":      {Type: "_._tcp"},
		"sixteen characters":       {Type: "_sixteen-letters1._tcp"},
		"a leading hyphen":         {Type: "_-http._tcp"},
		"a trailing hyphen":        {Type: "_http-._tcp"},
		"two hyphens together":     {Type: "_ht--tp._tcp"},
		"no letter":                {Type: "_123._tcp"},
		"a character that is none": {Type: "_ht_tp._tcp"},
		"a name of 64 bytes":       {Name: strings.Repeat("n", 64), Type: "_http._tcp"},
		"a name not UTF-8":         {Name: "bad\xff", Type: "_http._tcp"},
		"a name with a control":    {Name: "bell\a", Type: "_http._tcp"},
		"an empty subtype":         {Type: "_http._tcp", Subtypes: []string{""}},
		"a subtype of 64 bytes":    {Type: "_http._tcp", Subtypes: []string{strings.Repeat("s", 64)}},
		"a host with no address":   {Type: "_http._tcp", Host: "elsewhere.local"},
		"addresses with no host":   {Type: "_http._tcp", Addrs: addr},
		"an address that is none":  {Type: "_http._tcp", Host: "elsewhere", Addrs: []netip.Addr{{}}},
		"a host that is no name":   {Type: "_http._tcp", Host: "a..b", Addrs: addr},
		"a TTL below zero":         {Type: "_http._tcp", TTL: -time.Second},
		"text out of bounds":       {Type: "_http._tcp", Text: mdns.TXT{{Key: "a=b"}}},
	} {
		if err := service.Validate(); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTextIsHeldToItsRules(t *testing.T) {
	t.Parallel()

	text := mdns.TXT{
		{Key: "path", Value: []byte("/index")},
		{Key: "Paper"},
		{Key: "empty", Value: []byte{}},
		{Key: "bytes", Value: []byte{0, 1, 0xFF}},
	}

	if err := text.Validate(); err != nil {
		t.Fatal(err)
	}

	for key, want := range map[string]string{"path": "/index", "PATH": "/index", "paper": "", "empty": "", "bytes": "\x00\x01\xff"} {
		if got, there := text.Get(key); !there || got != want {
			t.Errorf("%s is set to %q, there %t", key, got, there)
		}
	}

	if got, there := text.Get("absent"); there || got != "" {
		t.Errorf("a key that is not there is set to %q", got)
	}

	// The bounds, each at its edge: 255 bytes for an entry, 8900 for the
	// record, a length byte counted for each entry.
	edge := mdns.TXT{{Key: "k", Value: []byte(strings.Repeat("v", 253))}}
	if err := edge.Validate(); err != nil {
		t.Errorf("an entry of 255 bytes: %v", err)
	}

	whole := make(mdns.TXT, 0, 89)
	for index := range 89 {
		whole = append(whole, mdns.Entry{Key: fmt.Sprintf("k%02d", index), Value: []byte(strings.Repeat("v", 95))})
	}

	if err := whole.Validate(); err != nil {
		t.Errorf("a record of 8900 bytes: %v", err)
	}

	whole[0].Value = append(whole[0].Value, 'v')

	for name, bad := range map[string]mdns.TXT{
		"no key":                 {{Value: []byte("v")}},
		"an equals sign":         {{Key: "a=b"}},
		"a key not ASCII":        {{Key: "clé"}},
		"a control character":    {{Key: "a\tb"}},
		"a key twice":            {{Key: "a"}, {Key: "b"}, {Key: "A", Value: []byte("1")}},
		"an entry of 256 bytes":  {{Key: "k", Value: []byte(strings.Repeat("v", 254))}},
		"a key of 256 bytes":     {{Key: strings.Repeat("k", 256)}},
		"a record of 8901 bytes": whole,
	} {
		if err := bad.Validate(); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
