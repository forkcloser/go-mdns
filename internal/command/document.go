package command

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/forkcloser/go-mdns"
)

// errDocument is a document that does not say what to announce.
var errDocument = errors.New("not a document of services")

// document is what to announce, as it is written.
type document struct {
	// Hostname is the name the host answers to. Empty is the system's.
	Hostname string            `json:"hostname"`
	Services []json.RawMessage `json:"services"`
}

// service is one service of a document: a mdns.Service, field for field.
type service struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	Port       *uint16      `json:"port"`
	Subtypes   []string     `json:"subtypes"`
	Text       []entry      `json:"text"`
	Priority   uint16       `json:"priority"`
	Weight     uint16       `json:"weight"`
	Host       string       `json:"host"`
	Addresses  []netip.Addr `json:"addresses"`
	Interfaces []string     `json:"interfaces"`
	TTL        duration     `json:"ttl"`
	// Rename is whether to take another name when this one is taken.
	// Left out, it is.
	Rename *bool `json:"rename"`
}

// entry is an entry of a text record: a string as it goes on the wire,
// "key=value" or "key"; or, for a value that is not text, an object
// with the key and the value in base64.
type entry mdns.Entry

func (e *entry) UnmarshalJSON(written []byte) error {
	var plain string

	if json.Unmarshal(written, &plain) == nil {
		key, value, valued := bytes.Cut([]byte(plain), []byte("="))
		e.Key, e.Value = string(key), nil

		if valued {
			e.Value = value
		}

		return nil
	}

	var binary struct {
		Key    string `json:"key"`
		Base64 string `json:"base64"`
	}

	if err := strict(written, &binary); err != nil {
		return fmt.Errorf("a text entry is a string, or a key and a value in base64: %w", err)
	}

	value, err := base64.StdEncoding.DecodeString(binary.Base64)
	if err != nil {
		return fmt.Errorf("the value of the text key %q: %w", binary.Key, err)
	}

	e.Key, e.Value = binary.Key, value

	return nil
}

// MarshalJSON writes an entry as it is read: a string when its value is
// text, an object when it is not.
func (e entry) MarshalJSON() ([]byte, error) {
	var written any

	switch {
	case e.Value == nil:
		written = e.Key
	case utf8.Valid(e.Value):
		written = e.Key + "=" + string(e.Value)
	default:
		written = map[string]string{"key": e.Key, "base64": base64.StdEncoding.EncodeToString(e.Value)}
	}

	encoded, err := json.Marshal(written)
	if err != nil {
		return nil, fmt.Errorf("writing the text key %q: %w", e.Key, err)
	}

	return encoded, nil
}

// duration is a length of time as Go writes one: "2m", "90s".
type duration time.Duration

func (d *duration) UnmarshalJSON(written []byte) error {
	var plain string

	if err := json.Unmarshal(written, &plain); err != nil {
		return fmt.Errorf("a length of time is a string, as \"2m\": %w", err)
	}

	parsed, err := time.ParseDuration(plain)
	if err != nil {
		return fmt.Errorf("a length of time: %w", err)
	}

	*d = duration(parsed)

	return nil
}

// strict reads JSON into a value, and refuses a field the value has
// not: a misspelt field left out is worse than a refusal.
func strict(written []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(written))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("%w: %w", errDocument, err)
	}

	if decoder.More() {
		return fmt.Errorf("%w: something follows it", errDocument)
	}

	return nil
}

// wanted is what a document asks for: the host's name, and its services
// as the library takes them, each with whether it may be renamed.
type wanted struct {
	hostname string
	services []asked
}

// asked is one service asked for.
type asked struct {
	service mdns.Service
	rename  bool
}

// read reads a document, and says of a service that cannot be announced
// which it is and why.
func read(written []byte) (wanted, error) {
	var whole document

	if err := strict(written, &whole); err != nil {
		return wanted{}, err
	}

	if len(whole.Services) == 0 {
		return wanted{}, fmt.Errorf("%w: it has no service", errDocument)
	}

	read := wanted{hostname: whole.Hostname}

	for index, raw := range whole.Services {
		var one service

		if err := strict(raw, &one); err != nil {
			return wanted{}, fmt.Errorf("service %d: %w", index+1, err)
		}

		if one.Port == nil {
			return wanted{}, fmt.Errorf("service %d: %w: it has no port", index+1, errDocument)
		}

		announced := one.announced()
		if err := announced.service.Validate(); err != nil {
			return wanted{}, fmt.Errorf("service %d: %w", index+1, err)
		}

		read.services = append(read.services, announced)
	}

	return read, nil
}

// announced is a service of a document as the library takes one.
func (s *service) announced() asked {
	text := make(mdns.TXT, len(s.Text))
	for index, one := range s.Text {
		text[index] = mdns.Entry(one)
	}

	announced := mdns.Service{
		Name: s.Name, Type: s.Type, Subtypes: s.Subtypes, Port: *s.Port, Text: text,
		Priority: s.Priority, Weight: s.Weight, Host: s.Host, Addrs: s.Addresses, TTL: time.Duration(s.TTL),
	}

	if len(s.Interfaces) > 0 {
		announced.Interfaces = mdns.On(s.Interfaces...)
	}

	return asked{service: announced, rename: s.Rename == nil || *s.Rename}
}
