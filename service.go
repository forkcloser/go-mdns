package mdns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/forkcloser/go-mdns/internal/todo"
)

const (
	// maxServiceName is the most characters a service's name holds after
	// its underscore, by RFC 6335.
	maxServiceName = 15
	// maxEntry is the most bytes one entry of a TXT record holds, and
	// maxTXT the most a whole record does and still fits a message.
	maxEntry = 255
	maxTXT   = 8900
)

// Service is a service a host offers, to announce.
type Service struct {
	// Name is the instance's name, for a person to read: "Kitchen
	// printer". Any text of up to 63 bytes, dots and spaces included.
	// Empty is the host's name, without ".local".
	Name string

	// Type is what kind of service it is and how it is carried:
	// "_http._tcp", "_matter._udp".
	Type string

	// Subtypes are narrower kinds a browser may ask for: "_printer", for
	// a service found as "_printer._sub._http._tcp" too.
	Subtypes []string

	// Port is where the service listens. Zero says the service exists
	// and cannot be reached, which RFC 6763 has a use for.
	Port uint16

	// Text is the service's TXT record: what a client needs to know
	// before it connects. Empty is a record with nothing in it, which
	// every service has.
	Text TXT

	// Priority and Weight are the SRV record's, for a client choosing
	// among several hosts of one instance. Most services leave both
	// zero.
	Priority uint16
	Weight   uint16

	// Host and Addrs announce a service that is somewhere else, on its
	// behalf: the name of the host it is on, and the addresses that
	// host is at, which need be none of this host's. Both, or neither:
	// empty is this host, at its own addresses on each link. The name
	// is claimed as this host's own is, and the addresses are said as
	// they are given, on every interface the service is announced on.
	Host  string
	Addrs []netip.Addr

	// Interfaces says which interfaces to announce on, of those the
	// Peer is on: On("en0"), or any rule. Nil is all of them, those
	// that come up later included.
	Interfaces func(Interface) bool

	// Rename says what to do when another host already announces an
	// instance of this name and type. Nil numbers it.
	Rename Rename

	// TTL is how long a neighbour may remember the service after last
	// hearing of it, for every record of it. Zero is what RFC 6762
	// recommends: 120 seconds for what names a host, 75 minutes for the
	// rest.
	TTL time.Duration
}

// Validate reports a service that cannot be announced, as ErrInvalid
// with why: a name that is not one label of text; a type that is not a
// service name of up to fifteen letters, digits and hyphens under an
// underscore, followed by "_tcp" or "_udp"; a subtype that is not one
// label; a text record out of bounds; a host without addresses, or
// addresses without a host; a TTL below zero.
func (s *Service) Validate() error {
	if s.Name != "" {
		if err := instanceLabel(s.Name); err != nil {
			return err
		}
	}

	if err := announcedType(s.Type); err != nil {
		return err
	}

	for _, subtype := range s.Subtypes {
		if subtype == "" || len(subtype) > maxLabel {
			return fmt.Errorf("%w: the subtype %q is not one label", ErrInvalid, subtype)
		}
	}

	if err := s.Text.Validate(); err != nil {
		return err
	}

	if s.TTL < 0 {
		return fmt.Errorf("%w: a TTL of %s", ErrInvalid, s.TTL)
	}

	return s.elsewhere()
}

// elsewhere is Validate for a service on another host: that host's name
// and its addresses, both or neither.
func (s *Service) elsewhere() error {
	if (s.Host == "") != (len(s.Addrs) == 0) {
		return fmt.Errorf("%w: a service on another host needs that host's name and its addresses, both", ErrInvalid)
	}

	if s.Host != "" {
		if _, err := hostName(s.Host); err != nil {
			return err
		}
	}

	for _, addr := range s.Addrs {
		if !addr.IsValid() {
			return fmt.Errorf("%w: an address that is none", ErrInvalid)
		}
	}

	return nil
}

// serviceType splits a type into its two labels, and says whether they
// are a service's: "_name", then "_tcp" or "_udp".
func serviceType(written string) (service, proto string, err error) {
	service, proto, found := strings.Cut(strings.TrimSuffix(written, "."), ".")

	switch {
	case !found || strings.Contains(proto, "."):
		return "", "", fmt.Errorf("%w: the type %q is not a service and a protocol", ErrInvalid, written)
	case !sameLabel(proto, "_tcp") && !sameLabel(proto, "_udp"):
		return "", "", fmt.Errorf("%w: the type %q is carried by neither _tcp nor _udp", ErrInvalid, written)
	case len(service) < 2 || service[0] != '_' || len(service) > maxLabel:
		return "", "", fmt.Errorf("%w: the type %q does not name a service", ErrInvalid, written)
	}

	return service, proto, nil
}

// announcedType holds a type to RFC 6335, as a service announced has to
// be: what is found may be older than the rule, what is announced may
// not.
func announcedType(written string) error {
	service, _, err := serviceType(written)
	if err != nil {
		return err
	}

	name := service[1:]

	if len(name) > maxServiceName || name[0] == '-' || name[len(name)-1] == '-' || strings.Contains(name, "--") {
		return fmt.Errorf("%w: the type %q is not a service name of RFC 6335", ErrInvalid, written)
	}

	letters := false

	for _, char := range []byte(name) {
		switch {
		case lower(char) >= 'a' && lower(char) <= 'z':
			letters = true
		case isDigit(char) || char == '-':
		default:
			return fmt.Errorf("%w: the type %q is not a service name of RFC 6335", ErrInvalid, written)
		}
	}

	if !letters {
		return fmt.Errorf("%w: the type %q has no letter", ErrInvalid, written)
	}

	return nil
}

// hostName is a host's name as a Name under "local": "printer",
// "printer.local" and "printer.local." are the same host.
func hostName(written string) (Name, error) {
	name, err := ParseName(written)
	if err != nil {
		return nil, err
	}

	if !sameLabel(name[len(name)-1], local) {
		name = append(name, local)
	}

	if err = name.Validate(); err != nil {
		return nil, err
	}

	return name, nil
}

// TXT is a service's text record: entries in the order they are sent.
type TXT []Entry

// Entry is one entry of a text record: a key, and what it is set to.
type Entry struct {
	// Key is the entry's key: printable ASCII but for "=", compared
	// without regard to case.
	Key string
	// Value is what the key is set to, any bytes. Nil is a key with no
	// value, which is not the same as an empty one: "paper" and
	// "paper=" are two entries a service may tell apart.
	Value []byte
}

// Get is what a key is set to, as text, and whether the key is there at
// all. A key with no value is there, set to nothing.
func (t TXT) Get(key string) (string, bool) {
	for _, entry := range t {
		if sameLabel(entry.Key, key) {
			return string(entry.Value), true
		}
	}

	return "", false
}

// Validate reports a text record that cannot be sent, as ErrInvalid: a
// key that is empty, holds "=" or anything but printable ASCII, or is
// there twice; an entry over 255 bytes; a record over 8900.
func (t TXT) Validate() error {
	total := 0

	for index, entry := range t {
		size, err := entry.size()
		if err != nil {
			return err
		}

		for _, earlier := range t[:index] {
			if sameLabel(earlier.Key, entry.Key) {
				return fmt.Errorf("%w: the text key %q is there twice", ErrInvalid, entry.Key)
			}
		}

		total += 1 + size
	}

	if total > maxTXT {
		return fmt.Errorf("%w: the text record is %d bytes, over %d", ErrInvalid, total, maxTXT)
	}

	return nil
}

// size is how many bytes an entry is on the wire, its length byte aside:
// the key, and with a value the "=" and the value. It is ErrInvalid for
// a key that is none and for an entry too long.
func (e Entry) size() (int, error) {
	if e.Key == "" {
		return 0, fmt.Errorf("%w: a text entry with no key", ErrInvalid)
	}

	for _, char := range []byte(e.Key) {
		if char < ' ' || char > '~' || char == '=' {
			return 0, fmt.Errorf("%w: the text key %q is not printable ASCII without \"=\"", ErrInvalid, e.Key)
		}
	}

	size := len(e.Key)
	if e.Value != nil {
		size += 1 + len(e.Value)
	}

	if size > maxEntry {
		return 0, fmt.Errorf("%w: the text entry %q is %d bytes, over %d", ErrInvalid, e.Key, size, maxEntry)
	}

	return size, nil
}

// Announcement is a service being announced.
type Announcement struct{}

// Announce offers a service on every link the Peer is on, and on each it
// comes to be on. It first asks, on each link, whether the name is free,
// as RFC 6762 has it; a name another host holds is put to the service's
// Rename, and the answer tried. It returns once the service is announced
// on the links there are, under the name it ended with, which Name
// gives; or with ErrConflict when Rename gave up, ErrInvalid for a
// service that does not validate, or ctx's error, the service then
// withdrawn.
//
// From then on the Peer answers for the service, defends its name,
// announces it on links that come up, and renames it should a host turn
// up later with the same one.
func (p *Peer) Announce(ctx context.Context, service Service) (*Announcement, error) {
	return nil, todo.ImplementMe(p, ctx, service)
}

// Name is the instance name the service is announced under now: the one
// asked for, or the one it was renamed to.
func (a *Announcement) Name() string {
	_ = todo.ImplementMe(a)

	return ""
}

// Update changes the service's text record and tells the neighbours, as
// RFC 6762 has a changed record told. Nothing else of a service changes
// while it is announced: a new port is a new announcement.
//
// A text that changes more than ten times a minute is more than the
// protocol means to carry: the neighbours are told of the last, not of
// each.
func (a *Announcement) Update(ctx context.Context, text TXT) error {
	return todo.ImplementMe(a, ctx, text)
}

// Close withdraws the service: its neighbours are told goodbye, and
// forget it at once.
func (a *Announcement) Close() error {
	return todo.ImplementMe(a)
}

// Done is closed when the service is no longer announced: withdrawn by
// Close or by the Peer's, or renamed to nothing by Rename.
func (a *Announcement) Done() <-chan struct{} {
	_ = todo.ImplementMe(a)

	return nil
}

// Err is why, once Done is closed: ErrClosed, or ErrConflict. Nil until
// then.
func (a *Announcement) Err() error {
	return todo.ImplementMe(a)
}
