package command_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/internal/command"
	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/mdnstest"
	"github.com/forkcloser/go-mdns/transport"
)

// buffer is what a command says, read while it runs.
type buffer struct {
	mu      sync.Mutex
	written bytes.Buffer
}

func (b *buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.written.Write(p)
}

func (b *buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.written.String()
}

// lines is the lines of JSON said so far, each as an object.
func (b *buffer) lines(t *testing.T) []map[string]any {
	t.Helper()

	var said []map[string]any

	for line := range strings.Lines(b.String()) {
		var one map[string]any

		if err := json.Unmarshal([]byte(line), &one); err != nil {
			t.Fatalf("said %q, which is not JSON: %v", line, err)
		}

		said = append(said, one)
	}

	return said
}

// running is a command under way.
type running struct {
	out, err buffer
	code     chan int
	stop     context.CancelFunc
}

// ended is how the command ended; a command that has not, an hour on,
// is not going to.
func (r *running) ended(t *testing.T) int {
	t.Helper()

	select {
	case code := <-r.code:
		// Left for the end of the test, which waits for it too.
		r.code <- code

		return code
	case <-time.After(time.Hour):
		t.Fatal("the command has not ended")

		return 0
	}
}

// lan is an interface on the wire, at 192.0.2.last.
func lan(last string) mdnstest.Port {
	return mdnstest.Port{
		Interface: "en0",
		Wire:      "lan",
		Addrs:     []netip.Prefix{netip.MustParsePrefix("192.0.2." + last + "/24")},
	}
}

// run runs the command on a host of the network, and stops it with the
// test.
func run(t *testing.T, network *mdnstest.Network, in string, args ...string) *running {
	t.Helper()

	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	started := &running{code: make(chan int, 1), stop: stop}

	go func() {
		started.code <- command.Run(ctx, command.Environment{
			Args: args, In: strings.NewReader(in), Out: &started.out, Err: &started.err,
			Network: network.Host(lan("1")),
		})
	}()

	t.Cleanup(func() {
		stop()
		<-started.code
	})

	return started
}

// watcher is a Peer on the wire, and what its Browse for web services
// stands at.
type watcher struct {
	peer  *mdns.Peer
	told  chan func(map[string]mdns.Instance)
	known map[string]mdns.Instance
}

func watch(t *testing.T, network *mdnstest.Network) *watcher {
	t.Helper()

	peer, err := mdns.Open(t.Context(), mdns.Config{Network: network.Host(lan("2"))})
	if err != nil {
		t.Fatal(err)
	}

	watching := &watcher{
		peer:  peer,
		told:  make(chan func(map[string]mdns.Instance), 64),
		known: map[string]mdns.Instance{},
	}
	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	ended := make(chan struct{})

	go func() {
		defer close(ended)

		_ = peer.Browse(ctx, mdns.Query{Type: "_http._tcp"}, func(change mdns.Change, found mdns.Instance) {
			// An instance is one by its name, its host and its port.
			ident := fmt.Sprintf("%s at %s:%d", found.Name, found.Host, found.Port)

			watching.told <- func(known map[string]mdns.Instance) {
				if change == mdns.Lost {
					delete(known, ident)
				} else {
					known[ident] = found
				}
			}
		})
	}()

	t.Cleanup(func() {
		stop()
		<-ended

		_ = peer.Close()
	})

	return watching
}

// stands is the services the watcher knows of now, by name.
func (w *watcher) stands() map[string]mdns.Instance {
	synctest.Wait()

	for len(w.told) > 0 {
		(<-w.told)(w.known)
	}

	named := map[string]mdns.Instance{}
	for _, found := range w.known {
		named[found.Name] = found
	}

	return named
}

// events is the events said, each with the name it is of.
func events(t *testing.T, said *buffer) []string {
	t.Helper()

	var listed []string

	for _, one := range said.lines(t) {
		listed = append(listed, fmt.Sprintf("%v %v", one["event"], one["name"]))
	}

	return listed
}

const document = `{
  "hostname": "kitchen",
  "services": [
    {"name": "Kitchen display", "type": "_http._tcp", "port": 8080, "subtypes": ["_printer"],
     "text": ["path=/", "secure", {"key": "id", "base64": "3q2+7w=="}], "priority": 1, "weight": 2, "ttl": "2m"},
    {"name": "Garden camera", "type": "_http._tcp", "port": 554, "host": "garden-camera", "addresses": ["192.0.2.40"]}
  ]
}`

// A document of two services, read from standard input: both are
// announced as it says, said so as JSON, and withdrawn when the command
// is told to stop.
func TestADocumentIsAnnounced(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		watching := watch(t, &network)
		announcing := run(t, &network, document, "announce", "-")

		time.Sleep(5 * time.Second)

		en0 := []mdns.Interface{{Index: 1, Name: "en0"}}
		want := map[string]mdns.Instance{
			"Kitchen display": {
				Name:       "Kitchen display",
				Type:       "_http._tcp",
				Interfaces: en0,
				Host:       "kitchen.local",
				Port:       8080,
				Priority:   1,
				Weight:     2,
				Text: mdns.TXT{
					{Key: "path", Value: []byte("/")},
					{Key: "secure"},
					{Key: "id", Value: []byte{0xde, 0xad, 0xbe, 0xef}},
				},
				Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			},
			"Garden camera": {
				Name: "Garden camera", Type: "_http._tcp", Interfaces: en0, Host: "garden-camera.local", Port: 554,
				Text: mdns.TXT{}, Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.40")},
			},
		}

		if got := watching.stands(); !reflect.DeepEqual(got, want) {
			t.Errorf("found\n%+v\nwant\n%+v", got, want)
		}

		said := []map[string]any{
			{
				"event": "announced",
				"name":  "Kitchen display",
				"asked": "Kitchen display",
				"type":  "_http._tcp",
				"host":  "kitchen.local",
			},
			{
				"event": "announced",
				"name":  "Garden camera",
				"asked": "Garden camera",
				"type":  "_http._tcp",
				"host":  "kitchen.local",
			},
		}

		if got := announcing.out.lines(t); !reflect.DeepEqual(got, said) {
			t.Errorf("said\n%v\nwant\n%v", got, said)
		}

		// Two minutes, as the document says, for every record of it.
		ctx, stop := context.WithCancel(t.Context())

		_ = watching.peer.Ask(
			ctx,
			mdns.Question{Name: mdns.Name{"Kitchen display", "_http", "_tcp", "local"}, Type: mdns.TypeTXT},
			func(_ mdns.Change, answer mdns.Answer) {
				if answer.Record.TTL != 2*time.Minute {
					t.Errorf("a text record good for %s", answer.Record.TTL)
				}

				stop()
			},
		)

		announcing.stop()

		if code := announcing.ended(t); code != command.Done || announcing.err.String() != "" {
			t.Errorf("ended with %d, saying %q", code, announcing.err.String())
		}

		time.Sleep(2 * time.Second)

		if got := watching.stands(); len(got) != 0 {
			t.Errorf("still found once the command ended: %+v", got)
		}
	})
}

// One service, said with flags; a name that is taken is numbered, and
// said so.
func TestAServiceSaidWithFlags(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		watching := watch(t, &network)

		taken, err := watching.peer.Announce(t.Context(), mdns.Service{Name: "Kitchen", Type: "_http._tcp", Port: 1})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = taken.Close() }()

		announcing := run(
			t,
			&network,
			"",
			"announce",
			"--type",
			"_http._tcp",
			"--port",
			"8080",
			"--name",
			"Kitchen",
			"--txt",
			"path=/",
			"--txt",
			"secure",
			"--txt",
			"empty=",
			"--subtype",
			"_printer",
			"--interface",
			"en0",
			"--ttl",
			"1m",
			"--hostname",
			"oven",
		)

		time.Sleep(5 * time.Second)

		got := watching.stands()["Kitchen (2)"]
		want := mdns.TXT{{Key: "path", Value: []byte("/")}, {Key: "secure"}, {Key: "empty", Value: []byte{}}}

		if got.Host != "oven.local" || got.Port != 8080 || !reflect.DeepEqual(got.Text, want) {
			t.Errorf("found %+v", got)
		}

		if said := events(
			t,
			&announcing.out,
		); !reflect.DeepEqual(
			said,
			[]string{"renamed Kitchen (2)", "announced Kitchen (2)"},
		) {
			t.Errorf("said %v", said)
		}
	})
}

// A name that is taken, and no other wanted: nothing of the document is
// left announced, and the command says why and leaves with an error.
func TestANameThatIsTakenAndNoOtherWanted(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		watching := watch(t, &network)

		taken, err := watching.peer.Announce(t.Context(), mdns.Service{Name: "Kitchen", Type: "_http._tcp", Port: 1})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = taken.Close() }()

		announcing := run(t, &network, `{"services": [
			{"name": "Pantry", "type": "_http._tcp", "port": 80},
			{"name": "Kitchen", "type": "_http._tcp", "port": 80, "rename": false}]}`, "announce", "-")

		if code := announcing.ended(t); code != command.Failed ||
			!strings.Contains(announcing.err.String(), `"Kitchen"`) {
			t.Errorf("ended with %d, saying %q", code, announcing.err.String())
		}

		time.Sleep(2 * time.Second)

		if got := watching.stands(); len(got) != 1 || got["Kitchen"].Port != 1 {
			t.Errorf("found %+v", got)
		}
	})
}

// A document read from a file: its services are announced, each on
// the interfaces it names and no other.
func TestADocumentReadFromAFile(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		path := filepath.Join(t.TempDir(), "services.json")
		if err := os.WriteFile(path, []byte(`{"services": [
			{"name": "Here", "type": "_http._tcp", "port": 1, "interfaces": ["en0"]},
			{"name": "Elsewhere", "type": "_http._tcp", "port": 7, "interfaces": ["en9"]}]}`), 0o600); err != nil {
			t.Fatal(err)
		}

		watching := watch(t, &network)
		announcing := run(t, &network, "", "announce", path)

		time.Sleep(5 * time.Second)

		got := watching.stands()
		if len(got) != 1 || got["Here"].Port != 1 {
			t.Errorf("found %+v", got)
		}

		if said := events(
			t,
			&announcing.out,
		); !reflect.DeepEqual(
			said,
			[]string{"announced Here", "announced Elsewhere"},
		) {
			t.Errorf("said %v", said)
		}
	})
}

// A service written twice is announced twice, the second under another
// name and said to be; where no other name is wanted, the command ends
// as for any name that is taken.
func TestAServiceWrittenTwice(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		watching := watch(t, &network)
		announcing := run(t, &network, `{"hostname": "kitchen", "services": [
			{"name": "Oven", "type": "_http._tcp", "port": 1},
			{"name": "Oven", "type": "_http._tcp.", "port": 2},
			{"type": "_http._tcp", "port": 3},
			{"name": "Kitchen", "type": "_http._tcp", "port": 4}]}`, "announce", "-")

		time.Sleep(10 * time.Second)

		ports := map[string]uint16{}
		for name, found := range watching.stands() {
			ports[name] = found.Port
		}

		if want := map[string]uint16{
			"Oven": 1, "Oven (2)": 2, "kitchen": 3, "Kitchen (2)": 4,
		}; !reflect.DeepEqual(ports, want) {
			t.Errorf("found %v, want %v", ports, want)
		}

		if said, want := events(t, &announcing.out), []string{
			"announced Oven", "renamed Oven (2)", "announced Oven (2)",
			"announced kitchen", "renamed Kitchen (2)", "announced Kitchen (2)",
		}; !reflect.DeepEqual(said, want) {
			t.Errorf("said %v, want %v", said, want)
		}

		refused := run(t, &network, `{"services": [
			{"name": "Stove", "type": "_http._tcp", "port": 1},
			{"name": "Stove", "type": "_http._tcp", "port": 2, "rename": false}]}`, "announce", "-")

		if code := refused.ended(t); code != command.Failed {
			t.Errorf("a service written twice, and no other name wanted: ended with %d, %q", code, refused.err.String())
		}
	})
}

// What the command refuses, and how it says so: with what is wrong and
// where, and the mark of having been asked wrongly.
func TestWhatTheCommandRefuses(t *testing.T) {
	t.Parallel()

	for what, row := range map[string]struct {
		in   string
		args []string
		says string
	}{
		"nothing":                      {args: nil, says: "mdns announces services"},
		"no such verb":                 {args: []string{"shout"}, says: "mdns announces services"},
		"a field that is none":         {args: []string{"announce", "-"}, in: `{"services": [{"type": "_http._tcp", "port": 1}, {"type": "_http._tcp", "prot": 80}]}`, says: `service 2: not a document of services: json: unknown field "prot"`},
		"no port":                      {args: []string{"announce", "-"}, in: `{"services": [{"type": "_http._tcp"}]}`, says: "service 1: not a document of services: it has no port"},
		"a type that is none":          {args: []string{"announce", "-"}, in: `{"services": [{"type": "http", "port": 1}]}`, says: "service 1: not valid in Multicast DNS"},
		"no service":                   {args: []string{"announce", "-"}, in: `{"hostname": "kitchen"}`, says: "it has no service"},
		"not JSON":                     {args: []string{"announce", "-"}, in: `services:`, says: "not a document of services"},
		"two documents":                {args: []string{"announce", "-"}, in: `{"services": [{"type": "_http._tcp", "port": 1}]} {}`, says: "something follows it"},
		"a text entry of no kind":      {args: []string{"announce", "-"}, in: `{"services": [{"type": "_http._tcp", "port": 1, "text": [7]}]}`, says: "a text entry is a string"},
		"a value that is not base64":   {args: []string{"announce", "-"}, in: `{"services": [{"type": "_http._tcp", "port": 1, "text": [{"key": "id", "base64": "!"}]}]}`, says: `the value of the text key "id"`},
		"a time that is none":          {args: []string{"announce", "-"}, in: `{"services": [{"type": "_http._tcp", "port": 1, "ttl": "soon"}]}`, says: "a length of time"},
		"a document and flags":         {args: []string{"announce", "--port", "1", "file.json"}, says: "announce FILE, or announce --type TYPE --port PORT"},
		"flags with no type":           {args: []string{"announce", "--port", "1"}, says: "announce FILE, or announce --type TYPE --port PORT"},
		"a port that is none":          {args: []string{"announce", "--type", "_http._tcp", "--port", "65536"}, says: "announce FILE, or announce --type TYPE --port PORT"},
		"an address that is none":      {args: []string{"announce", "--type", "_http._tcp", "--port", "1", "--host", "h", "--address", "here"}, says: `the address "here"`},
		"a flag that is none":          {args: []string{"announce", "--loud"}, says: "flag provided but not defined"},
		"a service that does not hold": {args: []string{"announce", "--type", "_http._tcp", "--port", "1", "--host", "h"}, says: "needs that host's name and its addresses"},
		"browsing for nothing":         {args: []string{"browse"}, says: "browse [--subtype SUBTYPE]"},
		"browsing for no type":         {args: []string{"browse", "http"}, says: "not valid in Multicast DNS"},
		"resolving half a name":        {args: []string{"resolve", "Kitchen"}, says: "resolve [--timeout DURATION] NAME TYPE"},
		"looking up nothing":           {args: []string{"lookup"}, says: "lookup [--timeout DURATION] HOST"},
	} {
		t.Run(what, func(t *testing.T) {
			t.Parallel()

			var (
				network  mdnstest.Network
				out, err buffer
			)

			// What is refused ends at once; what is let through would
			// announce for as long as it is let, which is not long.
			ctx, stop := context.WithTimeout(t.Context(), 2*time.Second)
			defer stop()

			code := command.Run(
				ctx,
				command.Environment{
					Args:    row.args,
					In:      strings.NewReader(row.in),
					Out:     &out,
					Err:     &err,
					Network: network.Host(),
				},
			)

			if code != command.Misused || !strings.Contains(err.String(), row.says) || out.String() != "" {
				t.Errorf("ended with %d, saying %q", code, err.String())
			}
		})
	}

	var out, err buffer

	if code := command.Run(
		t.Context(),
		command.Environment{Args: []string{"help"}, Out: &out, Err: &err},
	); code != command.Done ||
		err.String() != command.Usage {
		t.Errorf("asked for help: %d, %q", code, err.String())
	}

	missing := filepath.Join(t.TempDir(), "none.json")

	var network mdnstest.Network

	if code := command.Run(
		t.Context(),
		command.Environment{Args: []string{"announce", missing}, Out: &out, Err: &err, Network: network.Host()},
	); code != command.Failed {
		t.Errorf("a document that is not there: %d", code)
	}
}

// A network looked at by hand: the services of a type as they come, one
// by its name, a host by its own; and what is not there, said not to
// be, in the time given.
func TestANetworkLookedAt(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		announcer, err := mdns.Open(t.Context(), mdns.Config{Network: network.Host(lan("2")), Hostname: "kitchen"})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = announcer.Close() }()

		synctest.Wait()

		if _, err = announcer.Announce(t.Context(), mdns.Service{
			Name: "Kitchen display", Type: "_http._tcp", Subtypes: []string{"_printer"}, Port: 8080,
			Text: mdns.TXT{{Key: "path", Value: []byte("/")}, {Key: "id", Value: []byte{0xff}}},
		}); err != nil {
			t.Fatal(err)
		}

		found := map[string]any{
			"event": "found",
			"name":  "Kitchen display",
			"type":  "_http._tcp",
			"host":  "kitchen.local",
			"port":  float64(8080),
			"text": []any{
				"path=/",
				map[string]any{"key": "id", "base64": "/w=="},
			},
			"addresses":  []any{"192.0.2.2"},
			"interfaces": []any{"en0"},
		}

		for what, row := range map[string]struct {
			args []string
			code int
			says []map[string]any
			errs string
		}{
			"browsing for a while":     {args: []string{"browse", "--for", "3s", "--subtype", "_printer", "--interface", "en0", "_http._tcp"}, says: []map[string]any{found}},
			"browsing another subtype": {args: []string{"browse", "--for", "3s", "--subtype", "_scanner", "_http._tcp"}},
			"browsing elsewhere":       {args: []string{"browse", "--for", "3s", "--interface", "en9", "_http._tcp"}},
			"resolving":                {args: []string{"resolve", "Kitchen display", "_http._tcp"}, says: []map[string]any{found}},
			"resolving what is not":    {args: []string{"resolve", "--timeout", "2s", "Pantry", "_http._tcp"}, code: command.Failed, errs: `not found: "Pantry" of type _http._tcp, in 2s`},
			"looking up":               {args: []string{"lookup", "kitchen"}, says: []map[string]any{{"event": "found", "name": "kitchen", "addresses": []any{"192.0.2.2"}}}},
			"looking up what is not":   {args: []string{"lookup", "--timeout", "2s", "pantry"}, code: command.Failed, errs: `not found: the host "pantry", in 2s`},
		} {
			looking := run(t, &network, "", row.args...)

			if code := looking.ended(t); code != row.code || !reflect.DeepEqual(looking.out.lines(t), row.says) ||
				!strings.Contains(looking.err.String(), row.errs) {
				t.Errorf("%s: ended with %d, saying %v and %q", what, code, looking.out.lines(t), looking.err.String())
			}
		}
	})
}

// A host that turns up later with a service's name, when the service
// will have no other: the command says the service is lost, and leaves
// with an error. One that may be renamed takes a name that still fits.
func TestAServiceLostLater(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		long := strings.Repeat("é", 31) + "x"
		watching := watch(t, &network)

		taken, err := watching.peer.Announce(t.Context(), mdns.Service{Name: long, Type: "_http._tcp", Port: 1})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = taken.Close() }()

		announcing := run(t, &network, `{"hostname": "oven", "services": [
			{"name": "`+long+`", "type": "_http._tcp", "port": 80},
			{"name": "Kitchen", "type": "_http._tcp", "port": 80, "rename": false}]}`, "announce", "-")

		time.Sleep(5 * time.Second)

		renamed := events(t, &announcing.out)[0]
		if name := strings.TrimPrefix(
			renamed,
			"renamed ",
		); len(name) > 63 || !utf8.ValidString(name) ||
			!strings.HasSuffix(name, " (2)") {
			t.Errorf("said %q", renamed)
		}

		// Another host says it is where "Kitchen" is, and again when it
		// is asked.
		link := speaker(t, &network)
		theirs := wire.Record{
			Name: []string{"Kitchen", "_http", "_tcp", "local"}, Class: wire.ClassIN, TTL: 120, Flush: true,
			Data: wire.Service{Port: 81, Target: []string{"other", "local"}},
		}

		for range 2 {
			message := wire.NewBuilder(nil, wire.Header{Response: true, Authoritative: true}, wire.Options{})
			if err = message.Answer(theirs); err != nil {
				t.Fatal(err)
			}

			if err = link.Multicast(message.Bytes()); err != nil {
				t.Fatal(err)
			}

			time.Sleep(300 * time.Millisecond)
		}

		if code := announcing.ended(t); code != command.Failed ||
			!strings.Contains(announcing.err.String(), `the service "Kitchen" of type _http._tcp: the name is taken`) {
			t.Errorf("ended with %d, saying %q", code, announcing.err.String())
		}

		if said := events(t, &announcing.out); said[len(said)-1] != "lost Kitchen" {
			t.Errorf("said %v", said)
		}
	})
}

// speaker is a host on the wire that says what a test has it say.
func speaker(t *testing.T, network *mdnstest.Network) transport.Link {
	t.Helper()

	ctx, stop := context.WithCancel(context.WithoutCancel(t.Context()))
	up := make(chan transport.Link, 1)
	ended := make(chan struct{})

	go func() {
		defer close(ended)

		_ = network.Host(lan("9")).Watch(ctx, func(event transport.Event) {
			if event.Change == transport.Up {
				up <- event.Link
			}
		})
	}()

	t.Cleanup(func() {
		stop()
		<-ended
	})

	return <-up
}

// A host whose own name is taken says so, with the name it takes.
func TestAHostNameThatIsTaken(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var network mdnstest.Network

		// Another Peer of this very system has the system's name first.
		watching := watch(t, &network)

		taken, err := watching.peer.Announce(t.Context(), mdns.Service{Name: "First", Type: "_http._tcp", Port: 1})
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = taken.Close() }()

		announcing := run(t, &network, "", "announce", "--type", "_http._tcp", "--port", "2", "--name", "Second")

		time.Sleep(5 * time.Second)

		// The system's name with "-2" after it, shortened to stay a label
		// where the system's is as long as a label may be: the machines
		// tests run on have such names.
		label := strings.TrimSuffix(watching.peer.Hostname(), ".local")
		for len(label)+len("-2") > 63 {
			_, size := utf8.DecodeLastRuneInString(label)
			label = label[:len(label)-size]
		}

		said := announcing.out.lines(t)
		if len(said) != 2 || said[0]["event"] != "host" || said[0]["name"] != label+"-2.local" ||
			said[1]["host"] != said[0]["name"] {
			t.Errorf("said %v, the system being %q", said, watching.peer.Hostname())
		}

		if got := watching.stands()["Second"].Host; got != said[0]["name"] {
			t.Errorf("found on %q", got)
		}
	})
}
