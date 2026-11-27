// Package command is the mdns command: a service announced by a program
// run beside it, from a document that says what to announce, and a
// network looked at by hand. It is the library and nothing more, with
// JSON on both sides.
package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/transport"
)

// How the command ends.
const (
	// Done is a command that did what it was asked.
	Done = 0
	// Failed is one that could not: a name that is taken, a network that
	// is not there, something that was not found.
	Failed = 1
	// Misused is one that was not asked properly: an argument or a
	// document that says nothing it can do.
	Misused = 2
)

// Environment is where a command runs.
type Environment struct {
	// Args is what it was called with, the program's name aside.
	Args []string
	// In is what a document is read from when it is "-".
	In io.Reader
	// Out is where what happens is said, one JSON object on a line; Err
	// where what goes wrong is.
	Out io.Writer
	Err io.Writer
	// Network is the network to be on. Nil is the host's own.
	Network transport.Network

	// saying is held while a line is said: several things happen at
	// once, and each is said whole.
	saying *sync.Mutex
}

// Usage is how the command is asked.
const Usage = `mdns announces services on the local network, and looks for them.

  mdns announce FILE         announce the services of a JSON document; - reads it
                             from standard input
  mdns announce --type TYPE --port PORT [--name NAME] [--txt KEY=VALUE]...
                [--subtype SUBTYPE]... [--interface NAME]... [--host HOST
                --address ADDRESS...] [--ttl DURATION] [--no-rename]
                [--hostname NAME]
                             announce one service
  mdns browse [--subtype SUBTYPE] [--interface NAME]... [--for DURATION] TYPE
                             tell of the services of a type as they come and go
  mdns resolve [--timeout DURATION] NAME TYPE
                             find one service by its name
  mdns lookup [--timeout DURATION] HOST
                             find the addresses of a host

Everything is said as JSON, one object on a line. A document is:

  {"hostname": "kitchen",
   "services": [{"name": "Kitchen display", "type": "_http._tcp", "port": 8080,
                 "subtypes": ["_printer"], "text": ["path=/", "secure"],
                 "interfaces": ["en0"], "ttl": "2m", "rename": false},
                {"name": "Garden camera", "type": "_rtsp._tcp", "port": 554,
                 "host": "garden-camera", "addresses": ["192.0.2.40"]}]}

Only type and port are required.
`

// errUsage is a command that was not asked properly.
var errUsage = errors.New("usage")

// Run runs the command until it is done or ctx ends, and says how it
// ended.
func Run(ctx context.Context, env Environment) int {
	verbs := map[string]func(context.Context, *Environment, []string) error{
		"announce": announce, "browse": browse, "resolve": resolve, "lookup": lookup,
	}

	if len(env.Args) == 0 || verbs[env.Args[0]] == nil {
		_, _ = io.WriteString(env.Err, Usage)

		if len(env.Args) > 0 && (env.Args[0] == "help" || env.Args[0] == "--help" || env.Args[0] == "-h") {
			return Done
		}

		return Misused
	}

	env.saying = &sync.Mutex{}

	err := verbs[env.Args[0]](ctx, &env, env.Args[1:])
	if err == nil {
		return Done
	}

	_, _ = fmt.Fprintf(env.Err, "mdns %s: %v\n", env.Args[0], err)

	if errors.Is(err, errUsage) || errors.Is(err, errDocument) || errors.Is(err, mdns.ErrInvalid) {
		return Misused
	}

	return Failed
}

// flags is the flags of a verb. What is wrong with them is said by the
// verb, in one line.
func flags(verb string) *flag.FlagSet {
	set := flag.NewFlagSet("mdns "+verb, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.Usage = func() {}

	return set
}

// list is a flag that may be given several times.
type list []string

func (l *list) String() string { return strings.Join(*l, ",") }

func (l *list) Set(value string) error {
	*l = append(*l, value)

	return nil
}

// said is what the command says of a service: what happened to it, and
// how it stands.
type said struct {
	Event      string   `json:"event"`
	Name       string   `json:"name"`
	Asked      string   `json:"asked,omitempty"`
	Type       string   `json:"type,omitempty"`
	Host       string   `json:"host,omitempty"`
	Port       *uint16  `json:"port,omitempty"`
	Text       []entry  `json:"text,omitempty"`
	Addresses  []string `json:"addresses,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"`
}

// say says something on Out, as one line of JSON.
func (e *Environment) say(what said) {
	line, err := json.Marshal(what)
	if err != nil {
		return
	}

	e.saying.Lock()
	defer e.saying.Unlock()

	_, _ = e.Out.Write(append(line, '\n'))
}

// open opens a Peer on the environment's network.
func (e *Environment) open(ctx context.Context, cfg mdns.Config) (*mdns.Peer, error) {
	cfg.Network = e.Network

	peer, err := mdns.Open(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("opening on the network: %w", err)
	}

	return peer, nil
}

// instance is an instance found, as the command says it.
func instance(event string, found *mdns.Instance) said {
	told := said{
		Event:     event,
		Name:      found.Name,
		Type:      found.Type,
		Host:      found.Host,
		Port:      &found.Port,
		Addresses: addresses(found.Addrs),
	}

	for _, one := range found.Text {
		told.Text = append(told.Text, entry(one))
	}

	for _, one := range found.Interfaces {
		told.Interfaces = append(told.Interfaces, one.Name)
	}

	return told
}

func addresses(addrs []netip.Addr) []string {
	written := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		written = append(written, addr.String())
	}

	return written
}

// browse tells of the services of a type as they come and go.
func browse(ctx context.Context, env *Environment, args []string) error {
	var (
		set        = flags("browse")
		subtype    = set.String("subtype", "", "")
		during     = set.Duration("for", 0, "")
		interfaces list
	)

	set.Var(&interfaces, "interface", "")

	if err := set.Parse(args); err != nil || set.NArg() != 1 {
		return fmt.Errorf("%w: browse [--subtype SUBTYPE] [--interface NAME]... [--for DURATION] TYPE", errUsage)
	}

	query := mdns.Query{Type: set.Arg(0), Subtype: *subtype}
	if len(interfaces) > 0 {
		query.Interfaces = mdns.On(interfaces...)
	}

	peer, err := env.open(ctx, mdns.Config{})
	if err != nil {
		return err
	}

	defer func() { _ = peer.Close() }()

	if *during > 0 {
		var stop context.CancelFunc

		ctx, stop = context.WithTimeout(ctx, *during)
		defer stop()
	}

	err = peer.Browse(ctx, query, func(change mdns.Change, found mdns.Instance) {
		env.say(instance(change.String(), &found))
	})

	// Told to stop, or its time up: that is how it ends well.
	if ctx.Err() != nil {
		return nil
	}

	return fmt.Errorf("browsing: %w", err)
}

// errNotFound is something that was looked for and not found in time.
var errNotFound = errors.New("not found")

// patience is how long one service or one host is looked for when no
// time is given.
const patience = 5 * time.Second

// resolve finds one service by its name.
func resolve(ctx context.Context, env *Environment, args []string) error {
	set := flags("resolve")
	timeout := set.Duration("timeout", patience, "")

	if err := set.Parse(args); err != nil || set.NArg() != 2 {
		return fmt.Errorf("%w: resolve [--timeout DURATION] NAME TYPE", errUsage)
	}

	peer, err := env.open(ctx, mdns.Config{})
	if err != nil {
		return err
	}

	defer func() { _ = peer.Close() }()

	ctx, stop := context.WithTimeout(ctx, *timeout)
	defer stop()

	found, err := peer.Resolve(ctx, set.Arg(0), set.Arg(1))
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %q of type %s, in %s", errNotFound, set.Arg(0), set.Arg(1), *timeout)
	}

	if err != nil {
		return fmt.Errorf("resolving %q: %w", set.Arg(0), err)
	}

	env.say(instance("found", &found))

	return nil
}

// lookup finds the addresses of a host.
func lookup(ctx context.Context, env *Environment, args []string) error {
	set := flags("lookup")
	timeout := set.Duration("timeout", patience, "")

	if err := set.Parse(args); err != nil || set.NArg() != 1 {
		return fmt.Errorf("%w: lookup [--timeout DURATION] HOST", errUsage)
	}

	peer, err := env.open(ctx, mdns.Config{})
	if err != nil {
		return err
	}

	defer func() { _ = peer.Close() }()

	ctx, stop := context.WithTimeout(ctx, *timeout)
	defer stop()

	addrs, err := peer.LookupHost(ctx, set.Arg(0))
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: the host %q, in %s", errNotFound, set.Arg(0), *timeout)
	}

	if err != nil {
		return fmt.Errorf("looking for %q: %w", set.Arg(0), err)
	}

	env.say(said{Event: "found", Name: set.Arg(0), Addresses: addresses(addrs)})

	return nil
}

// source is where what to announce comes from: a file, standard input,
// or flags that say one service.
type source struct {
	path string
	once wanted
}

// load reads what to announce from where it comes from, until ctx ends.
func (s *source) load(ctx context.Context, env *Environment) (wanted, error) {
	switch s.path {
	case "":
		return s.once, nil
	case "-":
		// Read apart: nothing ends the read of a terminal, or of a pipe
		// no one writes to, but what is at its other end.
		type document struct {
			written []byte
			err     error
		}

		whole := make(chan document, 1)

		go func() {
			written, err := io.ReadAll(env.In)
			whole <- document{written, err}
		}()

		select {
		case got := <-whole:
			if got.err != nil {
				return wanted{}, fmt.Errorf("reading standard input: %w", got.err)
			}

			return read(got.written)
		case <-ctx.Done():
			return wanted{}, fmt.Errorf("reading standard input: %w", context.Cause(ctx))
		}
	default:
		written, err := os.ReadFile(s.path)
		if err != nil {
			return wanted{}, fmt.Errorf("reading the document: %w", err)
		}

		return read(written)
	}
}
