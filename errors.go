package mdns

import "errors"

// The errors, to test with errors.Is.
var (
	// ErrInvalid: what was asked cannot be said in the protocol: a name
	// too long, a type that is not one, a text record past its bounds.
	ErrInvalid = errors.New("not valid in Multicast DNS")
	// ErrConflict: a name is another host's, and Rename gave up.
	ErrConflict = errors.New("the name is taken")
	// ErrClosed: the Peer is closed, or what was asked of was withdrawn.
	ErrClosed = errors.New("closed")
)
