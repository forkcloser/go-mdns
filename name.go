package mdns

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// maxLabel is the most bytes a label holds, and maxName the most a
	// name does on the wire, each label's length byte and the root's
	// included.
	maxLabel = 63
	maxName  = 255
	// maxByte is the most a "\DDD" escape may say.
	maxByte = 255
	// local is the domain Multicast DNS answers for.
	local = "local"
)

// Name is a domain name, as its labels, in the order they are written
// and the root left out: {"printer", "local"}. A label is any bytes, a dot among
// them: a service's instance name is one label however it is punctuated,
// which is why a name is not a string here. Names compare without regard
// to the case of ASCII letters.
type Name []string

// ParseName reads a name as it is written: labels separated by dots, a
// dot inside a label written "\.", a backslash "\\", and any byte as
// "\DDD", its value in three decimal digits. A trailing dot is allowed.
// It is ErrInvalid for a label that is empty or too long, a name too
// long, or an escape that is not one.
func ParseName(written string) (Name, error) {
	var (
		name  Name
		label []byte
	)

	written = withoutRoot(written)
	if written == "" {
		return nil, fmt.Errorf("%w: a name with no label", ErrInvalid)
	}

	for index := 0; index < len(written); index++ {
		char := written[index]

		switch {
		case char == '.':
			name = append(name, string(label))
			label = label[:0]
		case char != '\\':
			label = append(label, char)
		case index+3 < len(written) && isDigit(written[index+1]) && isDigit(written[index+2]) && isDigit(written[index+3]):
			value := int(written[index+1]-'0')*100 + int(written[index+2]-'0')*10 + int(written[index+3]-'0')
			if value > maxByte {
				return nil, fmt.Errorf("%w: %q has an escape above 255", ErrInvalid, written)
			}

			label = append(label, byte(value)) // #nosec G115 -- at most maxByte, by the check above
			index += 3
		case index+1 < len(written) && !isDigit(written[index+1]):
			label = append(label, written[index+1])
			index++
		default:
			return nil, fmt.Errorf("%w: %q has an escape that is not one", ErrInvalid, written)
		}
	}

	name = append(name, string(label))

	if err := name.Validate(); err != nil {
		return nil, err
	}

	return name, nil
}

// withoutRoot drops the dot a name may end in, unless it is escaped and
// so part of the last label: "a\." is the label "a.", "a\\." is the
// label "a\" and the root.
func withoutRoot(written string) string {
	bare, found := strings.CutSuffix(written, ".")
	if !found {
		return written
	}

	if escapes := len(bare) - len(strings.TrimRight(bare, `\`)); escapes%2 == 1 {
		return written
	}

	return bare
}

// String writes a name as ParseName reads it, without a trailing dot:
// a dot or a backslash in a label escaped, and any byte that is not
// printable ASCII as "\DDD".
func (n Name) String() string {
	var written strings.Builder

	for index, label := range n {
		if index > 0 {
			written.WriteByte('.')
		}

		for _, char := range []byte(label) {
			switch {
			case char == '.' || char == '\\':
				written.WriteByte('\\')
				written.WriteByte(char)
			case char < ' ' || char > '~':
				fmt.Fprintf(&written, "\\%03d", char)
			default:
				written.WriteByte(char)
			}
		}
	}

	return written.String()
}

// Validate reports a name that cannot be sent, as ErrInvalid: no label,
// a label that is empty or over 63 bytes, or a name over 255 bytes on
// the wire.
func (n Name) Validate() error {
	if len(n) == 0 {
		return fmt.Errorf("%w: a name with no label", ErrInvalid)
	}

	wire := 1

	for _, label := range n {
		switch {
		case label == "":
			return fmt.Errorf("%w: %q has an empty label", ErrInvalid, n.String())
		case len(label) > maxLabel:
			return fmt.Errorf("%w: %q has a label of %d bytes, over %d", ErrInvalid, n.String(), len(label), maxLabel)
		}

		wire += 1 + len(label)
	}

	if wire > maxName {
		return fmt.Errorf("%w: %q is %d bytes on the wire, over %d", ErrInvalid, n.String(), wire, maxName)
	}

	return nil
}

// Equal says whether two names are the same name: label for label,
// without regard to the case of ASCII letters.
func (n Name) Equal(other Name) bool {
	if len(n) != len(other) {
		return false
	}

	for index := range n {
		if !sameLabel(n[index], other[index]) {
			return false
		}
	}

	return true
}

// sameLabel compares two labels as DNS does: byte for byte, but for the
// case of ASCII letters.
func sameLabel(one, other string) bool {
	if len(one) != len(other) {
		return false
	}

	for index := range len(one) {
		if lower(one[index]) != lower(other[index]) {
			return false
		}
	}

	return true
}

func lower(char byte) byte {
	if char >= 'A' && char <= 'Z' {
		return char + ('a' - 'A')
	}

	return char
}

func isDigit(char byte) bool { return char >= '0' && char <= '9' }

// instanceLabel reports an instance name that cannot be one label of
// Net-Unicode text: empty, over 63 bytes, not UTF-8, or holding an ASCII
// control character.
func instanceLabel(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: a name that is empty", ErrInvalid)
	case len(name) > maxLabel:
		return fmt.Errorf("%w: the name %q is %d bytes, over %d", ErrInvalid, name, len(name), maxLabel)
	case !utf8.ValidString(name):
		return fmt.Errorf("%w: the name %q is not UTF-8", ErrInvalid, name)
	}

	for _, char := range []byte(name) {
		if char < ' ' || char == 0x7F {
			return fmt.Errorf("%w: the name %q holds a control character", ErrInvalid, name)
		}
	}

	return nil
}
