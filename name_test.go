package mdns_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/forkcloser/go-mdns"
)

func TestNamesAreRead(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 63)

	for written, want := range map[string]mdns.Name{
		"printer.local":                    {"printer", "local"},
		"printer.local.":                   {"printer", "local"},
		`Living Room 2\.4GHz._http._tcp`:   {"Living Room 2.4GHz", "_http", "_tcp"},
		`back\\slash.local`:                {`back\slash`, "local"},
		`caf\195\169.local`:                {"café", "local"},
		`a\032b.local`:                     {"a b", "local"},
		`quo\"te.local`:                    {`quo"te`, "local"},
		long + ".local":                    {long, "local"},
		"b._dns-sd._udp.0.1.168.192.local": {"b", "_dns-sd", "_udp", "0", "1", "168", "192", "local"},
	} {
		got, err := mdns.ParseName(written)
		if err != nil || !got.Equal(want) || len(got) != len(want) {
			t.Errorf("%q read as %q, %v", written, got, err)

			continue
		}

		// What is written from it reads back as the same name.
		again, err := mdns.ParseName(got.String())
		if err != nil || !again.Equal(got) {
			t.Errorf("%q written as %q, read back as %q, %v", written, got.String(), again, err)
		}
	}

	for name, written := range map[string]string{
		"nothing":               "",
		"the root alone":        ".",
		"an empty label":        "a..local",
		"a leading dot":         ".local",
		"a label of 64 bytes":   long + "a.local",
		"an escape cut short":   `a\`,
		"digits cut short":      `a\19`,
		"an escape above 255":   `a\256`,
		"a name over 255 bytes": strings.Repeat(long+".", 4),
	} {
		if got, err := mdns.ParseName(written); !errors.Is(err, mdns.ErrInvalid) {
			t.Errorf("%s: read as %q, %v", name, got, err)
		}
	}
}

func TestNamesAreWrittenAndCompared(t *testing.T) {
	t.Parallel()

	for want, name := range map[string]mdns.Name{
		"printer.local":                  {"printer", "local"},
		`Living Room 2\.4GHz._http._tcp`: {"Living Room 2.4GHz", "_http", "_tcp"},
		`a\\b`:                           {`a\b`},
		`caf\195\169`:                    {"café"},
		`tab\009`:                        {"tab\t"},
		`Dr\. Smith\.`:                   {"Dr. Smith."},
		`a\.`:                            {"a."},
		`a\\`:                            {`a\`},
	} {
		if got := name.String(); got != want {
			t.Errorf("%q written as %q", []string(name), got)
		}

		// What is written is read back as it was.
		back, err := mdns.ParseName(want)
		if err != nil || !slices.Equal(back, name) {
			t.Errorf("%q read back as %q, %v", want, []string(back), err)
		}
	}

	// A trailing dot is the root, unless it is escaped.
	for written, want := range map[string]mdns.Name{
		`a\..`:  {"a."},
		`a\\.`:  {`a\`},
		`a\\\.`: {`a\.`},
		"a.":    {"a"},
	} {
		if got, err := mdns.ParseName(written); err != nil || !slices.Equal(got, want) {
			t.Errorf("%q read as %q, %v", written, []string(got), err)
		}
	}

	same := mdns.Name{"Printer", "LOCAL"}

	if !same.Equal(mdns.Name{"printer", "local"}) {
		t.Error("names that differ by the case of ASCII letters are not the same")
	}

	for name, other := range map[string]mdns.Name{
		"another label":      {"printer2", "local"},
		"one label fewer":    {"printer"},
		"one label more":     {"printer", "local", "x"},
		"a letter not ASCII": {"printér", "local"},
	} {
		if same.Equal(other) {
			t.Errorf("%s is the same name as %q", name, []string(same))
		}
	}

	// The longest name there is: 255 bytes on the wire.
	longest := mdns.Name{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}
	if err := longest.Validate(); err != nil {
		t.Errorf("a name of 255 bytes on the wire: %v", err)
	}

	longest[3] += "d"

	if err := longest.Validate(); !errors.Is(err, mdns.ErrInvalid) {
		t.Errorf("a name of 256 bytes on the wire: %v", err)
	}

	if err := (mdns.Name{}).Validate(); !errors.Is(err, mdns.ErrInvalid) {
		t.Errorf("a name with no label: %v", err)
	}
}
