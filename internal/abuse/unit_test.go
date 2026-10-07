package abuse

import (
	"testing"
	"unicode/utf8"
)

func TestEnvBool(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"1", true}, {"true", true}, {"yes", true},
		{"0", false}, {"false", false}, {"no", false}, {"garbage", false},
	}
	for _, tc := range cases {
		useEnv(t, "FLAG", tc.value)
		if got := envBool("FLAG", "false"); got != tc.want {
			t.Errorf("envBool(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestEnvBool_UsesDefaultWhenUnset(t *testing.T) {
	useEnv(t)
	if envBool("MISSING", "true") != true {
		t.Error("unset variable should use default true")
	}
	if envBool("MISSING", "false") != false {
		t.Error("unset variable should use default false")
	}
}

func TestTruncateUTF8(t *testing.T) {
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"shorter than limit", "hello", 100, "hello"},
		{"exactly at limit", "hello", 5, "hello"},
		{"ascii truncation", "hello world", 5, "hello"},
		{"does not split rune", "café", 4, "caf"}, // é is 2 bytes
		{"rune at exact boundary", "café", 5, "café"},
		{"single multibyte rune cut", "€", 2, ""}, // 3-byte rune
		{"zero max", "hello", 0, ""},
		{"empty input", "", 10, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateUTF8(tc.in, tc.max)
			if got != tc.want {
				t.Errorf("truncateUTF8(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("result %q is not valid UTF-8", got)
			}
			if len(got) > tc.max {
				t.Errorf("result has %d bytes, limit %d", len(got), tc.max)
			}
		})
	}
}

func TestSha1Hex_KnownVectors(t *testing.T) {
	cases := map[string]string{
		"":    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"abc": "a9993e364706816aba3e25717850c26c9cd0d89d",
	}
	for in, want := range cases {
		if got := sha1Hex(in); got != want {
			t.Errorf("sha1Hex(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestAppendUnique(t *testing.T) {
	var l []string
	for _, v := range []string{"a", "b", "a", "c", "b", "a"} {
		l = appendUnique(l, v)
	}
	if len(l) != 3 || l[0] != "a" || l[1] != "b" || l[2] != "c" {
		t.Errorf("appendUnique result = %v, want [a b c] in first-seen order", l)
	}
}
