package shell

import "testing"

func TestQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "'plain'"},
		{"it's", `'it'\''s'`},
		{`say "hi"; exit`, `'say "hi"; exit'`},
		{"", "''"},
		{"$(touch pwned)", "'$(touch pwned)'"},
		{"back`tick", "'back`tick'"},
		{"multi\nline", "'multi\nline'"}, // a real newline stays literal inside the quotes
		{"trailing\\", "'trailing\\'"},   // backslashes need no escaping inside single quotes
	}
	for _, tc := range cases {
		if got := Quote(tc.in); got != tc.want {
			t.Errorf("Quote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
