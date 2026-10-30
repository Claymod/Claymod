package stdfiles

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchContentSizeCap(t *testing.T) {
	old := fetchMaxSize
	fetchMaxSize = 8
	t.Cleanup(func() { fetchMaxSize = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 16)))
	}))
	defer srv.Close()

	if _, err := fetchContent(srv.URL, ""); err == nil {
		t.Fatal("fetchContent accepted a body over the size cap")
	} else if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error = %q, want a size-limit message", err.Error())
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":          `'plain'`,
		"it's":           `'it'\''s'`,
		`say "hi"; exit`: `'say "hi"; exit'`,
		"":               `''`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
