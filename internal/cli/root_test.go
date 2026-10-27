package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelp(t *testing.T) {
	root := newRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("root --help returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "claymod") {
		t.Errorf("help output missing program name:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "version") {
		t.Errorf("help output missing version subcommand:\n%s", buf.String())
	}
}

func TestVersionOutput(t *testing.T) {
	version = "1.2.3-test"
	root := newRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("version returned error: %v", err)
	}
	if got := buf.String(); got != "claymod 1.2.3-test\n" {
		t.Errorf("version output = %q", got)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"definitely-not-a-command"})
	if err := root.Execute(); err == nil {
		t.Fatal("unknown command did not return an error")
	}
}
