// Package shell holds helpers for generating POSIX sh command recipes
// (the agent runs shell strings under /bin/sh -c).
package shell

import "strings"

// Quote single-quotes s for POSIX sh. The result is always a single
// word: every character (quotes, $, `, newlines) is literal inside it.
// Use it for every variable fragment of a generated recipe — paths,
// values, names — and never interpolate a quoted string inside double
// quotes (where `$(...)` and backticks would execute).
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
