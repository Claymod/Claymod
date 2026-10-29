// Package pklschema embeds the shipped claymod PKL schema (the base
// module and the std resource families) so claymod binaries resolve
// "modulepath:/claymod/…" from any working directory, without a
// repository checkout.
//
// The schema stays editable in pkl/claymod/ — this file only embeds it
// at build time; internal/schema materializes it into the user cache
// directory for the pkl CLI.
package pklschema

import "embed"

// FS holds pkl/claymod/ (the schema root passed to `pkl eval
// --module-path`).
//
//go:embed claymod
var FS embed.FS
