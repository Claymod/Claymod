package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/libs"
	"github.com/claymod/claymod/internal/util"
)

// scaffoldPlaybook is the starter playbook: valid out of the box
// (`claymod playbook validate` passes), demonstrating the three common
// file resources — literal content, a template with per-host vars, and
// a static copy with its source under files/.
const scaffoldPlaybook = `amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"

// Hosts to apply to (exact names from the inventory).
hosts { "web01" }

// Per-host template variables.
vars {
  ["greeting"] = "hello"
}

resources {
  // Literal text, written as-is (files.Content is not templated).
  new files.Content {
    name = "banner"
    content = "Managed by claymod\n"
    dest = "/tmp/claymod-banner.txt"
  }
  // Rendered per host server-side with .Host and .Vars.
  new files.Template {
    name = "hello"
    source = "files/hello.tmpl"
    dest = "/tmp/claymod-hello.txt"
  }
  // Static file; source paths are relative to this playbook.
  new files.Copy {
    name = "motd"
    source = "files/motd.txt"
    dest = "/tmp/claymod-motd.txt"
  }
}
`

const scaffoldTemplate = `Hello {{.Host}}, {{.Vars.greeting}}.
`

const scaffoldMotd = `Managed by claymod — edit me in files/motd.txt.
`

// scaffoldProject is written only when no claymod.project.yaml exists
// in the target dir or any parent (a parent's project file owns the
// playbook; writing a local one would shadow it and drop its libraries).
const scaffoldProject = `# claymod.project.yaml — project-wide playbook configuration.
version: 1

# Extra local module-path directories (relative to this file).
schemaPaths: []

# External PKL libraries pinned from git (docs/playbooks.md#libraries):
# libraries:
#   - name: acme
#     git: ssh://git@git.example.com/acme/claymod-lib.git
#     ref: v1.2.0
#     path: pkl
libraries: []
`

func newPlaybookInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init <dir>",
		Short: "Scaffold a starter playbook directory",
		Long: `Creates <dir> with a valid starter playbook (playbook.pkl), its
supporting files (files/motd.txt, files/hello.tmpl) and — when no
claymod.project.yaml exists here or above — a project file to pin
libraries in. Refuses to overwrite any existing playbook file.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			dir := mustAbs(util.ExpandHome(args[0]))

			// Refuse before writing anything if a playbook file exists.
			type target struct{ rel, content string }
			files := []target{
				{"playbook.pkl", scaffoldPlaybook},
				{filepath.Join("files", "hello.tmpl"), scaffoldTemplate},
				{filepath.Join("files", "motd.txt"), scaffoldMotd},
			}
			var existing []string
			for _, f := range files {
				p := filepath.Join(dir, f.rel)
				if _, err := os.Stat(p); err == nil {
					existing = append(existing, f.rel)
				}
			}
			if len(existing) > 0 {
				return fmt.Errorf("refusing to overwrite in %s: %s (move them away or pick another directory)", dir, strings.Join(existing, ", "))
			}

			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create %s: %w", dir, err)
			}
			for _, f := range files {
				p := filepath.Join(dir, f.rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					return err
				}
				if err := util.WriteFileAtomic(p, []byte(f.content), 0o644); err != nil {
					return fmt.Errorf("write %s: %w", f.rel, err)
				}
				fmt.Fprintf(out, "created  %s\n", f.rel)
			}

			// Project file: only when none exists here or above.
			projectRel := libs.ProjectFileName
			if proj, err := libs.Discover(dir); err != nil {
				return err
			} else if proj != nil {
				fmt.Fprintf(out, "skipped  %s (using the existing project at %s)\n",
					projectRel, filepath.Join(proj.Dir, projectRel))
			} else if _, err := os.Stat(filepath.Join(dir, projectRel)); err == nil {
				fmt.Fprintf(out, "skipped  %s (already present)\n", projectRel)
			} else {
				p := filepath.Join(dir, projectRel)
				if err := util.WriteFileAtomic(p, []byte(scaffoldProject), 0o644); err != nil {
					return fmt.Errorf("write %s: %w", projectRel, err)
				}
				fmt.Fprintf(out, "created  %s\n", projectRel)
			}

			fmt.Fprintf(out, "\nnext: claymod playbook validate %s\n", filepath.Join(dir, "playbook.pkl"))
			return nil
		},
	}
}
