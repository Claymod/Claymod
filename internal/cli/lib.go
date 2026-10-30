package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/claymod/claymod/internal/libs"
)

// discoverProject loads the project file for the lib subcommands: the
// --project flag (a claymod.project.yaml path) or a walk up from the
// working directory.
func discoverProject(flagPath string) (*libs.Project, error) {
	if flagPath != "" {
		return libs.Load(flagPath)
	}
	proj, err := libs.Discover(".")
	if err != nil {
		return nil, err
	}
	if proj == nil {
		return nil, fmt.Errorf("no %s found here or in any parent directory (or pass --project)", libs.ProjectFileName)
	}
	return proj, nil
}

func newLibCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lib",
		Short: "List and sync the project's external PKL libraries",
		Long: `Manage the libraries pinned in claymod.project.yaml. Git libraries
sync into the user cache; pinned refs (tags, commits) never touch the
network once cached, branch refs re-fetch on sync. Playbook commands
sync automatically on evaluate — these commands exist for inspection
and for warming caches on a connected machine (air-gapped flow).`,
	}
	cmd.AddCommand(newLibListCmd())
	cmd.AddCommand(newLibSyncCmd())
	return cmd
}

func newLibListCmd() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show the project's libraries and their cache state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			proj, err := discoverProject(project)
			if err != nil {
				return err
			}
			sts, err := proj.Status()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "project: %s (%d librar(y|ies))\n",
				filepath.Join(proj.Dir, libs.ProjectFileName), len(sts))
			for _, st := range sts {
				source := st.Git + " @ " + st.Ref
				if st.Git == "" {
					source = "local: " + st.Path
				}
				state := "not synced"
				if st.Cached {
					state = "cached @ " + shortSha(st.Commit)
					if !st.Warm {
						state += " (stale: ref or url changed)"
					}
				}
				fmt.Fprintf(out, "  %-14s %-50s %s\n", st.Name, source, state)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "path to claymod.project.yaml (default: discover from the working directory)")
	return cmd
}

func newLibSyncCmd() *cobra.Command {
	var project string
	var offline bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync the project's git libraries into the cache",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			proj, err := discoverProject(project)
			if err != nil {
				return err
			}
			if _, err := proj.Sync(offline); err != nil {
				return err
			}
			// Metadata was (re)written by the sync: Status reads it back.
			sts, err := proj.Status()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, st := range sts {
				if st.Git == "" {
					fmt.Fprintf(out, "%-14s local %s\n", st.Name, st.Path)
					continue
				}
				fmt.Fprintf(out, "%-14s @ %s\n", st.Name, shortSha(st.Commit))
			}
			if offline {
				fmt.Fprintln(out, "offline: network was not used")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "path to claymod.project.yaml (default: discover from the working directory)")
	cmd.Flags().BoolVar(&offline, "offline", false, "forbid network: reuse the cache as-is, fail on a cold cache")
	return cmd
}

func shortSha(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
