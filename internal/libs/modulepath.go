package libs

import (
	"path/filepath"

	"github.com/claymod/claymod/internal/schema"
	"github.com/claymod/claymod/internal/util"
)

// ModulePathFor assembles the full module path for evaluating
// playbookFile: the std root, the extra dirs (flags, env), then — when
// a claymod.project.yaml exists above the playbook — the project's
// schemaPaths and synced library directories, in file order. offline
// forbids network during library sync (errors only on a cold cache).
func ModulePathFor(playbookFile string, extraDirs []string, offline bool) ([]string, error) {
	dirs, err := schema.ModulePath(extraDirs)
	if err != nil {
		return nil, err
	}
	proj, err := Discover(filepath.Dir(playbookFile))
	if err != nil {
		return nil, err
	}
	if proj == nil {
		return dirs, nil
	}
	for _, sp := range proj.SchemaPaths {
		local := util.ExpandHome(sp)
		if !filepath.IsAbs(local) {
			local = filepath.Join(proj.Dir, local)
		}
		dirs = append(dirs, local)
	}
	libDirs, err := proj.Sync(offline)
	if err != nil {
		return nil, err
	}
	return append(dirs, libDirs...), nil
}
