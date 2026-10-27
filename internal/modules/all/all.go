// Package all wires in every bundled module family (blank imports for
// init-time compiler registration). Importing this package gives you the
// complete std module set; the registry lives in the modules package.
package all

import (
	_ "github.com/claymod/claymod/internal/modules/stdcommands"
	_ "github.com/claymod/claymod/internal/modules/stdfiles"
	_ "github.com/claymod/claymod/internal/modules/stdservice"
)
