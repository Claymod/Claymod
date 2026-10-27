// Command claymod is a push-based IaC tool: a control server compiles PKL
// playbooks and applies them to enrolled hosts over a WireGuard overlay.
package main

import (
	"fmt"
	"os"

	"github.com/claymod/claymod/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "claymod:", err)
		os.Exit(1)
	}
}
