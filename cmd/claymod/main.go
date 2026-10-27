// Command claymod is a push-based IaC tool: a control server compiles PKL
// playbooks and applies them to enrolled hosts over a WireGuard overlay.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/claymod/claymod/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "claymod:", err)
		// `exec` propagates the remote command's exit code.
		var exitErr cli.ExitCoder
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
