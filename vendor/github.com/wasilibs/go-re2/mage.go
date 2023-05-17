//go:build tools
// +build tools

// Entrypoint to mage for running without needing to install the command.
// https://magefile.org/zeroinstall/
package main

import (
	"os"

	"github.com/magefile/mage/mage"
)

func main() {
	os.Exit(mage.Main())
}
