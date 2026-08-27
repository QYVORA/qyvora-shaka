// Command shaka is the QYVORA authorized Active Directory security assessment
// framework. It never calls os.Exit itself; the exit-code contract lives in
// the cli package so test binaries can exercise exit behavior directly.
package main

import (
	"os"

	"github.com/QYVORA/qyvora-shaka/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
