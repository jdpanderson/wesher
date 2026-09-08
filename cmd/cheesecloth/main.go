// Command cheesecloth builds an encrypted wireguard mesh across a cluster of
// nodes whose membership rests on per-node identities and invitation tokens.
package main

import (
	"fmt"
	"os"

	"github.com/jdpanderson/cheesecloth/internal/cli"
)

// version is set by the Makefile from the git tag.
var version = "dev"

func main() {
	c := &cli.CLI{}
	k, err := cli.Parser(c, cli.DefaultConfigPath, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cheesecloth:", err)
		os.Exit(1)
	}
	ktx, err := k.Parse(os.Args[1:])
	k.FatalIfErrorf(err)
	k.FatalIfErrorf(ktx.Run())
}
