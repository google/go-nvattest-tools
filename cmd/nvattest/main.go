// The nvattest command provides a command line tool for device attestation.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"flag"

	"github.com/google/subcommands"
)

const (
	deviceGPU      = "gpu"
	deviceNVSwitch = "nvswitch"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&collectCmd{}, "")
	subcommands.Register(&attestCmd{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

func parseNonce(nonceHex string) ([32]byte, error) {
	var nonceBytes [32]byte
	if nonceHex == "" {
		return nonceBytes, nil
	}
	dec, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nonceBytes, fmt.Errorf("invalid nonce: %w", err)
	}
	if len(dec) != 32 {
		return nonceBytes, fmt.Errorf("invalid nonce: must be exactly 32 bytes")
	}
	copy(nonceBytes[:], dec)
	return nonceBytes, nil
}
