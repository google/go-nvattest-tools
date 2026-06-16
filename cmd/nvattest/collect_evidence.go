package main

import (
	"context"
	"fmt"
	"os"

	"flag"

	"github.com/google/go-nvattest-tools/client"
	"google.golang.org/protobuf/encoding/protojson"
	"github.com/google/subcommands"
)

type collectCmd struct {
	device       string
	nonce        string
	evidenceFile string
}

func (*collectCmd) Name() string     { return "collect-evidence" }
func (*collectCmd) Synopsis() string { return "Collect evidence from live devices." }
func (*collectCmd) Usage() string {
	return `collect-evidence [--device gpu|nvswitch] [--nonce hex] [--evidence_file path]
`
}

func (c *collectCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.device, "device", deviceGPU, fmt.Sprintf("device to attest: %s, %s", deviceGPU, deviceNVSwitch))
	f.StringVar(&c.nonce, "nonce", "", "nonce in hex")
	f.StringVar(&c.evidenceFile, "evidence_file", "", "output json file")
}

func (c *collectCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	nonceBytes, err := parseNonce(c.nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return subcommands.ExitUsageError
	}

	var data []byte

	switch c.device {
	case deviceGPU:
		provider := &client.LinuxGpuQuoteProvider{}
		quote, err := provider.CollectGpuEvidence(nonceBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to collect GPU evidence: %v\n", err)
			return subcommands.ExitFailure
		}
		data, err = protojson.MarshalOptions{Multiline: true}.Marshal(quote)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal quote: %v\n", err)
			return subcommands.ExitFailure
		}
	case deviceNVSwitch:
		provider := &client.LinuxSwitchQuoteProvider{}
		quote, err := provider.CollectSwitchEvidence(nonceBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to collect Switch evidence: %v\n", err)
			return subcommands.ExitFailure
		}
		data, err = protojson.MarshalOptions{Multiline: true}.Marshal(quote)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal quote: %v\n", err)
			return subcommands.ExitFailure
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown device: %q\n", c.device)
		return subcommands.ExitUsageError
	}

	if c.evidenceFile != "" {
		if err := os.WriteFile(c.evidenceFile, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write file: %v\n", err)
			return subcommands.ExitFailure
		}
	} else {
		fmt.Println(string(data))
	}
	return subcommands.ExitSuccess
}
