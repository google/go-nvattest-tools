package main

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"

	"flag"

	"github.com/google/subcommands"
)

// Build information. These are overridden at link time by the release build
// (see scripts/build-release.sh) with:
//
//	-ldflags "-X main.version=v1.2.3 -X main.commit=<sha> -X main.buildDate=<date>"
var (
	version   = ""
	commit    = ""
	buildDate = ""
)

type versionCmd struct{}

func (*versionCmd) Name() string { return "version" }
func (*versionCmd) Synopsis() string {
	return "Print the nvattest version and build information."
}
func (*versionCmd) Usage() string {
	return `version
`
}

func (*versionCmd) SetFlags(*flag.FlagSet) {}

func (*versionCmd) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	v, c := version, commit
	// Binaries built with plain `go build` (or `go install`) carry no linker
	// stamps, so fall back to whatever the Go toolchain embedded.
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "" && info.Main.Version != "" {
			v = info.Main.Version
		}
		if c == "" {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" {
					c = s.Value
				}
			}
		}
	}
	if v == "" {
		v = "devel"
	}
	if c == "" {
		c = "unknown"
	}
	d := buildDate
	if d == "" {
		d = "unknown"
	}

	fmt.Printf("nvattest %s\n", v)
	fmt.Printf("  commit:     %s\n", c)
	fmt.Printf("  build date: %s\n", d)
	fmt.Printf("  go version: %s\n", runtime.Version())
	fmt.Printf("  platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return subcommands.ExitSuccess
}
