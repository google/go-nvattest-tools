package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"flag"

	"github.com/google/subcommands"

	"github.com/google/go-nvattest-tools/abi"
	"github.com/google/go-nvattest-tools/client"
	"github.com/google/go-nvattest-tools/mpt"
	"github.com/google/go-nvattest-tools/ppcie/server"
	"github.com/google/go-nvattest-tools/server/ocsp/nvidiaocsp"
	nvattestocsp "github.com/google/go-nvattest-tools/server/ocsp"
	"github.com/google/go-nvattest-tools/server/rim/nvidiarim"
	"github.com/google/go-nvattest-tools/server/rim"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
	"github.com/google/go-nvattest-tools/spt"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	ocsppb "github.com/google/go-nvattest-tools/proto/nvocsp"
	nvrimpb "github.com/google/go-nvattest-tools/proto/nvrim"
)

type attestCmd struct {
	device          string
	nonce           string
	evidenceFile    string
	rimsFile        string
	rimsOCSPFile    string
	deviceOCSPFile  string
	deviceL4CRLFile string
	now             *verify.TimeSet
	newRimClient    func(httpClient *http.Client, serviceKey string) rim.Client
	newOcspClient   func(httpClient *http.Client, serviceKey string) nvattestocsp.Client
}

func (*attestCmd) Name() string     { return "attest" }
func (*attestCmd) Synopsis() string { return "Verify device attestation evidence." }
func (*attestCmd) Usage() string {
	return `attest [--device gpu|nvswitch] [--evidence_file path] ...
`
}

func (c *attestCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.device, "device", deviceGPU, fmt.Sprintf("device to attest: %s, %s", deviceGPU, deviceNVSwitch))
	f.StringVar(&c.nonce, "nonce", "", "nonce in hex")
	f.StringVar(&c.evidenceFile, "evidence_file", "", "evidence file (protojson). If empty, collects live.")
	f.StringVar(&c.rimsFile, "rims_file", "", "Path to rims.textproto")
	f.StringVar(&c.rimsOCSPFile, "rims_ocsp_file", "", "Path to rims_ocsp.textproto")
	f.StringVar(&c.deviceOCSPFile, "device_ocsp_file", "", "Path to device_ocsp.textproto")
	f.StringVar(&c.deviceL4CRLFile, "device_l4_crl_file", "", "Path to L4 CRL textproto")
}

func (c *attestCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	nonceBytes, err := parseNonce(c.nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return subcommands.ExitUsageError
	}

	valOpts := validate.Options{
		Nonce:           nonceBytes[:],
		DisableRefCheck: false,
		GpuArch:         pb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED,
		NewRimClient:    c.newRimClient,
	}
	verOpts := verify.Options{
		GpuOpts: verify.GPUOpts{
			GPUArch:            pb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED,
			MaxCertChainLength: 5,
		},
		Now:           c.now,
		NewRimClient:  c.newRimClient,
		NewOcspClient: c.newOcspClient,
	}

	if c.rimsFile != "" {
		rimsData, err := os.ReadFile(c.rimsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read RIMs file: %v\n", err)
			return subcommands.ExitFailure
		}
		var rimsCache nvrimpb.NvidiaRims
		if err := prototext.Unmarshal(rimsData, &rimsCache); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal RIMs: %v\n", err)
			return subcommands.ExitFailure
		}
		verOpts.RimClient = nvidiarim.NewClient(&rimsCache)
		valOpts.RimClient = verOpts.RimClient

		if c.rimsOCSPFile == "" {
			fmt.Fprintf(os.Stderr, "--rims_ocsp_file must be provided when --rims_file is set for offline verification\n")
			return subcommands.ExitUsageError
		}

		rimsOCSPData, err := os.ReadFile(c.rimsOCSPFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read RIM OCSP file: %v\n", err)
			return subcommands.ExitFailure
		}
		var rimsOCSPCache ocsppb.OCSPResponses
		if err := prototext.Unmarshal(rimsOCSPData, &rimsOCSPCache); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal RIM OCSP: %v\n", err)
			return subcommands.ExitFailure
		}

		if c.deviceOCSPFile == "" {
			fmt.Fprintf(os.Stderr, "--device_ocsp_file must be provided when --rims_file is set for offline verification\n")
			return subcommands.ExitUsageError
		}

		deviceOCSPData, err := os.ReadFile(c.deviceOCSPFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read Device OCSP: %v\n", err)
			return subcommands.ExitFailure
		}
		var deviceOCSPCache ocsppb.OCSPResponses
		if err := prototext.Unmarshal(deviceOCSPData, &deviceOCSPCache); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal Device OCSP: %v\n", err)
			return subcommands.ExitFailure
		}

		var deviceL4CrlCache ocsppb.DeviceL4RevokedCerts
		if c.deviceL4CRLFile != "" {
			deviceL4CrlData, err := os.ReadFile(c.deviceL4CRLFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read CRL: %v\n", err)
				return subcommands.ExitFailure
			}
			if err := prototext.Unmarshal(deviceL4CrlData, &deviceL4CrlCache); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to unmarshal CRL: %v\n", err)
				return subcommands.ExitFailure
			}
		}

		verOpts.OcspClient = nvidiaocsp.NewClient(&rimsOCSPCache, &deviceOCSPCache, &deviceL4CrlCache)
		fmt.Println("Configured for offline verification.")
	} else {
		fmt.Println("No --rims_file provided, defaulting to online verification.")
	}

	if c.device == deviceGPU {
		var gpuQuote *pb.GpuAttestationQuote
		if c.evidenceFile != "" {
			data, err := os.ReadFile(c.evidenceFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read evidence file: %v\n", err)
				return subcommands.ExitFailure
			}
			gpuQuote = &pb.GpuAttestationQuote{}
			if err := protojson.Unmarshal(data, gpuQuote); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to unmarshal evidence: %v\n", err)
				return subcommands.ExitFailure
			}
		} else {
			provider := &client.LinuxGpuQuoteProvider{}
			var err error
			gpuQuote, err = provider.CollectGpuEvidence(nonceBytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to collect GPU evidence: %v\n", err)
				return subcommands.ExitFailure
			}
		}

		// Auto-detect the operating mode (MPT, SPT, PPCIe)
		// based on the OpaqueDataFeatureFlag embedded inside the attestation report.
		mode := abi.SPTMode
		if len(gpuQuote.GetGpuInfos()) > 0 {
			gpuInfo := gpuQuote.GetGpuInfos()[0]
			valOpts.GpuArch = gpuInfo.GetGpuArchitecture()
			verOpts.GpuOpts.GPUArch = gpuInfo.GetGpuArchitecture()
			var err error
			mode, err = detectMode(gpuInfo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to detect operating mode: %v\n", err)
				return subcommands.ExitFailure
			}
		}

		var state *pb.GpuQuoteState
		switch mode {
		case abi.SPTMode, abi.LegacyMode:
			state = &pb.GpuQuoteState{
				GpuInfoStates: make([]*pb.GpuInfoState, 0, len(gpuQuote.GetGpuInfos())),
			}
			sptOpts := spt.Options{
				Validation:   valOpts,
				Verification: verOpts,
			}
			for i, gpuInfo := range gpuQuote.GetGpuInfos() {
				gpuState, err := spt.VerifyGpuQuote(ctx, gpuInfo, sptOpts)
				if err != nil {
					fmt.Fprintf(os.Stderr, "GPU %d SPT Verification failed: %v\n", i, err)
					return subcommands.ExitFailure
				}
				state.GpuInfoStates = append(state.GpuInfoStates, gpuState)
			}
		case abi.PPCIEMode:
			ppcieOpts := ppcie.Options{
				GPUValidationOpts: valOpts,
				VerificationOpts:  verOpts,
			}
			var err error
			state, _, err = ppcie.VerifySystemQuotes(ctx, gpuQuote, nil, ppcieOpts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "PPCIe Verification failed: %v\n", err)
				return subcommands.ExitFailure
			}
		case abi.MPTMode:
			mptOpts := mpt.Options{
				Validation:   valOpts,
				Verification: verOpts,
			}
			var err error
			state, err = mpt.VerifySystemQuotes(ctx, gpuQuote, mptOpts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "MPT Verification failed: %v\n", err)
				return subcommands.ExitFailure
			}
		default:
			fmt.Fprintf(os.Stderr, "Unknown verification mode: %v\n", mode)
			return subcommands.ExitFailure
		}

		for i, gpuState := range state.GetGpuInfoStates() {
			if !gpuState.SignatureVerified {
				fmt.Fprintf(os.Stderr, "GPU %d Security Fail: Report signature invalid.\n", i)
				return subcommands.ExitFailure
			}
		}
		fmt.Println("Success: All GPUs cryptographically verified against policies.")
	} else {
		fmt.Fprintf(os.Stderr, "attest for %s not implemented yet\n", deviceNVSwitch)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

func detectMode(gpuInfo *pb.GpuInfo) (string, error) {
	report, err := abi.RawAttestationReportToProto(gpuInfo.GetAttestationReport(), abi.GPU)
	if err != nil {
		return "", fmt.Errorf("failed to parse raw attestation report to proto: %v", err)
	}

	parsedMode, err := abi.ParseFeatureFlag(report)
	if err != nil {
		return "", fmt.Errorf("failed to parse feature flag from attestation report: %v", err)
	}

	return parsedMode, nil
}
