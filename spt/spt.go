// Package spt provides the implementation for SPT verification.
package spt

import (
	"context"
	"fmt"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
)

// Options holds the options for the SPT.
type Options struct {
	Validation   validate.Options
	Verification verify.Options

	verifyGpuInfo             func(context.Context, *pb.GpuInfo, verify.Options) (*pb.GpuInfoState, error)
	validateAttestationReport func(context.Context, []byte, validate.Options) error
}

// VerifyGpuQuote verifies and validates a single GPU device.
func VerifyGpuQuote(ctx context.Context, gpuInfo *pb.GpuInfo, opts Options) (*pb.GpuInfoState, error) {
	if opts.verifyGpuInfo == nil {
		opts.verifyGpuInfo = verify.GpuInfo
	}
	if opts.validateAttestationReport == nil {
		opts.validateAttestationReport = validate.AttestationReport
	}

	// 1. verify the GPU info.
	gpuInfoState, err := opts.verifyGpuInfo(ctx, gpuInfo, opts.Verification)
	if err != nil {
		return nil, fmt.Errorf("GPU UUID %q: %w", gpuInfo.GetUuid(), err)
	}

	// 2. validate the attestation report.
	// Set the driver and VBIOS versions based on the GPU info.
	opts.Validation.DriverVersion = gpuInfo.GetDriverVersion()
	opts.Validation.VBiosVersion = gpuInfo.GetVbiosVersion()
	err = opts.validateAttestationReport(ctx, gpuInfo.GetAttestationReport(), opts.Validation)
	if err != nil {
		return nil, fmt.Errorf("GPU UUID %q: %w", gpuInfo.GetUuid(), err)
	}

	if !opts.Validation.DisableRefCheck {
		gpuInfoState.MeasurementsMatched = true
	}
	return gpuInfoState, nil
}
