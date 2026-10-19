// Package mpt provides the implementation for MPT verification.
package mpt

import (
	"context"
	"fmt"

	"github.com/google/go-nvattest-tools/abi"
	"github.com/google/go-nvattest-tools/server/utility"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
	"go.uber.org/multierr"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
)

// DefaultMaxGpuCount is the maximum number of GPU reports verified per quote
// when Options.MaxGpuCount is zero. Set Options.MaxGpuCount for systems with
// more GPUs.
const DefaultMaxGpuCount = 16

// Options holds the options for the MPT.
type Options struct {
	Validation   validate.Options
	Verification verify.Options
	// MaxGpuCount bounds the number of GPU reports verified per quote. Zero or
	// less means DefaultMaxGpuCount. It is enforced before any report is
	// verified, because each report costs several P-384 signature checks.
	MaxGpuCount int
}

// VerifySystemQuotes verifies a GpuAttestationQuote from an MPT system.
// It rejects a quote with more than opts.MaxGpuCount GPU reports before it
// verifies any report.
func VerifySystemQuotes(ctx context.Context, quote *pb.GpuAttestationQuote, opts Options) (*pb.GpuQuoteState, error) {
	return verifySystemQuotes(ctx, quote, opts, verify.GpuInfo)
}

type verifyGpuInfoFunc func(context.Context, *pb.GpuInfo, verify.Options) (*pb.GpuInfoState, error)

func verifySystemQuotes(ctx context.Context, quote *pb.GpuAttestationQuote, opts Options, verifyGpuInfo verifyGpuInfoFunc) (*pb.GpuQuoteState, error) {
	var allErrs []error

	// 1. Initial Validation for MPT mode.
	if len(quote.GetGpuInfos()) == 0 {
		return nil, fmt.Errorf("empty MPT attestation")
	}
	maxGpuCount := opts.MaxGpuCount
	if maxGpuCount <= 0 {
		maxGpuCount = DefaultMaxGpuCount
	}
	if got := len(quote.GetGpuInfos()); got > maxGpuCount {
		return nil, fmt.Errorf("MPT attestation has %d GPU reports, want at most %d", got, maxGpuCount)
	}

	if err := utility.ValidateModes(quote, abi.MPTMode); err != nil {
		allErrs = append(allErrs, err)
	}

	quoteState := &pb.GpuQuoteState{
		GpuInfoStates: make([]*pb.GpuInfoState, 0, len(quote.GetGpuInfos())),
	}

	for _, gpuInfo := range quote.GetGpuInfos() {
		// 2. Perform verification for the specific GPU.
		gpuInfoState, err := verifyGpuInfo(ctx, gpuInfo, opts.Verification)
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("GPU UUID %q: %w", gpuInfo.GetUuid(), err))
			// Skip this GPU and avoid appending a nil gpuInfoState.
			continue
		}

		// 3. Verification succeeded, so proceed with validation.
		opts.Validation.DriverVersion = gpuInfo.GetDriverVersion()
		opts.Validation.VBiosVersion = gpuInfo.GetVbiosVersion()

		err = validate.AttestationReport(ctx, gpuInfo.GetAttestationReport(), opts.Validation)
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("GPU UUID %q: %w", gpuInfo.GetUuid(), err))
		} else if !opts.Validation.DisableRefCheck {
			gpuInfoState.MeasurementsMatched = true
		}

		// 4. Safe append: gpuInfoState is guaranteed to be non-nil here due to the 'continue' above.
		quoteState.GpuInfoStates = append(quoteState.GpuInfoStates, gpuInfoState)
	}

	return quoteState, multierr.Combine(allErrs...)
}
