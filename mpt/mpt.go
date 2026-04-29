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

// Options holds the options for the MPT.
type Options struct {
	Validation   validate.Options
	Verification verify.Options
}

// VerifySystemQuotes verifies a GpuAttestationQuote from an MPT system.
func VerifySystemQuotes(ctx context.Context, quote *pb.GpuAttestationQuote, opts Options) (*pb.GpuQuoteState, error) {
	var allErrs []error

	// 1. Initial Validation for MPT mode.
	if len(quote.GetGpuInfos()) == 0 {
		return nil, fmt.Errorf("empty MPT attestation")
	}

	if err := utility.ValidateModes(quote, abi.MPTMode); err != nil {
		allErrs = append(allErrs, err)
	}

	quoteState := &pb.GpuQuoteState{
		GpuInfoStates: make([]*pb.GpuInfoState, 0, len(quote.GetGpuInfos())),
	}

	for _, gpuInfo := range quote.GetGpuInfos() {
		// 2. Perform verification for the specific GPU.
		gpuInfoState, err := verify.GpuInfo(ctx, gpuInfo, opts.Verification)
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
