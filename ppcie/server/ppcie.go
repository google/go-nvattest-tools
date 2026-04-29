// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ppcie provides system-level attestation utilities for multi-device
// systems, such as NVIDIA HGX platforms. It orchestrates attestation verification
// and topology validation for PPCIe-connected devices.
package ppcie

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-nvattest-tools/abi"
	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/utility"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
)

// ValidateSystemTopology validates the PCIe topology based on provided attestation reports.
// This function assumes the reports have already been individually verified and
// focuses solely on validating the interconnections based on the opaque data within them.
// It returns sentinel errors like ErrNilOptions, or ErrEmptyReports for
// invalid arguments. On validation failure, it returns a descriptive error that may wrap
// sentinel errors like ErrTopologyGpuCountMismatch.
func ValidateSystemTopology(ctx context.Context, gpuAttestationReports []*nvattestpb.AttestationReport, switchAttestationReports []*nvattestpb.AttestationReport, opts *Options) error {
	if opts == nil {
		return ErrNilOptions
	}
	// The len() function on a nil slice returns 0, so this check correctly handles both nil and empty slices.
	if len(gpuAttestationReports) == 0 || len(switchAttestationReports) == 0 {
		return ErrEmptyReports
	}

	return validateSystemTopology(
		ctx,
		gpuAttestationReports,
		switchAttestationReports,
		opts.ExpectedGpuCount,
		opts.ExpectedSwitchCount,
	)
}

// VerifySystemQuotes verifies previously collected GpuAttestationQuote and SwitchAttestationQuote.
// It orchestrates calls to the verify and validate packages for each device.
func VerifySystemQuotes(ctx context.Context, gpuQuote *nvattestpb.GpuAttestationQuote, switchQuote *nvattestpb.SwitchAttestationQuote, opts Options) (*nvattestpb.GpuQuoteState, *nvattestpb.SwitchQuoteState, error) {
	if opts.verifyGpuInfoFn == nil {
		opts.verifyGpuInfoFn = verify.GpuInfo
	}
	if opts.verifySwitchInfoFn == nil {
		opts.verifySwitchInfoFn = verify.SwitchInfo
	}
	if opts.validateAttestationReportFn == nil {
		opts.validateAttestationReportFn = validate.AttestationReport
	}
	if opts.validateModesFn == nil {
		opts.validateModesFn = utility.ValidateModes
	}

	gpuQuoteState := &nvattestpb.GpuQuoteState{
		GpuInfoStates: make([]*nvattestpb.GpuInfoState, 0, len(gpuQuote.GetGpuInfos())),
	}
	switchQuoteState := &nvattestpb.SwitchQuoteState{
		SwitchInfoStates: make([]*nvattestpb.SwitchInfoState, 0, len(switchQuote.GetSwitchInfos())),
	}
	var allErrs []error

	// Initial Validation for PPCIE mode.
	if err := opts.validateModesFn(gpuQuote, abi.PPCIEMode); err != nil {
		allErrs = append(allErrs, err)
	}

	for _, gpuInfo := range gpuQuote.GetGpuInfos() {
		gpuInfoState, err := opts.verifyGpuInfoFn(ctx, gpuInfo, opts.VerificationOpts)
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("GPU UUID %q: %w", gpuInfo.GetUuid(), err))
			continue
		}

		// Set the driver and VBIOS versions based on the GPU info.
		opts.GPUValidationOpts.DriverVersion = gpuInfo.GetDriverVersion()
		opts.GPUValidationOpts.VBiosVersion = gpuInfo.GetVbiosVersion()
		err = opts.validateAttestationReportFn(ctx, gpuInfo.GetAttestationReport(), opts.GPUValidationOpts)
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("GPU UUID %q: %w", gpuInfo.GetUuid(), err))
		} else if !opts.GPUValidationOpts.DisableRefCheck {
			// This block only executes if validateAttestationReport succeeds. If reference check is
			// enabled, success implies that reference measurements matched.
			gpuInfoState.MeasurementsMatched = true
		}
		gpuQuoteState.GpuInfoStates = append(gpuQuoteState.GpuInfoStates, gpuInfoState)
	}

	for _, switchInfo := range switchQuote.GetSwitchInfos() {
		switchInfoState, err := opts.verifySwitchInfoFn(ctx, switchInfo, opts.VerificationOpts)
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("switch UUID %q: %w", switchInfo.GetUuid(), err))
			continue
		}

		// Set the BIOS version in the validation options
		// since it's extracted from the opaque data and only available after verification.
		opts.NVSwitchValidationOpts.VBiosVersion = switchInfoState.GetBiosVersion()
		err = opts.validateAttestationReportFn(ctx, switchInfo.GetAttestationReport(), opts.NVSwitchValidationOpts)
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("switch UUID %q: %w", switchInfo.GetUuid(), err))
		} else if !opts.NVSwitchValidationOpts.DisableRefCheck {
			// This block only executes if validateAttestationReport succeeds. If reference check is
			// enabled, success implies that reference measurements matched.
			switchInfoState.MeasurementsMatched = true
		}
		switchQuoteState.SwitchInfoStates = append(switchQuoteState.SwitchInfoStates, switchInfoState)
	}

	return gpuQuoteState, switchQuoteState, errors.Join(allErrs...)
}
