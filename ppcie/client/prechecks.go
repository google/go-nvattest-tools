// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package client provides system-level attestation utilities for multi-device
// systems, such as NVIDIA HGX platforms. It orchestrates pre-checks and
// attestation collection for PPCIe-connected devices.
package client

import (
	"context"
	"errors"
	"fmt"

	attestclient "github.com/google/go-nvattest-tools/client"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/google/go-nvattest-tools/internal/nvnscq/pkg/nscq"
)

// Prechecker implements the pre-check logic.
type Prechecker struct {
	NVML nvml.Interface
	NSCQ nscq.Interface
}

// DefaultPrechecker creates a new Prechecker with default implementations.
func DefaultPrechecker() *Prechecker {
	return &Prechecker{
		NVML: nvml.New(),
		NSCQ: nscq.New(),
	}
}

// Options holds configuration for the PPCIE client.
// This structure is based on the LLD.
type Options struct {
	// ExpectedGpuCount is the number of GPUs expected in the system (e.g., 8 for HGX).
	ExpectedGpuCount int
	// ExpectedSwitchCount is the number of NVSwitches expected in the system (e.g., 4 for HGX).
	ExpectedSwitchCount int
}

// Precheck performs pre-validation checks for both GPUs and NVSwitches.
func (p *Prechecker) Precheck(ctx context.Context, opts *Options) error {
	var allErrors []error
	allErrors = append(allErrors, p.performGPUPreChecks(ctx, opts)...)
	allErrors = append(allErrors, p.performNvSwitchPreChecks(ctx, opts)...)

	if err := errors.Join(allErrors...); err != nil {
		return fmt.Errorf("pre-validation checks failed: %w", err)
	}
	return nil
}

// Precheck performs pre-validation checks for both GPUs and NVSwitches using the default prechecker.
func Precheck(ctx context.Context, opts *Options) error {
	return DefaultPrechecker().Precheck(ctx, opts)
}

// performGPUPreChecks handles the internal logic for GPU pre-validation.
func (p *Prechecker) performGPUPreChecks(ctx context.Context, opts *Options) (errs []error) {
	if ret := p.NVML.Init(); ret != nvml.SUCCESS {
		return []error{&attestclient.LibError{Operation: "initialize NVML", ReturnCode: ret}}
	}
	defer func() {
		if shutdownRet := p.NVML.Shutdown(); shutdownRet != nvml.SUCCESS {
			errs = append(errs, &attestclient.LibError{Operation: "shutdown NVML", ReturnCode: shutdownRet})
		}
	}()

	// 1. Check GPU Count.
	gpuCount, ret := p.NVML.DeviceGetCount()
	if ret != nvml.SUCCESS {
		errs = append(errs, &attestclient.LibError{Operation: "get GPU count", ReturnCode: ret})
	} else if gpuCount != opts.ExpectedGpuCount {
		errs = append(errs, &GpuCountMismatchError{Want: opts.ExpectedGpuCount, Got: gpuCount})
	}

	// 2. Check System-wide TNVL Mode.
	settings, ret := p.NVML.SystemGetConfComputeSettings()
	if ret != nvml.SUCCESS {
		errs = append(errs, &attestclient.LibError{Operation: "get system-wide TNVL mode", ReturnCode: ret})
	} else {
		// In PPCIe mode, the system's MultiGpuMode must be enabled (set to 1).
		const multiGpuModeEnabled = 1
		if settings.MultiGpuMode != multiGpuModeEnabled {
			errs = append(errs, &GpuTnvlDisabledError{})
		}
	}

	return errs
}

// performNvSwitchPreChecks handles the internal logic for NVSwitch pre-validation.
func (p *Prechecker) performNvSwitchPreChecks(ctx context.Context, opts *Options) (errs []error) {
	if ret := p.NSCQ.Init(); ret != nscq.Success {
		return []error{&attestclient.LibError{Operation: "initialize NSCQ", ReturnCode: ret}}
	}
	defer func() {
		if shutdownRet := p.NSCQ.Shutdown(); shutdownRet != nscq.Success {
			errs = append(errs, &attestclient.LibError{Operation: "shutdown NSCQ", ReturnCode: shutdownRet})
		}
	}()

	const defaultNscqSessionFlags = 1
	session, ret := p.NSCQ.SessionCreate(defaultNscqSessionFlags)
	if ret != nscq.Success {
		return []error{&attestclient.LibError{Operation: "create NSCQ session", ReturnCode: ret}}
	}
	defer func() {
		if destroyRet := p.NSCQ.SessionDestroy(session); destroyRet != nscq.Success {
			errs = append(errs, &attestclient.LibError{Operation: "destroy NSCQ session", ReturnCode: destroyRet})
		}
	}()

	uuids, ret := p.NSCQ.SwitchDeviceUUIDs(session)
	if ret != nscq.Success {
		errs = append(errs, &attestclient.LibError{Operation: "get all device UUIDs", ReturnCode: ret})
	}

	if len(uuids) != opts.ExpectedSwitchCount {
		errs = append(errs, &NvSwitchCountMismatchError{Want: opts.ExpectedSwitchCount, Got: len(uuids)})
	}

	for _, uuid := range uuids {
		mode, ret := p.NSCQ.SwitchPCIEMode(session, uuid)
		if ret != nscq.Success {
			errs = append(errs, &attestclient.LibError{Operation: fmt.Sprintf("get PCIe mode for NVSwitch %s", uuid), ReturnCode: ret})
			continue
		}
		// In PPCIe mode, the NVSwitch's PCIe mode must have TNVL enabled (bit 0) and locked (bit 1).
		// This corresponds to a mode value of 3.
		const expectedPcieMode = 3
		if mode != expectedPcieMode {
			errs = append(errs, &NvSwitchTnvlDisabledError{UUID: uuid, Mode: mode})
		}
	}

	return errs
}
