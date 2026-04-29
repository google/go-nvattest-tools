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

package ppcie

import (
	"context"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
)

// Options holds configuration for the PPCIE Verifier.
// This structure is based on the LLD.
type Options struct {
	// VerificationOpts contains the configuration for the verify package (authenticity checks).
	VerificationOpts verify.Options
	// GPUValidationOpts contains the configuration for the validate package (integrity checks) for GPU.
	GPUValidationOpts validate.Options
	// NVSwitchValidationOpts contains the configuration for the validate package (integrity checks) for NVSwitch.
	NVSwitchValidationOpts validate.Options
	// ExpectedGpuCount is the number of GPUs expected in the system (e.g., 8 for HGX).
	ExpectedGpuCount int
	// ExpectedSwitchCount is the number of NVSwitches expected in the system (e.g., 4 for HGX).
	ExpectedSwitchCount int

	// private fields for testing via dependency injection.
	verifyGpuInfoFn             func(ctx context.Context, gpuInfo *pb.GpuInfo, opts verify.Options) (*pb.GpuInfoState, error)
	verifySwitchInfoFn          func(ctx context.Context, switchInfo *pb.SwitchInfo, opts verify.Options) (*pb.SwitchInfoState, error)
	validateAttestationReportFn func(ctx context.Context, rawAttestationReport []uint8, opts validate.Options) error
	validateModesFn             func(gpuQuote *pb.GpuAttestationQuote, mode string) error
}
