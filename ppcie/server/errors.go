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

package ppcie

import (
	"errors"
	"fmt"

	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"
)

var (
	// ErrTopologyGpuCountMismatch indicates a mismatch between expected and actual GPU reports.
	ErrTopologyGpuCountMismatch = errors.New("mismatched GPU count")
	// ErrTopologySwitchCountMismatch indicates a mismatch between expected and actual NVSwitch reports.
	ErrTopologySwitchCountMismatch = errors.New("mismatched NVSwitch count")
	// ErrInconsistentSwitchView indicates that GPUs do not report a consistent set of connected switches.
	ErrInconsistentSwitchView = errors.New("inconsistent NVSwitch view from GPUs")
	// ErrTopologyInconsistent indicates a discrepancy between reported device connections.
	ErrTopologyInconsistent = errors.New("topology is inconsistent")
	// ErrNilOptions is returned when a nil PPCIEOptions is provided.
	ErrNilOptions = errors.New("ppcie: options cannot be nil")
	// ErrEmptyReports is returned when empty GPU or NVSwitch attestation reports are provided.
	ErrEmptyReports = errors.New("ppcie: cannot validate topology with no reports")
	// ErrDuplicateSwitchPDI indicates that a duplicate NVSwitch PDI was detected.
	ErrDuplicateSwitchPDI = errors.New("duplicate NVSwitch PDI detected")
)

// MissingOpaqueDataError indicates a required field was not found in a report.
type MissingOpaqueDataError struct {
	DeviceType     string // e.g., "GPU" or "NVSwitch"
	DeviceIndex    int
	OpaqueDataType nvattestpb.OpaqueDataType
}

func (e *MissingOpaqueDataError) Error() string {
	return fmt.Sprintf("%s report at index %d missing required opaque data field: %s", e.DeviceType, e.DeviceIndex, e.OpaqueDataType.String())
}
