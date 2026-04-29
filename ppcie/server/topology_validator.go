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
	"encoding/hex"
	"fmt"
	"maps"

	"github.com/google/go-cmp/cmp"

	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"
)

const (
	// disabledLinkPDIHex is the hex string representation of an 8-byte all-zero PDI.
	disabledLinkPDIHex = "0000000000000000"
)

// topologyValidator holds the state for a single topology validation run.
type topologyValidator struct {
	expectedGpuCount       int
	expectedSwitchCount    int
	gpuReports             []*nvattestpb.AttestationReport
	switchReports          []*nvattestpb.AttestationReport
	gpuReportedSwitchPDIs  map[int][]string    // Map from GPU index to its list of reported switch PDIs.
	switchReportedSelfPDIs map[string]bool     // Set of switch PDIs reported by the switches themselves.
	switchReportedGpuPDIs  map[string][]string // Map from Switch PDI to its list of reported GPU PDIs.
}

// findOpaqueField is a helper to find a specific opaque data field in an attestation report.
func findOpaqueField(report *nvattestpb.AttestationReport, dataType nvattestpb.OpaqueDataType) *nvattestpb.OpaqueFieldData {
	for _, field := range report.GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData() {
		if field.GetDataType() == dataType {
			return field
		}
	}
	return nil
}

// bytesToLittleEndianHex converts a byte slice to its little-endian hex string representation.
// This matches the nvtrust python implementation of read_field_as_little_endian.
func bytesToLittleEndianHex(b []byte) string {
	reversed := make([]byte, len(b))
	for i := range b {
		reversed[i] = b[len(b)-1-i]
	}
	return hex.EncodeToString(reversed)
}

// bytesToHex converts a slice of byte slices to a slice of hex strings.
func bytesToHex(byteSlices [][]byte) []string {
	hexStrings := make([]string, len(byteSlices))
	for i, b := range byteSlices {
		hexStrings[i] = hex.EncodeToString(b)
	}
	return hexStrings
}

// populatePDIs populates the validator's maps with data from GPU and switch reports.
func (v *topologyValidator) populatePDIs() error {
	// Extract data from GPU reports.
	for i, report := range v.gpuReports {
		field := findOpaqueField(report, nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_SWITCH_PDI)
		if field == nil {
			return &MissingOpaqueDataError{
				DeviceType:     "GPU",
				DeviceIndex:    i,
				OpaqueDataType: nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_SWITCH_PDI,
			}
		}
		pdis := field.GetSwitchPdis()
		if pdis == nil {
			return fmt.Errorf("GPU report at index %d has malformed SWITCH_PDI opaque data", i)
		}
		pdiValues := pdis.GetValues()
		hexPDIs := make([]string, len(pdiValues))
		for j, pdi := range pdiValues {
			hexPDIs[j] = bytesToLittleEndianHex(pdi)
		}
		v.gpuReportedSwitchPDIs[i] = hexPDIs
	}

	// Extract self-reported PDIs from Switch reports.
	for i, report := range v.switchReports {
		// get the switch's own PDI
		selfPDIField := findOpaqueField(report, nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_DEVICE_PDI)
		if selfPDIField.GetValue() == nil {
			return fmt.Errorf("NVSwitch report at index %d missing DEVICE_PDI opaque data", i)
		}

		selfPDIHex := hex.EncodeToString(selfPDIField.GetValue())
		if _, ok := v.switchReportedSelfPDIs[selfPDIHex]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicateSwitchPDI, selfPDIHex)
		}
		v.switchReportedSelfPDIs[selfPDIHex] = true

		// Extract the list of GPUs this switch is connected to.
		switchTopologyField := findOpaqueField(report, nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_SWITCH_GPU_PDIS)
		if switchTopologyField == nil {
			return fmt.Errorf("NVSwitch report %s (index %d) missing SWITCH_GPU_PDIS opaque data", selfPDIHex, i)
		}
		gpuPDIs := switchTopologyField.GetSwitchTopology().GetSwitchGpuPdis()
		if gpuPDIs == nil {
			return fmt.Errorf("NVSwitch report %s (index %d) has malformed SWITCH_GPU_PDIS opaque data", selfPDIHex, i)
		}
		v.switchReportedGpuPDIs[selfPDIHex] = bytesToHex(gpuPDIs)
	}
	return nil
}

// activePDIsToSet converts a slice of PDI hex strings to a set (map[string]bool),
// excluding any PDIs that represent a disabled link (all zeros).
func activePDIsToSet(pdis []string) map[string]bool {
	ret := make(map[string]bool, len(pdis))
	for _, pdi := range pdis {
		if pdi != disabledLinkPDIHex {
			ret[pdi] = true
		}
	}
	return ret
}

// validate performs all topology checks.
func (v *topologyValidator) validate() error {
	// 1. Check device counts.
	if len(v.gpuReports) != v.expectedGpuCount {
		return fmt.Errorf("%w: want %d, got %d", ErrTopologyGpuCountMismatch, v.expectedGpuCount, len(v.gpuReports))
	}
	if len(v.switchReports) != v.expectedSwitchCount {
		return fmt.Errorf("%w: want %d, got %d", ErrTopologySwitchCountMismatch, v.expectedSwitchCount, len(v.switchReports))
	}

	// 2. Validate GPU perspective: all GPUs must report the same set of switches.
	// Get the normalized set of active switches from the first GPU's report.
	goldenSwitchesSet := activePDIsToSet(v.gpuReportedSwitchPDIs[0])

	for i := 1; i < len(v.gpuReportedSwitchPDIs); i++ {
		// Normalize the current GPU's view of active switches.
		currentGpuActiveSwitchesSet := activePDIsToSet(v.gpuReportedSwitchPDIs[i])
		if !cmp.Equal(goldenSwitchesSet, currentGpuActiveSwitchesSet) {
			return fmt.Errorf("%w: GPU 0 reports active switches %v, but GPU %d reports %v",
				ErrInconsistentSwitchView, maps.Keys(goldenSwitchesSet), i, maps.Keys(currentGpuActiveSwitchesSet))
		}
	}

	// 3. Validate Switch perspective: all NVSwitches must report the same set of GPUs.
	var goldenGpuSet map[string]bool
	isFirst := true
	for switchPDI, gpuPDIs := range v.switchReportedGpuPDIs {
		currentSwitchGpuSet := activePDIsToSet(gpuPDIs)

		if isFirst {
			goldenGpuSet = currentSwitchGpuSet
			isFirst = false
		} else {
			if !cmp.Equal(goldenGpuSet, currentSwitchGpuSet) {
				return fmt.Errorf("%w: inconsistent GPU view from NVSwitches. First switch sees %v, but switch %s sees %v",
					ErrTopologyInconsistent, maps.Keys(goldenGpuSet), switchPDI, maps.Keys(currentSwitchGpuSet))
			}
		}
	}

	// 4. Cross-validate: The set of switches reported by GPUs must match the set of switches
	// that reported themselves.
	// The `goldenSwitchesSet` now represents the consistent, normalized view from all GPUs.
	if !cmp.Equal(goldenSwitchesSet, v.switchReportedSelfPDIs) {
		return fmt.Errorf("%w: discrepancy between switches reported by GPUs (%v) and switches reporting themselves (%v)",
			ErrTopologyInconsistent, maps.Keys(goldenSwitchesSet), maps.Keys(v.switchReportedSelfPDIs))
	}

	return nil
}

// validateSystemTopology is the internal implementation for topology validation.
// It checks for consistency in device counts and their reported interconnections.
func validateSystemTopology(ctx context.Context, gpuReports []*nvattestpb.AttestationReport, switchReports []*nvattestpb.AttestationReport, expectedGpuCount, expectedSwitchCount int) error {
	validator := &topologyValidator{
		expectedGpuCount:       expectedGpuCount,
		expectedSwitchCount:    expectedSwitchCount,
		gpuReports:             gpuReports,
		switchReports:          switchReports,
		gpuReportedSwitchPDIs:  make(map[int][]string),
		switchReportedSelfPDIs: make(map[string]bool),
		switchReportedGpuPDIs:  make(map[string][]string),
	}

	if err := validator.populatePDIs(); err != nil {
		return fmt.Errorf("failed to extract topology data from reports: %w", err)
	}

	if err := validator.validate(); err != nil {
		return fmt.Errorf("topology validation failed: %w", err)
	}
	return nil
}
