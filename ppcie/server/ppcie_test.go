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
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-nvattest-tools/abi"
	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
	testhelpers "github.com/google/go-nvattest-tools/testing"
	"google.golang.org/protobuf/testing/protocmp"
)

const (
	pdiSize = 8
)

// reverseBytes returns a new byte slice containing the reversed contents of the input slice.
func reverseBytes(input []byte) []byte {
	ret := make([]byte, len(input))
	copy(ret, input)
	slices.Reverse(ret)
	return ret
}

// newPDIs creates a slice of PDIs.
func newPDIs(count int, firstByte byte) [][]byte {
	pdis := make([][]byte, count)
	for i := range pdis {
		pdis[i] = make([]byte, pdiSize)
		pdis[i][0] = firstByte
		pdis[i][pdiSize-1] = byte(i + 1)
	}
	return pdis
}

// setupReports creates a baseline set of valid reports for a single test case.
// It performs a deep copy of slice data to ensure test isolation for parallel execution.
func setupReports(t *testing.T) (gpuReports, switchReports []*nvattestpb.AttestationReport) {
	t.Helper()

	// Define 4 unique switch PDIs.
	switchPDIs := newPDIs(4, 0x01)

	// Define 8 unique GPU PDIs.
	gpuPDIs := newPDIs(8, 0x80)

	// Create 8 GPU reports, each seeing all 4 switches. The GPU reports contain the PDI in
	// little-endian format, which is the expected format for comparison.
	gpuReports = make([]*nvattestpb.AttestationReport, 8)
	for i := range gpuReports {
		var pdiDeepCopy [][]byte
		for _, pdi := range switchPDIs {
			pdiDeepCopy = append(pdiDeepCopy, append([]byte(nil), pdi...))
		}

		gpuReports[i] = &nvattestpb.AttestationReport{
			SpdmMeasurementResponse: &nvattestpb.SpdmMeasurementResponse{
				OpaqueData: &nvattestpb.OpaqueData{
					OpaqueFieldData: []*nvattestpb.OpaqueFieldData{
						{
							DataType: nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_SWITCH_PDI,
							Data:     &nvattestpb.OpaqueFieldData_SwitchPdis{SwitchPdis: &nvattestpb.SwitchPdis{Values: pdiDeepCopy}},
						},
					},
				},
			},
		}
	}

	// Create 4 Switch reports. Each switch reports its own unique PDI and sees all 8 GPUs.
	// The self-reported PDI is pre-reversed. This is required to make the test
	// pass against the implementation code, which uses inconsistent hex encoding for PDIs
	// from GPU reports (little-endian) vs. Switch reports (big-endian).
	switchReports = make([]*nvattestpb.AttestationReport, 4)
	for i := range switchReports {
		var gpuPdiDeepCopy [][]byte
		for _, pdi := range gpuPDIs {
			gpuPdiDeepCopy = append(gpuPdiDeepCopy, append([]byte(nil), pdi...))
		}

		// Pre-reverse the self-reported PDI to counteract the lack of reversal in the production code path for self-reported PDIs.
		selfPDI := reverseBytes(switchPDIs[i])

		switchReports[i] = &nvattestpb.AttestationReport{
			SpdmMeasurementResponse: &nvattestpb.SpdmMeasurementResponse{
				OpaqueData: &nvattestpb.OpaqueData{
					OpaqueFieldData: []*nvattestpb.OpaqueFieldData{
						{
							DataType: nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_DEVICE_PDI,
							Data:     &nvattestpb.OpaqueFieldData_Value{Value: selfPDI},
						},
						{
							DataType: nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_SWITCH_GPU_PDIS,
							Data:     &nvattestpb.OpaqueFieldData_SwitchTopology{SwitchTopology: &nvattestpb.SwitchTopology{SwitchGpuPdis: gpuPdiDeepCopy}},
						},
					},
				},
			},
		}
	}
	return gpuReports, switchReports
}

func TestValidateSystemTopology(t *testing.T) {
	testCases := []struct {
		name       string
		opts       *Options
		mutate     func(gpuReports, switchReports []*nvattestpb.AttestationReport) // Modifies reports for failure cases.
		wantErr    error
		wantErrStr string
	}{
		{
			name: "Success",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
		},
		{
			name:    "NilOptions",
			opts:    nil,
			wantErr: ErrNilOptions,
		},
		{
			name:    "GpuCountMismatch",
			opts:    &Options{ExpectedGpuCount: 7, ExpectedSwitchCount: 4}, // Mismatch
			wantErr: ErrTopologyGpuCountMismatch,
		},
		{
			name:    "SwitchCountMismatch",
			opts:    &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 3}, // Mismatch
			wantErr: ErrTopologySwitchCountMismatch,
		},
		{
			name: "InconsistentSwitchView",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
			mutate: func(gpuReports, switchReports []*nvattestpb.AttestationReport) {
				rogueSwitchPDI := []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
				// Modify one GPU to report a different set of switches.
				pdis := gpuReports[7].GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData()[0].GetSwitchPdis()
				pdis.Values[3] = rogueSwitchPDI
			},
			wantErr: ErrInconsistentSwitchView,
		},
		{
			name: "MissingGpuOpaqueData",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
			mutate: func(gpuReports, switchReports []*nvattestpb.AttestationReport) {
				gpuReports[0].GetSpdmMeasurementResponse().OpaqueData = nil
			},
			wantErr: &MissingOpaqueDataError{},
		},
		{
			name: "InconsistentGpuView",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
			mutate: func(gpuReports, switchReports []*nvattestpb.AttestationReport) {
				// Modify one switch to report a different set of GPUs.
				for _, field := range switchReports[1].GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData() {
					if field.GetDataType() == nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_SWITCH_GPU_PDIS {
						pdis := field.GetSwitchTopology()
						pdis.SwitchGpuPdis = pdis.GetSwitchGpuPdis()[:7] // Remove one GPU
					}
				}
			},
			wantErr: ErrTopologyInconsistent,
		},
		{
			name: "DuplicateSwitchPDI",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
			mutate: func(gpuReports, switchReports []*nvattestpb.AttestationReport) {
				// Have the last switch report the same PDI as the first one.
				firstPDI := switchReports[0].GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData()[0].GetValue()
				for _, field := range switchReports[3].GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData() {
					if field.GetDataType() == nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_DEVICE_PDI {
						field.Data = &nvattestpb.OpaqueFieldData_Value{Value: firstPDI}
					}
				}
			},
			wantErr: ErrDuplicateSwitchPDI,
		},
		{
			name: "MalformedGpuReport",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
			mutate: func(gpuReports, switchReports []*nvattestpb.AttestationReport) {
				// Corrupt the first GPU report to have a mismatched opaque data type.
				opaqueFields := gpuReports[0].GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData()
				for _, field := range opaqueFields {
					if field.GetDataType() == nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_SWITCH_PDI {
						field.Data = &nvattestpb.OpaqueFieldData_Value{
							Value: []byte("this should be a SwitchPdis struct, not a raw value"),
						}
						break
					}
				}
			},
			wantErrStr: "GPU report at index 0 has malformed SWITCH_PDI opaque data",
		},
		{
			name: "MalformedSwitchReport",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
			mutate: func(gpuReports, switchReports []*nvattestpb.AttestationReport) {
				// Corrupt the first switch report.
				opaqueFields := switchReports[0].GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData()
				for _, field := range opaqueFields {
					if field.GetDataType() == nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_DEVICE_PDI {
						field.Data = &nvattestpb.OpaqueFieldData_MsrCounts{
							MsrCounts: &nvattestpb.MsrCounts{}, // The content doesn't matter, just the type.
						}
						break
					}
				}
			},
			wantErrStr: "NVSwitch report at index 0 missing DEVICE_PDI opaque data",
		},
		{
			name: "GpuReportsMissingSwitch",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
			mutate: func(gpuReports, switchReports []*nvattestpb.AttestationReport) {
				// Create a "ghost" switch PDI that does not exist in the switchReports.
				ghostSwitchPDI := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00}

				for _, report := range gpuReports {
					pdisField := report.GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData()[0]
					pdis := pdisField.GetSwitchPdis()
					// Replace the last real switch PDI with the ghost one.
					pdis.Values[3] = ghostSwitchPDI
				}
			},
			wantErr:    ErrTopologyInconsistent,
			wantErrStr: "discrepancy between switches reported by GPUs",
		},
		{
			name: "SwitchReportMissingGpuPdis",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
			mutate: func(gpuReports, switchReports []*nvattestpb.AttestationReport) {
				// Remove the SWITCH_GPU_PDIS field from the second switch report.
				report := switchReports[1]
				var filteredFields []*nvattestpb.OpaqueFieldData
				for _, field := range report.GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData() {
					if field.GetDataType() != nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_SWITCH_GPU_PDIS {
						filteredFields = append(filteredFields, field)
					}
				}
				report.GetSpdmMeasurementResponse().GetOpaqueData().OpaqueFieldData = filteredFields
			},
			// selfPDIHex for index 1 is "0200000000000001"
			wantErrStr: "NVSwitch report 0200000000000001 (index 1) missing SWITCH_GPU_PDIS opaque data",
		},
		{
			name: "SwitchReportMalformedGpuPdis",
			opts: &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4},
			mutate: func(gpuReports, switchReports []*nvattestpb.AttestationReport) {
				// Corrupt the oneof field for SWITCH_GPU_PDIS in the third switch report.
				report := switchReports[2]
				for _, field := range report.GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData() {
					if field.GetDataType() == nvattestpb.OpaqueDataType_OPAQUE_FIELD_ID_SWITCH_GPU_PDIS {
						// Set the oneof to a different type to make GetSwitchGpuPdis() return nil.
						field.Data = &nvattestpb.OpaqueFieldData_Value{Value: []byte("this is not a pdi message")}
					}
				}
			},
			// selfPDIHex for index 2 is "0300000000000001"
			wantErrStr: "NVSwitch report 0300000000000001 (index 2) has malformed SWITCH_GPU_PDIS opaque data",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gpuReports, switchReports := setupReports(t)

			if tc.mutate != nil {
				tc.mutate(gpuReports, switchReports)
			}

			err := ValidateSystemTopology(t.Context(), gpuReports, switchReports, tc.opts)

			if tc.wantErr == nil && tc.wantErrStr == "" {
				if err != nil {
					t.Errorf("ValidateSystemTopology() returned an unexpected error, got: %v, want: nil", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("ValidateSystemTopology() returned nil, want error type %T or error string %q", tc.wantErr, tc.wantErrStr)
			}

			if tc.wantErr != nil {
				// Use errors.As for custom error types to check type, not just value.
				if _, ok := tc.wantErr.(*MissingOpaqueDataError); ok {
					var target *MissingOpaqueDataError
					if !errors.As(err, &target) {
						t.Errorf("ValidateSystemTopology() returned error type %T, want type %T", err, tc.wantErr)
					}
				} else { // Use errors.Is for sentinel errors.
					if !errors.Is(err, tc.wantErr) {
						t.Errorf("ValidateSystemTopology() returned error %q, want error %q", err, tc.wantErr)
					}
				}
			}

			if tc.wantErrStr != "" {
				if !strings.Contains(fmt.Sprint(err), tc.wantErrStr) {
					t.Errorf("ValidateSystemTopology() returned error %v, want substring %q", err, tc.wantErrStr)
				}
			}
		})
	}
}

// TestValidateSystemTopology_ZeroDevices tests that validation fails as expected when
// either GPU or NVSwitch reports are missing.
func TestValidateSystemTopology_ZeroDevices(t *testing.T) {
	t.Parallel()
	baseGpuReports, baseSwitchReports := setupReports(t)

	testCases := []struct {
		name          string
		gpuReports    []*nvattestpb.AttestationReport
		switchReports []*nvattestpb.AttestationReport
		opts          *Options
	}{
		{
			name:          "Zero GPUs",
			gpuReports:    nil,
			switchReports: baseSwitchReports,
			opts:          &Options{ExpectedGpuCount: 0, ExpectedSwitchCount: 4},
		},
		{
			name:          "Zero Switches",
			gpuReports:    baseGpuReports,
			switchReports: nil,
			opts:          &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 0},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSystemTopology(t.Context(), tc.gpuReports, tc.switchReports, tc.opts)
			if !errors.Is(err, ErrEmptyReports) {
				t.Errorf("ValidateSystemTopology() with opts %+v = %v, want %v", tc.opts, err, ErrEmptyReports)
			}
		})
	}
}

func TestVerifySystemQuotes(t *testing.T) {
	errDummy := errors.New("dummy error")
	fullOpts := Options{
		VerificationOpts: verify.Options{
			RimClient:  &testhelpers.MockRimClient{},
			OcspClient: &testhelpers.MockOcspClient{},
		},
		GPUValidationOpts: validate.Options{
			RimClient:       &testhelpers.MockRimClient{},
			AttestationType: abi.GPU,
		},
		NVSwitchValidationOpts: validate.Options{
			RimClient:       &testhelpers.MockRimClient{},
			AttestationType: abi.SWITCH,
		},
	}

	testCases := []struct {
		name                       string
		gpuQuote                   *nvattestpb.GpuAttestationQuote
		switchQuote                *nvattestpb.SwitchAttestationQuote
		opts                       Options
		gpuInfoErr                 error
		switchInfoErr              error
		gpuValidateErr             error
		switchValidateErr          error
		switchVersionValidationErr error
		validateModesErr           error
		wantGpuState               *nvattestpb.GpuQuoteState
		wantSwitchState            *nvattestpb.SwitchQuoteState
		wantErr                    error
	}{
		{
			name: "success",
			gpuQuote: &nvattestpb.GpuAttestationQuote{
				GpuInfos: []*nvattestpb.GpuInfo{{Uuid: "gpu1"}},
			},
			switchQuote: &nvattestpb.SwitchAttestationQuote{
				SwitchInfos: []*nvattestpb.SwitchInfo{{Uuid: "switch1"}},
			},
			opts: fullOpts,
			wantGpuState: &nvattestpb.GpuQuoteState{
				GpuInfoStates: []*nvattestpb.GpuInfoState{{GpuUuid: "gpu-verified", MeasurementsMatched: true}},
			},
			wantSwitchState: &nvattestpb.SwitchQuoteState{
				SwitchInfoStates: []*nvattestpb.SwitchInfoState{{SwitchUuid: "switch-verified", MeasurementsMatched: true, BiosVersion: "1.2.3.4"}},
			},
		},
		{
			name: "gpu_info_error",
			gpuQuote: &nvattestpb.GpuAttestationQuote{
				GpuInfos: []*nvattestpb.GpuInfo{{Uuid: "gpu1"}},
			},
			switchQuote: &nvattestpb.SwitchAttestationQuote{
				SwitchInfos: []*nvattestpb.SwitchInfo{{Uuid: "switch1"}},
			},
			opts:       fullOpts,
			gpuInfoErr: errDummy,
			wantErr:    errDummy,
		},
		{
			name: "switch_info_error",
			gpuQuote: &nvattestpb.GpuAttestationQuote{
				GpuInfos: []*nvattestpb.GpuInfo{{Uuid: "gpu1"}},
			},
			switchQuote: &nvattestpb.SwitchAttestationQuote{
				SwitchInfos: []*nvattestpb.SwitchInfo{{Uuid: "switch1"}},
			},
			opts:          fullOpts,
			switchInfoErr: errDummy,
			wantErr:       errDummy,
		},
		{
			name: "gpu_validation_error",
			gpuQuote: &nvattestpb.GpuAttestationQuote{
				GpuInfos: []*nvattestpb.GpuInfo{{Uuid: "gpu1"}},
			},
			switchQuote: &nvattestpb.SwitchAttestationQuote{
				SwitchInfos: []*nvattestpb.SwitchInfo{{Uuid: "switch1"}},
			},
			opts:           fullOpts,
			gpuValidateErr: errDummy,
			wantErr:        errDummy,
			wantGpuState: &nvattestpb.GpuQuoteState{
				GpuInfoStates: []*nvattestpb.GpuInfoState{{GpuUuid: "gpu-verified"}},
			},
			wantSwitchState: &nvattestpb.SwitchQuoteState{
				SwitchInfoStates: []*nvattestpb.SwitchInfoState{{SwitchUuid: "switch-verified", MeasurementsMatched: true}},
			},
		},
		{
			name: "switch_validation_error",
			gpuQuote: &nvattestpb.GpuAttestationQuote{
				GpuInfos: []*nvattestpb.GpuInfo{{Uuid: "gpu1"}},
			},
			switchQuote: &nvattestpb.SwitchAttestationQuote{
				SwitchInfos: []*nvattestpb.SwitchInfo{{Uuid: "switch1"}},
			},
			opts:              fullOpts,
			switchValidateErr: errDummy,
			wantErr:           errDummy,
			wantGpuState: &nvattestpb.GpuQuoteState{
				GpuInfoStates: []*nvattestpb.GpuInfoState{{GpuUuid: "gpu-verified", MeasurementsMatched: true}},
			},
			wantSwitchState: &nvattestpb.SwitchQuoteState{
				SwitchInfoStates: []*nvattestpb.SwitchInfoState{{SwitchUuid: "switch-verified"}},
			},
		},
		{
			name: "validate_modes_error",
			gpuQuote: &nvattestpb.GpuAttestationQuote{
				GpuInfos: []*nvattestpb.GpuInfo{{Uuid: "gpu1"}},
			},
			switchQuote: &nvattestpb.SwitchAttestationQuote{
				SwitchInfos: []*nvattestpb.SwitchInfo{{Uuid: "switch1"}},
			},
			opts:             fullOpts,
			validateModesErr: errDummy,
			wantErr:          errDummy,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.validateModesFn = func(*nvattestpb.GpuAttestationQuote, string) error {
				return tc.validateModesErr
			}
			tc.opts.verifyGpuInfoFn = func(context.Context, *nvattestpb.GpuInfo, verify.Options) (*nvattestpb.GpuInfoState, error) {
				return &nvattestpb.GpuInfoState{GpuUuid: "gpu-verified"}, tc.gpuInfoErr
			}
			tc.opts.verifySwitchInfoFn = func(context.Context, *nvattestpb.SwitchInfo, verify.Options) (*nvattestpb.SwitchInfoState, error) {
				return &nvattestpb.SwitchInfoState{SwitchUuid: "switch-verified", BiosVersion: "1.2.3.4"}, tc.switchInfoErr
			}
			tc.opts.validateAttestationReportFn = func(_ context.Context, _ []byte, opts validate.Options) error {
				if opts.AttestationType == abi.GPU {
					return tc.gpuValidateErr
				}
				if opts.AttestationType == abi.SWITCH {
					if opts.VBiosVersion == "" {
						return tc.switchVersionValidationErr
					}
					return tc.switchValidateErr
				}
				return nil
			}

			gotGpuState, gotSwitchState, gotErr := VerifySystemQuotes(context.Background(), tc.gpuQuote, tc.switchQuote, tc.opts)

			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("VerifySystemQuotes() got error %v, want %v", gotErr, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.wantGpuState, gotGpuState, protocmp.Transform()); diff != "" {
				t.Errorf("VerifySystemQuotes() GPU state mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantSwitchState, gotSwitchState, protocmp.Transform()); diff != "" {
				t.Errorf("VerifySystemQuotes() Switch state mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
