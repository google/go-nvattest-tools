// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package abi

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	testdata "github.com/google/go-nvattest-tools/testing/testdata"
)

func ExampleRawAttestationReportToProto() {
	data := testdata.RawGpuAttestationReportTestData.RawAttestationReport
	attestationType := GPU

	report, err := RawAttestationReportToProto(data, attestationType)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Output some fields to demonstrate successful parsing.
	fmt.Printf("Attestation Type: %s\n", attestationType)
	fmt.Printf("SPDM Version: %x\n", report.GetSpdmMeasurementRequest().GetSpdmVersion())
	fmt.Printf("Nonce: %x\n", report.GetSpdmMeasurementResponse().GetNonce())
	fmt.Printf("Opaque Data Fields: %d\n", len(report.GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData()))

	// Output:
	// Attestation Type: GPU
	// SPDM Version: 11
	// Nonce: b4b8a06aaaa35542839388e159d447a5d6f6194998fd86513e2d591ccf640985
	// Opaque Data Fields: 14
}

type TestCase struct {
	name       string
	dataLength int
	data       []byte
	wantErr    error
}

func TestAttestationReportToProto(t *testing.T) {
	testcases := []struct {
		name            string
		data            []byte
		attestationType AttestationType
		wantErr         error
	}{
		{
			name:            "valid_attestation_report_gpu",
			data:            testdata.RawGpuAttestationReportTestData.RawAttestationReport,
			attestationType: GPU,
			wantErr:         nil,
		},
		{
			name:            "valid_attestation_report_switch",
			data:            testdata.RawSwitchAttestationReportTestData.RawAttestationReport,
			attestationType: SWITCH,
			wantErr:         nil,
		},
		{
			name:            "invalid_attestation_report_spdm_measurement_request_length",
			data:            make([]byte, 0),
			attestationType: GPU,
			wantErr:         &IncorrectLengthError{Context: "raw attestation report SPDM measurement request size", Expected: SpdmRequestSize, Actual: 0},
		},
		{
			name:            "unsupported_attestation_type",
			data:            testdata.RawGpuAttestationReportTestData.RawAttestationReport,
			attestationType: -1,
			wantErr:         &UnsupportedAttestationTypeError{AttestationType: -1},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := RawAttestationReportToProto(testcase.data, testcase.attestationType)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
		})
	}
}

func TestParseSpdmMeasurementRequest(t *testing.T) {
	testcases := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{
			name:    "valid_spdm_measurement_request_gpu",
			data:    testdata.RawGpuAttestationReportTestData.RawAttestationReport,
			wantErr: nil,
		},
		{
			name:    "invalid_attestation_report_spdm_measurement_request_length",
			data:    make([]byte, 0),
			wantErr: &IncorrectLengthError{Context: "raw attestation report SPDM measurement request size", Expected: SpdmRequestSize, Actual: 0},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			request, err := parseSpdmMeasurementRequest(testcase.data)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
			if err == nil {
				if len(request.GetSpdmVersion()) != SpdmVersionFieldSize {
					t.Errorf("returned spdm version length: %d, want %d", len(request.GetSpdmVersion()), SpdmVersionFieldSize)
				}
				if len(request.GetRequestResponseCode()) != RequestResponseCodeFieldSize {
					t.Errorf("returned request response code length: %d, want %d", len(request.GetRequestResponseCode()), RequestResponseCodeFieldSize)
				}
				if len(request.GetParam1()) != Param1FieldSize {
					t.Errorf("returned param1 length: %d, want %d", len(request.GetParam1()), Param1FieldSize)
				}
				if len(request.GetParam2()) != Param2FieldSize {
					t.Errorf("returned param2 length: %d, want %d", len(request.GetParam2()), Param2FieldSize)
				}
				if len(request.GetNonce()) != NonceFieldSize {
					t.Errorf("returned nonce length: %d, want %d", len(request.GetNonce()), NonceFieldSize)
				}
				if len(request.GetSlotIdParam()) != SlotIDParamFieldSize {
					t.Errorf("returned slot id param length: %d, want %d", len(request.GetSlotIdParam()), SlotIDParamFieldSize)
				}
			}
		})
	}
}

func TestParseSpdmMeasurementResponse(t *testing.T) {
	testcases := []struct {
		name             string
		data             []byte
		opaqueDataParser opaqueDataParser
		signatureLength  int
		parsedLength     int
		wantErr          error
	}{
		{
			name:             "valid_spdm_measurement_response_gpu",
			data:             testdata.RawGpuAttestationReportTestData.RawAttestationReport[SpdmRequestSize:],
			opaqueDataParser: &gpuOpaqueDataParser{},
			signatureLength:  GpuAttestationReportSignatureFieldSize,
			parsedLength:     testdata.RawGpuAttestationReportTestData.SpdmMeasurementResponseDataLength,
			wantErr:          nil,
		},
		{
			name:             "parsing_error_in_spdm_measurement_response_gpu",
			data:             make([]byte, 0),
			opaqueDataParser: &gpuOpaqueDataParser{},
			signatureLength:  GpuAttestationReportSignatureFieldSize,
			wantErr:          &ParsingError{Context: "parseSpdmMeasurementResponse(...)", Info: OutOfRangeRuntimeError},
		},
		{
			name:             "valid_spdm_measurement_response_switch",
			data:             testdata.RawSwitchAttestationReportTestData.RawAttestationReport[SpdmRequestSize:],
			opaqueDataParser: &switchOpaqueDataParser{},
			signatureLength:  SwitchAttestationReportSignatureFieldSize,
			parsedLength:     testdata.RawSwitchAttestationReportTestData.SpdmMeasurementResponseDataLength,
			wantErr:          nil,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			response, parsedLength, err := parseSpdmMeasurementResponse(testcase.data, testcase.opaqueDataParser, testcase.signatureLength)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
			if response != nil {
				if len(response.GetSpdmVersion()) != SpdmVersionFieldSize {
					t.Errorf("returned spdm version length: %d, want %d", len(response.GetSpdmVersion()), SpdmVersionFieldSize)
				}
				if len(response.GetRequestResponseCode()) != RequestResponseCodeFieldSize {
					t.Errorf("returned request response code length: %d, want %d", len(response.GetRequestResponseCode()), RequestResponseCodeFieldSize)
				}
				if len(response.GetParam1()) != Param1FieldSize {
					t.Errorf("returned param1 length: %d, want %d", len(response.GetParam1()), Param1FieldSize)
				}
				if len(response.GetParam2()) != Param2FieldSize {
					t.Errorf("returned param2 length: %d, want %d", len(response.GetParam2()), Param2FieldSize)
				}
				if len(response.GetNonce()) != NonceFieldSize {
					t.Errorf("returned nonce length: %d, want %d", len(response.GetNonce()), NonceFieldSize)
				}
				if parsedLength != testcase.parsedLength {
					t.Errorf("returned bytes covered: %d, want %d", parsedLength, testcase.parsedLength)
				}
			}
		})
	}
}

func TestParseMeasurementRecord(t *testing.T) {
	start := SpdmRequestSize + testdata.RawGpuAttestationReportTestData.MeasurementRecordOffset
	defaultData := func() []byte {
		return testdata.RawGpuAttestationReportTestData.RawAttestationReport[start:]
	}
	unsupportedDmtfMeasurementSpecificationData := func() []byte {
		data := clone(testdata.RawGpuAttestationReportTestData.RawAttestationReport[start:])
		data[1] = 0 // corrupting the first measurement block's specification byte
		return data
	}
	invalidDmtfMeasurementRecordData := func() []byte {
		data := clone(testdata.RawGpuAttestationReportTestData.RawAttestationReport[start:])
		data[3] = 255 // corrupting the first measurement block's measurement size to cause panic
		return data
	}
	offsetMismatchInMeasurementRecordData := func() []byte {
		data := clone(testdata.RawGpuAttestationReportTestData.RawAttestationReport[start:])
		offset := testdata.RawGpuAttestationReportTestData.MeasurementRecordLength - testdata.RawGpuAttestationReportTestData.DmtfMeasurementLength
		data[offset-2 /*3467*/] = 4 // corrupting the last measurement block's measurement size to cause offset mismatch
		data[offset+1 /*3470*/] = 1 // corrupting the last measurement block's DMTF measurement value size to not throw a panic in parseDmtfMeasurement() function
		return data
	}
	outOfRangeMeasurementRecordData := func() []byte {
		data := make([]byte, 1)
		return data
	}

	testcases := []struct {
		name                    string
		data                    func() []byte
		numberOfBlocks          int
		measurementRecordLength int
		wantErr                 error
	}{
		{
			name:                    "valid_measurement_record",
			data:                    defaultData,
			numberOfBlocks:          testdata.RawGpuAttestationReportTestData.NumberOfBlocks,
			measurementRecordLength: testdata.RawGpuAttestationReportTestData.MeasurementRecordLength,
			wantErr:                 nil,
		},
		{
			name:                    "no_measurement_blocks",
			data:                    defaultData,
			numberOfBlocks:          0,
			measurementRecordLength: testdata.RawGpuAttestationReportTestData.MeasurementRecordLength,
			wantErr:                 &NoMeasurementBlocksError{},
		},
		{
			name:                    "unsupported_dmtf_measurement_specification",
			data:                    unsupportedDmtfMeasurementSpecificationData,
			numberOfBlocks:          testdata.RawGpuAttestationReportTestData.NumberOfBlocks,
			measurementRecordLength: testdata.RawGpuAttestationReportTestData.MeasurementRecordLength,
			wantErr:                 &UnsupportedDmtfMeasurementSpecificationError{Index: 1},
		},
		{
			name:                    "invalid_dmtf_measurement",
			data:                    invalidDmtfMeasurementRecordData,
			numberOfBlocks:          testdata.RawGpuAttestationReportTestData.NumberOfBlocks,
			measurementRecordLength: testdata.RawGpuAttestationReportTestData.MeasurementRecordLength,
			wantErr:                 &IncorrectLengthError{Context: "dmtf measurement", Expected: 65331, Actual: 3516},
		},
		{
			name:                    "offset_mismatch_in_measurement_record",
			data:                    offsetMismatchInMeasurementRecordData,
			numberOfBlocks:          testdata.RawGpuAttestationReportTestData.NumberOfBlocks,
			measurementRecordLength: testdata.RawGpuAttestationReportTestData.MeasurementRecordLength,
			wantErr:                 &ParsingError{Context: "parseMeasurementRecord(...)", Info: fmt.Sprintf("something went wrong while parsing measurement record. Measurement record bytes length is 3473 bytes, expected 3520 bytes")},
		},
		{
			name:                    "out_of_range_data",
			data:                    outOfRangeMeasurementRecordData,
			numberOfBlocks:          2,
			measurementRecordLength: 1,
			wantErr:                 &ParsingError{Context: "parseMeasurementRecord(...)", Info: OutOfRangeRuntimeError},
		},
		{
			name:                    "invalid_measurement_record_length",
			data:                    func() []byte { return make([]byte, 0) },
			numberOfBlocks:          testdata.RawGpuAttestationReportTestData.NumberOfBlocks,
			measurementRecordLength: testdata.RawGpuAttestationReportTestData.MeasurementRecordLength,
			wantErr:                 &IncorrectLengthError{Context: "measurement record", Expected: testdata.RawGpuAttestationReportTestData.MeasurementRecordLength, Actual: 0},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := parseMeasurementRecord(testcase.data(), testcase.numberOfBlocks, testcase.measurementRecordLength)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
		})
	}
}

func TestParseDmtfMeasurement(t *testing.T) {
	start := SpdmRequestSize + testdata.RawGpuAttestationReportTestData.MeasurementRecordOffset + MeasurementBlockIndexFieldSize + MeasurementBlockSpecificationFieldSize + MeasurementBlockSizeFieldSize
	testcases := []TestCase{
		{
			name:       "valid_dmtf_measurement",
			dataLength: testdata.RawGpuAttestationReportTestData.DmtfMeasurementLength,
			data:       testdata.RawGpuAttestationReportTestData.RawAttestationReport[start:],
			wantErr:    nil,
		},
		{
			name:       "invalid_dmtf_measurement_length",
			dataLength: testdata.RawGpuAttestationReportTestData.DmtfMeasurementLength,
			data:       make([]byte, 0),
			wantErr:    &IncorrectLengthError{Context: "dmtf measurement", Expected: 51, Actual: 0},
		},
		{
			name:       "parsing_error_in_dmtf_measurement",
			dataLength: 4,
			data:       []byte{1, 2, 0, 0},
			wantErr:    &ParsingError{Context: "parseDmtfMeasurement(...)", Info: OutOfRangeRuntimeError},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			dmtfMeasurement, parsedLength, err := parseDmtfMeasurement(testcase.data, testcase.dataLength)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
			if dmtfMeasurement != nil {
				if len(dmtfMeasurement.GetValueType()) != DmtfSpecMeasurementValueTypeFieldSize {
					t.Errorf("returned value type length: %d, want %d", len(dmtfMeasurement.GetValueType()), DmtfSpecMeasurementValueTypeFieldSize)
				}
				if len(dmtfMeasurement.GetValue()) != int(dmtfMeasurement.GetValueSize()) {
					t.Errorf("returned value length: %d, want %d", len(dmtfMeasurement.GetValue()), int(dmtfMeasurement.GetValueSize()))
				}
				if parsedLength != testcase.dataLength {
					t.Errorf("returned bytes covered: %d, want %d", parsedLength, testcase.dataLength)
				}
			}
		})
	}
}

func TestParseOpaqueData(t *testing.T) {
	testcases := []struct {
		name       string
		parser     opaqueDataParser
		data       []byte
		start      int
		dataLength int
		wantErr    error
	}{
		{
			name:       "valid_opaque_data_gpu",
			parser:     &gpuOpaqueDataParser{},
			data:       testdata.RawGpuAttestationReportTestData.RawAttestationReport,
			start:      SpdmRequestSize + testdata.RawGpuAttestationReportTestData.OpaqueDataOffset,
			dataLength: testdata.RawGpuAttestationReportTestData.OpaqueDataLength,
			wantErr:    nil,
		},
		{
			name:       "check_measurement_counts_gpu",
			parser:     &gpuOpaqueDataParser{},
			data:       []byte{12, 0, OpaqueDataMsrCountSize, 0, 0, 0, 0, 0},
			dataLength: 8,
			wantErr:    nil,
		},
		{
			name:       "check_switch_pdis_gpu",
			parser:     &gpuOpaqueDataParser{},
			data:       []byte{22, 0, OpaquePdiDataSizeFieldSize, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			dataLength: 12,
			wantErr:    nil,
		},
		{
			name:       "invalid_opaque_data_length_gpu",
			parser:     &gpuOpaqueDataParser{},
			data:       []byte{},
			dataLength: testdata.RawGpuAttestationReportTestData.OpaqueDataLength,
			wantErr:    &IncorrectLengthError{Context: "opaque data", Expected: testdata.RawGpuAttestationReportTestData.OpaqueDataLength, Actual: 0},
		},
		{
			name:       "parsing_error_in_opaque_data_gpu",
			parser:     &gpuOpaqueDataParser{},
			data:       []byte{1, 0, 2, 0},
			dataLength: 4,
			wantErr:    &ParsingError{Context: "parseOpaqueData(...)", Info: OutOfRangeRuntimeError},
		},
		{
			name:       "valid_opaque_data_switch",
			parser:     &switchOpaqueDataParser{},
			data:       testdata.RawSwitchAttestationReportTestData.RawAttestationReport,
			start:      SpdmRequestSize + testdata.RawSwitchAttestationReportTestData.OpaqueDataOffset,
			dataLength: testdata.RawSwitchAttestationReportTestData.OpaqueDataLength,
			wantErr:    nil,
		},
		{
			name:       "check_measurement_counts_switch",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{12, 0, OpaqueDataMsrCountSize, 0, 0, 0, 0, 1},
			dataLength: 8,
			wantErr:    nil,
		},
		{
			name:       "check_switch_gpu_pdis_switch",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{26, 0, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			dataLength: 69,
			wantErr:    nil,
		},
		{
			name:       "check_floorswept_ports_switch",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{23, 0, 1, 0, 0},
			dataLength: 5,
			wantErr:    nil,
		},
		{
			name:       "check_floorswept_ports_switch",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{23, 0, 1, 0, 0},
			dataLength: 5,
			wantErr:    nil,
		},
		{
			name:       "check_value_switch",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{1, 0, 1, 0, 0},
			dataLength: 5,
			wantErr:    nil,
		},
		{
			name:       "check_switch_gpu_pdis_error",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{26, 0, 1, 0, 0},
			dataLength: 5,
			wantErr:    &IncorrectLengthError{Context: "switch gpu pdis", Expected: OpaquePdiDataSizeFieldSize * TotalNumberOfPdis, Actual: 1},
		},
		{
			name:       "check_floorswept_ports_switch_error",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{23, 0, 0, 0},
			dataLength: 4,
			wantErr:    &ParsingError{Context: "parseFloorsweptPorts(...)", Info: "failed to parse hex string"},
		},
		{
			name:       "invalid_opaque_data_length_switch",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{},
			dataLength: testdata.RawSwitchAttestationReportTestData.OpaqueDataLength,
			wantErr:    &IncorrectLengthError{Context: "opaque data", Expected: testdata.RawSwitchAttestationReportTestData.OpaqueDataLength, Actual: 0},
		},
		{
			name:       "parsing_error_in_opaque_data_switch",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{1, 0, 2, 0},
			dataLength: 4,
			wantErr:    &ParsingError{Context: "parseOpaqueData(...)", Info: OutOfRangeRuntimeError},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			opaqueData, err := testcase.parser.ParseOpaqueData(testcase.data[testcase.start:], testcase.dataLength)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
			if opaqueData != nil {
				if len(opaqueData.GetOpaqueFieldData()) == 0 {
					t.Error("returned empty opaque field data")
				}
			}
		})
	}
}

func TestParseMeasurementCounts(t *testing.T) {
	testcases := []TestCase{
		{
			name:    "valid_measurement_counts",
			data:    make([]uint8, OpaqueDataMsrCountSize),
			wantErr: nil,
		},
		{
			name:    "invalid_measurement_counts_length",
			data:    make([]uint8, OpaqueDataMsrCountSize-1),
			wantErr: &InvalidSizeMeasurementCountsError{Expected: OpaqueDataMsrCountSize, Actual: OpaqueDataMsrCountSize - 1},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			msrCounts, err := parseMeasurementCounts(testcase.data)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
			if msrCounts != nil {
				if len(msrCounts.GetValues()) != 1 {
					t.Errorf("returned measurement counts: %d, want %d", len(msrCounts.GetValues()), 1)
				}
			}
		})
	}
}

func TestParseSwitchPdis(t *testing.T) {
	testcases := []TestCase{
		{
			name:    "valid_switch_pdis",
			data:    make([]uint8, OpaquePdiDataSizeFieldSize),
			wantErr: nil,
		},
		{
			name:    "invalid_switch_pdis_length",
			data:    make([]uint8, OpaquePdiDataSizeFieldSize-1),
			wantErr: &InvalidSizeSwitchPdisError{Expected: OpaquePdiDataSizeFieldSize, Actual: OpaquePdiDataSizeFieldSize - 1},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			gpuOpaqueDataParser := &gpuOpaqueDataParser{}
			switchPdis, err := gpuOpaqueDataParser.parseSwitchPdis(testcase.data)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
			if switchPdis != nil {
				if len(switchPdis.GetValues()[0]) != OpaquePdiDataSizeFieldSize {
					t.Errorf("returned switch pdis length: %d, want %d", len(switchPdis.GetValues()[0]), OpaquePdiDataSizeFieldSize)
				}
			}
		})
	}
}

func TestParseSwitchGpuPdis(t *testing.T) {
	const numberOfSwitchPorts = 8
	testcases := []TestCase{
		{
			name:    "valid_switch_gpu_pdis",
			data:    make([]uint8, OpaquePdiDataSizeFieldSize*TotalNumberOfPdis+numberOfSwitchPorts),
			wantErr: nil,
		},
		{
			name:    "invalid_switch_gpu_pdis_length",
			data:    make([]uint8, 0),
			wantErr: &IncorrectLengthError{Context: "switch gpu pdis", Expected: OpaquePdiDataSizeFieldSize * TotalNumberOfPdis, Actual: 0},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			switchOpaqueDataParser := &switchOpaqueDataParser{}
			switchTopology, err := switchOpaqueDataParser.parseSwitchGpuPdis(testcase.data)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
			if switchTopology != nil {
				if len(switchTopology.GetSwitchGpuPdis()) != TotalNumberOfPdis {
					t.Errorf("returned switch gpu pdis length: %d, want %d", len(switchTopology.GetSwitchGpuPdis()), TotalNumberOfPdis)
				}
				if len(switchTopology.GetSwitchGpuPdis()[0]) != OpaquePdiDataSizeFieldSize {
					t.Errorf("returned switch gpu pdis' value length: %d, want %d", len(switchTopology.GetSwitchGpuPdis()[0]), OpaquePdiDataSizeFieldSize)
				}
				if len(switchTopology.GetSwitchPorts()) != numberOfSwitchPorts {
					t.Errorf("returned switch ports length: %d, want %d", len(switchTopology.GetSwitchPorts()), numberOfSwitchPorts)
				}
				if len(switchTopology.GetSwitchPorts()[0]) != OpaquePortIDSizeFieldSize {
					t.Errorf("returned switch ports' value length: %d, want %d", len(switchTopology.GetSwitchPorts()[0]), OpaquePdiDataSizeFieldSize)
				}
			}
		})
	}
}

func TestParseFloorsweptPorts(t *testing.T) {
	const numberOfFloorsweptPorts = 2
	testcases := []TestCase{
		{
			name:    "valid_floorswept_ports",
			data:    make([]uint8, numberOfFloorsweptPorts),
			wantErr: nil,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			switchOpaqueDataParser := &switchOpaqueDataParser{}
			floorsweptPorts, _ := switchOpaqueDataParser.parseFloorsweptPorts(testcase.data)
			expected := []int32{0, 0, 0, 0}
			if diff := cmp.Diff(expected, floorsweptPorts.GetValues()); diff != "" {
				t.Errorf("returned floorsweptPorts values: %v, want %v (diff -want, +got): %v", floorsweptPorts, expected, diff)
			}
		})
	}
}

func TestParseSignature(t *testing.T) {
	testcases := []TestCase{
		{
			name:       "valid_signature",
			data:       make([]uint8, GpuAttestationReportSignatureFieldSize),
			dataLength: GpuAttestationReportSignatureFieldSize,
			wantErr:    nil,
		},
		{
			name:       "invalid_signature_length",
			data:       make([]byte, 0),
			dataLength: GpuAttestationReportSignatureFieldSize,
			wantErr:    &IncorrectLengthError{Context: "signature", Expected: GpuAttestationReportSignatureFieldSize, Actual: 0},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := parseSignature(testcase.data, testcase.dataLength)
			if diff := cmp.Diff(testcase.wantErr, err); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, testcase.wantErr, diff)
			}
		})
	}
}

func TestExtractOpaqueValue(t *testing.T) {
	tests := []struct {
		name                string
		opaqueFieldDataList []*pb.OpaqueFieldData
		dataType            pb.OpaqueDataType
		want                []byte
	}{
		{
			name: "DataTypePresent",
			opaqueFieldDataList: []*pb.OpaqueFieldData{
				{
					DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION,
					Data:     &pb.OpaqueFieldData_Value{Value: []byte("driver_val")},
				},
				{
					DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION,
					Data:     &pb.OpaqueFieldData_Value{Value: []byte("vbios_val")},
				},
			},
			dataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION,
			want:     []byte("vbios_val"),
		},
		{
			name: "DataTypeNotPresent",
			opaqueFieldDataList: []*pb.OpaqueFieldData{
				{
					DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION,
					Data:     &pb.OpaqueFieldData_Value{Value: []byte("driver_val")},
				},
			},
			dataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_GPU_INFO,
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractOpaqueValue(tc.opaqueFieldDataList, tc.dataType)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("ExtractOpaqueValue(%v, %v) = %v, want %v", tc.opaqueFieldDataList, tc.dataType, got, tc.want)
			}
		})
	}
}

func TestParseFeatureFlag(t *testing.T) {
	testcases := []struct {
		name              string
		attestationReport *pb.AttestationReport
		want              string
		wantErr           bool
	}{
		{
			name: "legacy_mode",
			attestationReport: &pb.AttestationReport{
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
					OpaqueData: &pb.OpaqueData{
						OpaqueFieldData: []*pb.OpaqueFieldData{},
					},
				},
			},
			want: LegacyMode,
		},
		{
			name: "spt_mode",
			attestationReport: &pb.AttestationReport{
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
					OpaqueData: &pb.OpaqueData{
						OpaqueFieldData: []*pb.OpaqueFieldData{
							{
								DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_FEATURE_FLAG,
								Data:     &pb.OpaqueFieldData_Value{Value: []byte{0}},
							},
						},
					},
				},
			},
			want: SPTMode,
		},
		{
			name: "mpt_mode",
			attestationReport: &pb.AttestationReport{
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
					OpaqueData: &pb.OpaqueData{
						OpaqueFieldData: []*pb.OpaqueFieldData{
							{
								DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_FEATURE_FLAG,
								Data:     &pb.OpaqueFieldData_Value{Value: []byte{1}},
							},
						},
					},
				},
			},
			want: MPTMode,
		},
		{
			name: "ppcie_mode",
			attestationReport: &pb.AttestationReport{
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
					OpaqueData: &pb.OpaqueData{
						OpaqueFieldData: []*pb.OpaqueFieldData{
							{
								DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_FEATURE_FLAG,
								Data:     &pb.OpaqueFieldData_Value{Value: []byte{2}},
							},
						},
					},
				},
			},
			want: PPCIEMode,
		},
		{
			name: "unknown_mode",
			attestationReport: &pb.AttestationReport{
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
					OpaqueData: &pb.OpaqueData{
						OpaqueFieldData: []*pb.OpaqueFieldData{
							{
								DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_FEATURE_FLAG,
								Data:     &pb.OpaqueFieldData_Value{Value: []byte{3}},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "flag_too_long",
			attestationReport: &pb.AttestationReport{
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
					OpaqueData: &pb.OpaqueData{
						OpaqueFieldData: []*pb.OpaqueFieldData{
							{
								DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_FEATURE_FLAG,
								Data:     &pb.OpaqueFieldData_Value{Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "mpt_mode_with_padding",
			attestationReport: &pb.AttestationReport{
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
					OpaqueData: &pb.OpaqueData{
						OpaqueFieldData: []*pb.OpaqueFieldData{
							{
								DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_FEATURE_FLAG,
								Data:     &pb.OpaqueFieldData_Value{Value: []byte{1, 0, 0, 0}},
							},
						},
					},
				},
			},
			want: MPTMode,
		},
		{
			name: "mpt_mode_8_bytes",
			attestationReport: &pb.AttestationReport{
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
					OpaqueData: &pb.OpaqueData{
						OpaqueFieldData: []*pb.OpaqueFieldData{
							{
								DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_FEATURE_FLAG,
								Data:     &pb.OpaqueFieldData_Value{Value: []byte{1, 0, 0, 0, 0, 0, 0, 0}},
							},
						},
					},
				},
			},
			want: MPTMode,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFeatureFlag(tc.attestationReport)
			if (err != nil) != tc.wantErr {
				t.Errorf("ParseFeatureFlag(%v) returned error: %v, wantErr: %t", tc.attestationReport, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("ParseFeatureFlag(%v) = %q, want: %q", tc.attestationReport, got, tc.want)
			}
		})
	}
}
