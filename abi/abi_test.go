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
	"encoding/binary"
	"encoding/hex"
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
			wantErr:          &IncorrectLengthError{Context: "spdm measurement response header", Expected: SpdmMeasurementResponseHeaderSize, Actual: 0},
		},
		{
			name:             "truncated_nonce_in_spdm_measurement_response_gpu",
			data:             testdata.RawGpuAttestationReportTestData.RawAttestationReport[SpdmRequestSize : SpdmRequestSize+testdata.RawGpuAttestationReportTestData.MeasurementRecordOffset+testdata.RawGpuAttestationReportTestData.MeasurementRecordLength+10],
			opaqueDataParser: &gpuOpaqueDataParser{},
			signatureLength:  GpuAttestationReportSignatureFieldSize,
			wantErr:          &IncorrectLengthError{Context: "nonce", Expected: NonceFieldSize, Actual: 10},
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
			wantErr:                 &IncorrectLengthError{Context: "measurement block header", Expected: MeasurementBlockHeaderSize, Actual: 1},
		},
		{
			name:                    "invalid_measurement_record_length",
			data:                    func() []byte { return make([]byte, 0) },
			numberOfBlocks:          testdata.RawGpuAttestationReportTestData.NumberOfBlocks,
			measurementRecordLength: testdata.RawGpuAttestationReportTestData.MeasurementRecordLength,
			wantErr:                 &IncorrectLengthError{Context: "measurement record", Expected: testdata.RawGpuAttestationReportTestData.MeasurementRecordLength, Actual: 0},
		},
		{
			name:                    "negative_measurement_record_length",
			data:                    func() []byte { return make([]byte, 10) },
			numberOfBlocks:          1,
			measurementRecordLength: -1,
			wantErr:                 &IncorrectLengthError{Context: "measurement record", Expected: -1, Actual: 10},
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
			name:       "negative_dmtf_measurement_length",
			dataLength: -1,
			data:       []byte{1, 2, 0, 0},
			wantErr:    &IncorrectLengthError{Context: "dmtf measurement", Expected: -1, Actual: 4},
		},
		{
			name:       "parsing_error_in_dmtf_measurement",
			dataLength: 4,
			data:       []byte{1, 2, 0, 0},
			wantErr:    &IncorrectLengthError{Context: "dmtf measurement value", Expected: 2, Actual: 1},
		},
		{
			name:       "truncated_header_in_dmtf_measurement",
			dataLength: 2,
			data:       []byte{1, 2},
			wantErr:    &IncorrectLengthError{Context: "dmtf measurement header", Expected: DmtfMeasurementHeaderSize, Actual: 2},
		},
		{
			name:       "trailing_slack_bytes_in_dmtf_measurement",
			dataLength: 10,
			data:       []byte{1, 1, 0, 0xaa, 0, 0, 0, 0, 0, 0},
			wantErr:    &ParsingError{Context: "parseDmtfMeasurement(...)", Info: "something went wrong while parsing dmtf measurement. DMTF measurement bytes length is 4 bytes, expected 10 bytes"},
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
			wantErr:    &IncorrectLengthError{Context: "opaque field value", Expected: 2, Actual: 0},
		},
		{
			name:       "truncated_header_in_opaque_data_gpu",
			parser:     &gpuOpaqueDataParser{},
			data:       []byte{1, 0, 2},
			dataLength: 3,
			wantErr:    &IncorrectLengthError{Context: "opaque field header", Expected: OpaqueDataHeaderSize, Actual: 3},
		},
		{
			name:       "negative_opaque_data_length_gpu",
			parser:     &gpuOpaqueDataParser{},
			data:       []byte{1, 0, 2, 0},
			dataLength: -1,
			wantErr:    &IncorrectLengthError{Context: "opaque data", Expected: -1, Actual: 4},
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
			wantErr:    &IncorrectLengthError{Context: "opaque field value", Expected: 2, Actual: 0},
		},
		{
			name:       "truncated_header_in_opaque_data_switch",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{1, 0, 2},
			dataLength: 3,
			wantErr:    &IncorrectLengthError{Context: "opaque field header", Expected: OpaqueDataHeaderSize, Actual: 3},
		},
		{
			name:       "negative_opaque_data_length_switch",
			parser:     &switchOpaqueDataParser{},
			data:       []byte{1, 0, 2, 0},
			dataLength: -1,
			wantErr:    &IncorrectLengthError{Context: "opaque data", Expected: -1, Actual: 4},
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
		{
			name:       "negative_signature_length",
			data:       make([]byte, 10),
			dataLength: -1,
			wantErr:    &IncorrectLengthError{Context: "signature", Expected: -1, Actual: 10},
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

func makeNvdaodHeader(profile uint16, major, minor uint8) []byte {
	hdr := make([]byte, NvdaodHeaderSize)
	copy(hdr[:OpaqueDataHeaderMagicSize], OpaqueDataHeaderMagic)
	binary.LittleEndian.PutUint16(hdr[NvdaodHeaderProfileOffset:NvdaodHeaderProfileOffset+2], profile)
	hdr[NvdaodHeaderMajorOffset] = major
	hdr[NvdaodHeaderMinorOffset] = minor
	return hdr
}

func makeTypedTLV(dataType, valueType uint16, payload []byte) []byte {
	buf := make([]byte, TypedOpaqueDataHeaderSize+len(payload))
	binary.LittleEndian.PutUint16(buf[0:2], dataType)
	binary.LittleEndian.PutUint16(buf[2:4], valueType)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(payload)))
	copy(buf[6:], payload)
	return buf
}

func makeLegacyTLV(dataType uint16, payload []byte) []byte {
	buf := make([]byte, OpaqueDataHeaderSize+len(payload))
	binary.LittleEndian.PutUint16(buf[0:2], dataType)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(payload)))
	copy(buf[4:], payload)
	return buf
}

func TestParseOpaqueDataNvdaodHeaderAndVersioning(t *testing.T) {
	parser := &gpuOpaqueDataParser{}

	t.Run("valid_nvdaod_with_known_and_unknown_typed_fields", func(t *testing.T) {
		var blob []byte
		blob = append(blob, makeNvdaodHeader(0, 2, 0)...)
		blob = append(blob, makeTypedTLV(3, 0x0086, []byte("620.12\x00"))...)
		blob = append(blob, makeTypedTLV(37, MinSvnOpaqueValueType, []byte{0x03, 0x00})...)
		// Legacy field 34 with value > 2 is ignored when NVDAOD header is present.
		blob = append(blob, makeTypedTLV(34, 0x0086, []byte{0x99, 0x00})...)

		od, err := parser.ParseOpaqueData(blob, len(blob))
		if err != nil {
			t.Fatalf("ParseOpaqueData() unexpected error: %v", err)
		}
		if !od.GetFormatVersion().GetHasHeader() || od.GetFormatVersion().GetMajor() != 2 || od.GetFormatVersion().GetMinor() != 0 {
			t.Errorf("FormatVersion = %+v, want {Major:2 Minor:0 HasHeader:true}", od.GetFormatVersion())
		}
		if len(od.GetOpaqueFieldData()) != 3 {
			t.Fatalf("len(OpaqueFieldData) = %d, want 3", len(od.GetOpaqueFieldData()))
		}

		driverField := od.GetOpaqueFieldData()[0]
		if driverField.GetDataType() != pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION || driverField.GetRawDataType() != 3 || driverField.GetValueType() != 0x0086 {
			t.Errorf("driverField = %+v, want DataType=DRIVER_VERSION, RawDataType=3, ValueType=0x86", driverField)
		}

		unknownField := od.GetOpaqueFieldData()[1]
		if unknownField.GetDataType() != pb.OpaqueDataType_OPAQUE_FIELD_ID_UNSPECIFIED || unknownField.GetRawDataType() != 37 || unknownField.GetValueType() != MinSvnOpaqueValueType || !bytes.Equal(unknownField.GetValue(), []byte{0x03, 0x00}) {
			t.Errorf("unknownField = %+v, want DataType=UNSPECIFIED, RawDataType=37, ValueType=0x87, Value=[3 0]", unknownField)
		}
	})

	t.Run("nvdaod_unsupported_profile", func(t *testing.T) {
		blob := makeNvdaodHeader(1, 2, 0)
		_, err := parser.ParseOpaqueData(blob, len(blob))
		wantErr := &UnsupportedOpaqueDataProfileError{Profile: 1}
		if diff := cmp.Diff(wantErr, err); diff != "" {
			t.Errorf("ParseOpaqueData() error diff (-want +got): %s", diff)
		}
	})

	t.Run("nvdaod_unsupported_major_version", func(t *testing.T) {
		blob := makeNvdaodHeader(0, 3, 0)
		_, err := parser.ParseOpaqueData(blob, len(blob))
		wantErr := &UnsupportedOpaqueDataVersionError{Version: 3, Max: MaxOpaqueDataVersion}
		if diff := cmp.Diff(wantErr, err); diff != "" {
			t.Errorf("ParseOpaqueData() error diff (-want +got): %s", diff)
		}
	})

	t.Run("nvdaod_truncated_typed_tlv_header", func(t *testing.T) {
		blob := append(makeNvdaodHeader(0, 2, 0), 0x03, 0x00, 0x86, 0x00)
		_, err := parser.ParseOpaqueData(blob, len(blob))
		wantErr := &IncorrectLengthError{Context: "opaque field header", Expected: TypedOpaqueDataHeaderSize, Actual: 4}
		if diff := cmp.Diff(wantErr, err); diff != "" {
			t.Errorf("ParseOpaqueData() error diff (-want +got): %s", diff)
		}
	})

	t.Run("legacy_version_within_bounds", func(t *testing.T) {
		blob := makeLegacyTLV(34, []byte{0x02, 0x00})
		od, err := parser.ParseOpaqueData(blob, len(blob))
		if err != nil {
			t.Fatalf("ParseOpaqueData() unexpected error: %v", err)
		}
		if od.GetFormatVersion().GetHasHeader() || od.GetFormatVersion().GetMajor() != 0 {
			t.Errorf("FormatVersion = %+v, want HasHeader=false, Major=0", od.GetFormatVersion())
		}
	})

	t.Run("legacy_unsupported_version", func(t *testing.T) {
		blob := makeLegacyTLV(34, []byte{0x03, 0x00})
		_, err := parser.ParseOpaqueData(blob, len(blob))
		wantErr := &UnsupportedOpaqueDataVersionError{Version: 3, Max: MaxOpaqueDataVersion}
		if diff := cmp.Diff(wantErr, err); diff != "" {
			t.Errorf("ParseOpaqueData() error diff (-want +got): %s", diff)
		}
	})

	t.Run("legacy_version_too_long", func(t *testing.T) {
		blob := makeLegacyTLV(34, make([]byte, MaxOpaqueDataVersionSize+1))
		_, err := parser.ParseOpaqueData(blob, len(blob))
		wantErr := &IncorrectLengthError{Context: "opaque data version", Expected: MaxOpaqueDataVersionSize, Actual: MaxOpaqueDataVersionSize + 1}
		if diff := cmp.Diff(wantErr, err); diff != "" {
			t.Errorf("ParseOpaqueData() error diff (-want +got): %s", diff)
		}
	})
}

func TestExtractOpaqueFieldByRawType(t *testing.T) {
	fields := []*pb.OpaqueFieldData{
		{
			DataType:    pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION,
			RawDataType: 3,
			ValueType:   0x0086,
			Data:        &pb.OpaqueFieldData_Value{Value: []byte("620.12")},
		},
		{
			DataType:    pb.OpaqueDataType_OPAQUE_FIELD_ID_UNSPECIFIED,
			RawDataType: 37,
			ValueType:   MinSvnOpaqueValueType,
			Data:        &pb.OpaqueFieldData_Value{Value: []byte{0x05, 0x00}},
		},
		{
			// Manually constructed proto without RawDataType set.
			DataType:  pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION,
			ValueType: MinSvnOpaqueValueType,
			Data:      &pb.OpaqueFieldData_Value{Value: []byte{0x01, 0x00}},
		},
	}

	if got := ExtractOpaqueFieldByRawType(fields, 37); got == nil || !bytes.Equal(got.GetValue(), []byte{0x05, 0x00}) {
		t.Errorf("ExtractOpaqueFieldByRawType(fields, 37) = %v, want [5 0]", got)
	}
	if got := ExtractOpaqueFieldByRawType(fields, 6); got == nil || !bytes.Equal(got.GetValue(), []byte{0x01, 0x00}) {
		t.Errorf("ExtractOpaqueFieldByRawType(fields, 6) = %v, want fallback match [1 0]", got)
	}
	if got := ExtractOpaqueFieldByRawType(fields, 0); got != nil {
		t.Errorf("ExtractOpaqueFieldByRawType(fields, 0) = %v, want nil", got)
	}
	if got := ExtractOpaqueFieldByRawType(fields, 999); got != nil {
		t.Errorf("ExtractOpaqueFieldByRawType(fields, 999) = %v, want nil", got)
	}
}

const sampleNvdaodTranscriptHex = "11e001ff50e4490df1dadcc80d42038cfc91c023f55f1cd914e540641bf770d7bdfe6f4e001160000040c00d000101330001300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002013300013000809853e3249d26c76731f03adeabe846759a2dcc57750a9ebcb534f769399af767600dec181e28d79e7e017a331efcf403013300013000fc7f1e4283b053619b26f482c976765a22acf1ae75e7e46dce015247f26feb962b35a113a71c23adbb05b98fb02852a104013300013000095a396a0cc01df830ccedbb9ac7dbd8d6087824c7db7e05d34a97850600d34cc016c856bd9c7968cf6a057d4356764e05013300013000568b89291a34cece03b12aaa352d9afe273610307525b8443e90faa78d82ecfa9c7827d8f7915c35b2fab972e1086686060133000130009ddef3ff55eede4825cf8580a04202eb1bee8e90330ab15e3c94f764a74b5ff8b4160e8c90e681e7e40eb04fb798335c070133000130006850b0a82e7e77c0f51e0e6732163866003390c4eb286d8dfb26a72f711a9c8bcdf402a1fd4e5d70b97708107a785efc08013300013000ffc021cd1d8fa643485ca1bbaffc050c31ecf2469bfa3d07284d131872cf6d82fb6ede30f5c1ed2a329a74de83f67fd9090133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0133000130005ef8d0c61bfed5bfab4d117546d61276d58059cbb3a47955a9e79f4c73059c959cef8f75fe79870d810c154680cf6c6d0b0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c013300013000fdebad1a8cdc90a722cfaffe22029e610201e938d2a08df2e5f722e34074f4b13ed466cd91f1af7c468a4b8df43845fc0d013300013000e9bec0ccddde61f522f51f046d85302f4df5ec488e1df29099192b1d73612f6f0f6a6e07b8993688fc131826d3a6d3d70e0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f013300013000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001101330001300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012013300013000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000130133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001401330001300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000015013300013000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000160133000130002a5d7ce6d067d309d52c1bcbdc81e2be5cd1433174cdcee55bfe9d03eb7092ff599a90b4eb10062436a604f57cb61af8170133000130002574a2cb261858249ebead0e795dacc8f2e56b3cdba230b88cc4abdeec7413e0ad75f042ee455f8fb9e3014c1c6b5c0a18013300013000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000190133000130005a498c5634a37a3d6bdbcbb678b09a1297998d10a375be87564af6494e484d945e9f08309c8f6b3ae0548246bf65b7081a0133000130005c114a2cd3e73cc7cb75331abab894f2229d29da586c979ef513c1019e13dad1ac22865650586d16431727bc66b0ac831b01330001300017d95fcfa05c225a1c648d13afc4c52c4db4a8430b1770b46c6607625f516c11be0718d8a6c2753c219621b95616116f1c0133000130008de30518623c966397aae9dd2366b09bcaf3b4eb95596b5e9c3bca82cb1efe8ec711af16e42b18ce249da0913e33de851d0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e013300013000b268070c2086375840568bbbe528f2ff8e8a65d7e261a0cf67736cbaebef7384a68df787a103f986b882bf308249de051f013300013000a067105abf97dbb51932544b339f57a49ad8d8bd64c25626b4287b980e539b52fa164a41cf99556fbe9ee0ceec1cfaa120013300013000ba8bdbd5a0e83ddc997b62250d83af216c238544d94813d11778f7fede0869a4f28d3391517270f917554ca2c991941e21013300013000f6e3d813139ed1cbc32434dc6da668b2b47feb3043497e4b38333fe648ecfee4ae799f4ac38bf5ea5c7f0a245501205022013300013000198b81d9c0cefe0b33ad65de3fad238a5461d8ee32487bf70fc1926041408cb114624b8ca6b0d5fc97028b58d9cdb78d230133000130006bf52664076c0c0d519658fa0729510b72cf6279f76308c100bc433affbd70eb0f9554302e44947919ba730dfe08fd5e240133000130005af2810f7de5e1f8573ff70f7b6caf2eeeca9bc4920fbd97915d8ab34944de10aed02d6678762f09bffacf60cf0b3b922501330001300057fd92f25e125f93492ca6953dfbda253711c8eb95787bea73bd5fc1606771792a8721cb18138df7901eb0f0efe9ac7d260133000130004670da4690cd3603fe3252e72b16a24edd0bf3b8303b9a1b8d42800890a088dd01931ee3718a20205ba9ef2d8f4a1df927013300013000c7ea135dca389918789454861bb593095dc44f8ad39035665daa81fa02cf6fbd3a18227b6224dced70288b9fd3161cc028013300013000be2f33751351abc52b7b59ca0d74ec2e71ac64ce5534a6b1ed078a8c49bf4daec2c138ea9c7685a030c2f5aeddf32e172901330001300084fbfa0dee8a081c203bb4c57383cc7c55a6f052fbf98b2b59af0280c45603e087252d2487dc53edb5d971c2d80636e62a013300013000df68b2277af4baa8df1462a114854d3a9e435a437710a2869ae53dc43e049d6b37f81cef9939f2b72548b56352063e5d2b0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002c0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002d0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002f013300013000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003101330001300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032013300013000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000330133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003401330001300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000035013300013000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000360133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003701330001300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000038013300013000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000390133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003b0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003d0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e0133000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003f01330001300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040013300013000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c94956ea55a1151b7bb561b8c859a1e53458baf963323fb1823b2f911e5b1bf6e3014e5644414f4400000200000006008600080000d900960f0000000e0082000400350400000f008200090038383400000000000010008200050030000000001100820005004735323000120082000500303230310013008200020000000300860007003632302e31320004008200080080010000000000000c0084000001000000000100000004000000010000000100000001000000010000000100000000000000010000000000000083000000030000000000000000000000000000000000000000000000000000000000000000000000010000000200000000000000010000000100000001000000010000000000000001000000010000000100000001000000010000000200000001000000010000000100000001000000010000000100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d008300040000c001000b0082000100aa25008700020000001400010030000d7cde10dab1dd6dea10fed9a4a5e833111f8bf80104b557e51c9987f996b5f76a6c57969dbf080c10a36f69029b5d1615008500010055220086000200000224008500020000001f5ce3acaace4e7a96081a4756920e58d92096b8170db20513fdd78703306929031a42fcac2c802e7e0e6dcf049b5c56b50c2d2e17a038fdf30f45e345e30d34eb9162c28e8b991bee09f5b6e99ad0674ef75bcd63c2dda7b69e724f2f4db136"

func TestRawAttestationReportToProtoNvdaodTranscript(t *testing.T) {
	rawBytes, err := hex.DecodeString(sampleNvdaodTranscriptHex)
	if err != nil {
		t.Fatalf("hex.DecodeString failed: %v", err)
	}

	report, err := RawAttestationReportToProto(rawBytes, GPU)
	if err != nil {
		t.Fatalf("RawAttestationReportToProto() unexpected error: %v", err)
	}

	od := report.GetSpdmMeasurementResponse().GetOpaqueData()
	if !od.GetFormatVersion().GetHasHeader() || od.GetFormatVersion().GetMajor() != 2 || od.GetFormatVersion().GetMinor() != 0 {
		t.Errorf("FormatVersion = %+v, want {Major:2 Minor:0 HasHeader:true}", od.GetFormatVersion())
	}

	fields := od.GetOpaqueFieldData()
	if len(fields) != 17 {
		t.Fatalf("len(OpaqueFieldData) = %d, want 17", len(fields))
	}

	driverVer := ExtractOpaqueValue(fields, pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION)
	if !bytes.Equal(driverVer, []byte("620.12\x00")) {
		t.Errorf("driver version = %q, want \"620.12\\x00\"", driverVer)
	}

	fspSvn := ExtractOpaqueFieldByRawType(fields, 37)
	if fspSvn == nil || fspSvn.GetValueType() != MinSvnOpaqueValueType || !bytes.Equal(fspSvn.GetValue(), []byte{0x00, 0x00}) {
		t.Errorf("FSP_UCODE_SVN (type 37) = %+v, want ValueType=0x87, Value=[0 0]", fspSvn)
	}

	mode, err := ParseFeatureFlag(report)
	if err != nil || mode != SPTMode {
		t.Errorf("ParseFeatureFlag() = %q, %v; want %q, nil", mode, err, SPTMode)
	}
}
