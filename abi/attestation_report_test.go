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
	"encoding/binary"
	"testing"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/testing/testdata"
)

const (
	// responseHeaderSize is the size of the fixed SPDM measurement response
	// header preceding the measurement record.
	responseHeaderSize = SpdmVersionFieldSize + RequestResponseCodeFieldSize + Param1FieldSize + Param2FieldSize + NumberOfBlocksFieldSize + MeasurementRecordLengthFieldSize
	// blockHeaderSize is the size of the fixed header preceding each
	// measurement block's payload.
	blockHeaderSize = MeasurementBlockIndexFieldSize + MeasurementBlockSpecificationFieldSize + MeasurementBlockSizeFieldSize
	// signatureSize is the signature length, which is the same for GPU and
	// switch reports.
	signatureSize = GpuAttestationReportSignatureFieldSize
)

// Offsets of the block count and record length fields within the response
// header.
const (
	numberOfBlocksOffset          = SpdmVersionFieldSize + RequestResponseCodeFieldSize + Param1FieldSize + Param2FieldSize
	measurementRecordLengthOffset = numberOfBlocksOffset + NumberOfBlocksFieldSize
)

// fixtureFor maps a fuzz input's type selector to the attestation type and
// known-good report used to frame it.
func fixtureFor(isSwitch bool) (AttestationType, testdata.RawAttestationReportTestData) {
	if isSwitch {
		return SWITCH, testdata.RawSwitchAttestationReportTestData
	}
	return GPU, testdata.RawGpuAttestationReportTestData
}

// The helpers below read framing values from the raw report bytes rather than
// the testdata metadata, which is not kept in sync with the raw reports.

// numberOfBlocksFrom returns the measurement block count encoded in a
// known-good report's response header.
func numberOfBlocksFrom(td testdata.RawAttestationReportTestData) uint8 {
	return td.RawAttestationReport[SpdmRequestSize+numberOfBlocksOffset]
}

// measurementRecordFrom returns the raw measurement record bytes of a known-good
// report, using the length encoded in the report's own response header.
func measurementRecordFrom(td testdata.RawAttestationReportTestData) []byte {
	resp := td.RawAttestationReport[SpdmRequestSize:]
	lenOff := measurementRecordLengthOffset
	mrLen := int(binary.LittleEndian.Uint32([]byte{resp[lenOff], resp[lenOff+1], resp[lenOff+2], 0}))
	return resp[responseHeaderSize : responseHeaderSize+mrLen]
}

// opaqueDataFrom returns the raw opaque data bytes of a known-good report,
// using the length encoded in the report's own opaque length field.
func opaqueDataFrom(td testdata.RawAttestationReportTestData) []byte {
	resp := td.RawAttestationReport[SpdmRequestSize:]
	lenOff := responseHeaderSize + len(measurementRecordFrom(td)) + NonceFieldSize
	opLen := int(binary.LittleEndian.Uint16(resp[lenOff : lenOff+OpaqueLengthFieldSize]))
	start := lenOff + OpaqueLengthFieldSize
	return resp[start : start+opLen]
}

// firstMeasurementBlocks returns the prefix of record holding its first n
// measurement blocks. Small seeds keep fuzz minimization cheap while still
// exercising every per-block parsing path.
func firstMeasurementBlocks(record []byte, n int) []byte {
	offset := 0
	for i := 0; i < n; i++ {
		sizeOff := offset + MeasurementBlockIndexFieldSize + MeasurementBlockSpecificationFieldSize
		size := int(binary.LittleEndian.Uint16(record[sizeOff : sizeOff+MeasurementBlockSizeFieldSize]))
		offset += blockHeaderSize + size
	}
	return record[:offset]
}

// buildAttestationReport frames the given measurement record and opaque data in
// a syntactically valid attestation report so that fuzz inputs reach the inner
// parsers instead of being rejected by the outer length checks.
func buildAttestationReport(numberOfBlocks uint8, measurementRecord, opaqueData []byte) []byte {
	report := make([]byte, 0, SpdmRequestSize+responseHeaderSize+len(measurementRecord)+NonceFieldSize+OpaqueLengthFieldSize+len(opaqueData)+signatureSize)
	report = append(report, make([]byte, SpdmRequestSize)...)
	report = append(report, 0x11, 0x60, 0x00, 0x00) // version, response code, param1, param2
	report = append(report, numberOfBlocks)
	var mrLen [4]byte
	binary.LittleEndian.PutUint32(mrLen[:], uint32(len(measurementRecord)))
	report = append(report, mrLen[:MeasurementRecordLengthFieldSize]...)
	report = append(report, measurementRecord...)
	report = append(report, make([]byte, NonceFieldSize)...)
	var opLen [OpaqueLengthFieldSize]byte
	binary.LittleEndian.PutUint16(opLen[:], uint16(len(opaqueData)))
	report = append(report, opLen[:]...)
	report = append(report, opaqueData...)
	report = append(report, make([]byte, signatureSize)...)
	return report
}

// checkReport verifies the result contract of RawAttestationReportToProto.
func checkReport(t *testing.T, at AttestationType, report *pb.AttestationReport, err error) {
	t.Helper()
	if err != nil {
		if report != nil {
			t.Errorf("RawAttestationReportToProto(%v) returned non-nil report on error: %v", at, err)
		}
		return
	}
	if report == nil {
		t.Fatalf("RawAttestationReportToProto(%v) returned nil report without error", at)
	}
	if report.GetSpdmMeasurementRequest() == nil {
		t.Errorf("RawAttestationReportToProto(%v) report missing SpdmMeasurementRequest", at)
	}
	resp := report.GetSpdmMeasurementResponse()
	if resp == nil {
		t.Fatalf("RawAttestationReportToProto(%v) report missing SpdmMeasurementResponse", at)
	}
	if got, want := len(resp.GetSignature()), signatureSize; got != want {
		t.Errorf("RawAttestationReportToProto(%v) signature length = %d, want %d", at, got, want)
	}
}

// FuzzRawAttestationReportToProto feeds unstructured bytes to the parser to
// exercise the request header, response header, and outer framing checks.
func FuzzRawAttestationReportToProto(f *testing.F) {
	for _, isSwitch := range []bool{false, true} {
		_, td := fixtureFor(isSwitch)
		f.Add(isSwitch, td.RawAttestationReport)
		f.Add(isSwitch, td.RawAttestationReport[:SpdmRequestSize])
		f.Add(isSwitch, td.RawAttestationReport[:SpdmRequestSize+responseHeaderSize])
	}
	f.Add(false, []byte{})

	f.Fuzz(func(t *testing.T, isSwitch bool, data []byte) {
		at, _ := fixtureFor(isSwitch)
		report, err := RawAttestationReportToProto(data, at)
		checkReport(t, at, report, err)
	})
}

// FuzzParseMeasurementRecord frames the input as the measurement record of an
// otherwise valid report so that mutations reach the measurement block and
// DMTF measurement parsers.
func FuzzParseMeasurementRecord(f *testing.F) {
	for _, isSwitch := range []bool{false, true} {
		_, td := fixtureFor(isSwitch)
		record := measurementRecordFrom(td)
		f.Add(isSwitch, uint8(1), firstMeasurementBlocks(record, 1))
		f.Add(isSwitch, uint8(3), firstMeasurementBlocks(record, 3))
	}
	f.Add(false, uint8(0), []byte{})
	f.Add(false, uint8(1), []byte{0, DmtfMeasurementSpecificationValue, 3, 0, 1, 0, 0})

	f.Fuzz(func(t *testing.T, isSwitch bool, numberOfBlocks uint8, record []byte) {
		at, td := fixtureFor(isSwitch)
		if len(record) > 0xffffff {
			record = record[:0xffffff]
		}
		data := buildAttestationReport(numberOfBlocks, record, opaqueDataFrom(td))
		report, err := RawAttestationReportToProto(data, at)
		checkReport(t, at, report, err)
	})
}

// FuzzParseOpaqueData frames the input as the opaque data of an otherwise
// valid report so that mutations reach the GPU and Switch opaque TLV parsers.
func FuzzParseOpaqueData(f *testing.F) {
	f.Add(false, opaqueDataFrom(testdata.RawGpuAttestationReportTestData))
	f.Add(true, opaqueDataFrom(testdata.RawSwitchAttestationReportTestData))
	f.Add(false, []byte{})
	f.Add(true, []byte{})
	// A single zero-length field of an unknown type.
	f.Add(false, []byte{0xff, 0xff, 0, 0})
	// GPU feature flag fields selecting each mode, and an unknown value.
	f.Add(false, []byte{36, 0, 1, 0, 0})
	f.Add(false, []byte{36, 0, 1, 0, 1})
	f.Add(false, []byte{36, 0, 1, 0, 2})
	f.Add(false, []byte{36, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0x80})
	// Well-formed and misaligned values for each size-validated field type.
	f.Add(false, []byte{12, 0, 4, 0, 1, 2, 3, 4})                   // GPU MSRSCNT
	f.Add(false, []byte{12, 0, 3, 0, 1, 2, 3})                      // GPU MSRSCNT, size % 4 != 0
	f.Add(false, []byte{22, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8})       // GPU SWITCH_PDI
	f.Add(false, []byte{22, 0, 7, 0, 1, 2, 3, 4, 5, 6, 7})          // GPU SWITCH_PDI, size % 8 != 0
	f.Add(true, append([]byte{26, 0, 64, 0}, make([]byte, 64)...))  // Switch SWITCH_GPU_PDIS
	f.Add(true, append([]byte{26, 0, 63, 0}, make([]byte, 63)...))  // Switch SWITCH_GPU_PDIS, too short
	f.Add(true, []byte{23, 0, 0, 0})                                // Switch DISABLED_PORTS, empty
	f.Add(true, append([]byte{23, 0, 9, 0, 1}, make([]byte, 8)...)) // Switch DISABLED_PORTS, overflows uint64

	f.Fuzz(func(t *testing.T, isSwitch bool, opaque []byte) {
		at, td := fixtureFor(isSwitch)
		if len(opaque) > 0xffff {
			opaque = opaque[:0xffff]
		}
		data := buildAttestationReport(numberOfBlocksFrom(td), measurementRecordFrom(td), opaque)
		report, err := RawAttestationReportToProto(data, at)
		checkReport(t, at, report, err)
	})
}
