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

// Package testdata defines sample responses of the collaterals
package testdata

import (
	"embed"
	"encoding/base64"
	"encoding/hex"

	"log"
	"golang.org/x/crypto/ocsp"
)

//go:embed "test_raw_gpu_attestation_report.dat"
var rawGpuAttestationReport []byte

//go:embed "test_raw_switch_attestation_report.dat"
var rawSwitchAttestationReport []byte

// GpuAttestationCertificateChain contains the GPU attestation certificate chain.
//
//go:embed "test_gpu_attestation_certificate_chain.dat"
var GpuAttestationCertificateChain []byte

// SwitchAttestationCertificateChain contains the Switch attestation certificate chain.
//
//go:embed "test_switch_attestation_certificate_chain.dat"
var SwitchAttestationCertificateChain []byte

// TestValidRootCert contains the valid root certificate for unit testing verifyXmlSignature functionality for RIM. This data is test data obtained from goxmldsig library.
//
//go:embed rim/test_valid_root_cert.dat
var TestValidRootCert []byte

//go:embed rim/*.xml
var xmlFiles embed.FS

// The OCSP responses below correspond to certificates in certificate chains.
// Certificate chains are ordered Leaf->Issuer->...->Root.
// GpuAttestationCertificateChain has 5 certificates (indices 0-4), L5(Leaf) to L1(Root).
// RIM certificate chains have 4 certificates (indices 0-3), L4(Leaf) to L1(Root).
// OCSP is checked for all certs except root.

// testGpuOcspResponseCertL4 contains OCSP response for certificate
// at index 1 (L4) in GpuAttestationCertificateChain.
//
//go:embed ocsp/test_gpu_certificate_l4_base64encoded_ocsp_response.dat
var testGpuOcspResponseCertL4 string

// testGpuOcspResponseCertL3 contains OCSP response for certificate
// at index 2 (L3) in GpuAttestationCertificateChain.
//
//go:embed ocsp/test_gpu_certificate_l3_base64encoded_ocsp_response.dat
var testGpuOcspResponseCertL3 string

// testGpuOcspResponseCertL2 contains OCSP response for certificate
// at index 3 (L2) in GpuAttestationCertificateChain.
//
//go:embed ocsp/test_gpu_certificate_l2_base64encoded_ocsp_response.dat
var testGpuOcspResponseCertL2 string

// For RIM certs, Driver and VBIOS RIMs share intermediate certificates
// L2 and L3 at indices 1 and 2 of their 4-cert chains but leaf cert L4 at index 0 is unique.
// See rim/NV_GPU_DRIVER_GH100_550.90.07.xml and rim/NV_GPU_VBIOS_1010_0200_882_96009F0001.xml.

// testDriverRimOcspResponseCertL4 contains OCSP response for certificate
// at index 0 (L4) in Driver RIM certificate chain.
//
//go:embed ocsp/test_gpu_driver_rim_l4_base64encoded_ocsp_response.dat
var testDriverRimOcspResponseCertL4 string

// testVbiosRimOcspResponseCertL4 contains OCSP response for certificate
// at index 0 (L4) in VBIOS RIM certificate chain.
//
//go:embed ocsp/test_gpu_vbios_l4_base64encoded_ocsp_response.dat
var testVbiosRimOcspResponseCertL4 string

// testRimOcspResponseCertL3 contains OCSP response for certificate
// at index 1 (L3) in RIM certificate chains (shared between Driver and VBIOS).
//
//go:embed ocsp/test_gpu_driver_rim_l3_base64encoded_ocsp_response.dat
var testRimOcspResponseCertL3 string

// testRimOcspResponseCertL2 contains OCSP response for certificate
// at index 2 (L2) in RIM certificate chains (shared between Driver and VBIOS).
//
//go:embed ocsp/test_gpu_rim_l2_base64encoded_ocsp_response.dat
var testRimOcspResponseCertL2 string

// Nonce defines a nonce example that is all zeros except the last byte is 1.
var Nonce = [32]byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 1}

// RawAttestationReportTestData contains the raw attestation report data required for testing.
type RawAttestationReportTestData struct {
	// RawAttestationReport contains the raw GPU/Switch attestation report data.
	RawAttestationReport []byte

	// NumberOfBlocks is the number of blocks in the measurement record.
	NumberOfBlocks int

	// MeasurementRecordOffset is the offset of a measurement record in a SPDM measurement response.
	MeasurementRecordOffset int

	// MeasurementRecordLength is the length of a measurement record.
	MeasurementRecordLength int

	// DmtfMeasurementLength is the length of a DMTF measurement.
	DmtfMeasurementLength int

	// OpaqueDataOffset is the offset of the opaque data in a SPDM measurement response.
	OpaqueDataOffset int

	// OpaqueDataLength is the length of the opaque data in a SPDM measurement response.
	OpaqueDataLength int

	// SpdmMeasurementResponseDataLength is the length of the SPDM measurement response data.
	SpdmMeasurementResponseDataLength int

	// Nonce is the nonce in the attestation report.
	Nonce []byte

	// DriverVersion is the driver version in the attestation report.
	DriverVersion string

	// VBiosVersion is the vbios version in the attestation report.
	VBiosVersion string
}

// RawGpuAttestationReportTestData contains the raw GPU attestation report data required for testing.
var RawGpuAttestationReportTestData = RawAttestationReportTestData{
	RawAttestationReport:              rawGpuAttestationReport,
	NumberOfBlocks:                    64,
	MeasurementRecordOffset:           8,
	MeasurementRecordLength:           3520,
	DmtfMeasurementLength:             51,
	OpaqueDataOffset:                  3562,
	OpaqueDataLength:                  422,
	SpdmMeasurementResponseDataLength: 4080,
	Nonce:                             decodeHexString("931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"),
	DriverVersion:                     SPTGPUDriverVersion,
	VBiosVersion:                      SPTGPUVBiosVersion,
}

// RawSwitchAttestationReportTestData contains the raw switch attestation report data required for testing.
var RawSwitchAttestationReportTestData = RawAttestationReportTestData{
	RawAttestationReport:              rawSwitchAttestationReport,
	NumberOfBlocks:                    64,
	MeasurementRecordOffset:           8,
	MeasurementRecordLength:           3520,
	DmtfMeasurementLength:             51,
	OpaqueDataOffset:                  1747,
	OpaqueDataLength:                  292,
	SpdmMeasurementResponseDataLength: 2135,
	Nonce:                             decodeHexString("1234567890123456789012345678901234567890123456789012345678901234"),
	VBiosVersion:                      NVSwitchBiosVersion,
}

// ReadXMLFile reads a XML file from the embedded filesystem.
func ReadXMLFile(name string) ([]byte, error) {
	return xmlFiles.ReadFile(name)
}

func decodeHexString(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// Parsed OCSP responses
var (
	ParsedGpuOcspResponseCertL4       = parseB64OcspResponse(testGpuOcspResponseCertL4)
	ParsedGpuOcspResponseCertL3       = parseB64OcspResponse(testGpuOcspResponseCertL3)
	ParsedGpuOcspResponseCertL2       = parseB64OcspResponse(testGpuOcspResponseCertL2)
	ParsedDriverRimOcspResponseCertL4 = parseB64OcspResponse(testDriverRimOcspResponseCertL4)
	ParsedVbiosRimOcspResponseCertL4  = parseB64OcspResponse(testVbiosRimOcspResponseCertL4)
	ParsedRimOcspResponseCertL3       = parseB64OcspResponse(testRimOcspResponseCertL3)
	ParsedRimOcspResponseCertL2       = parseB64OcspResponse(testRimOcspResponseCertL2)
)

const (
	// ExpectedGpuDriverRimFileID is the expected file ID for the GPU Driver RIM.
	ExpectedGpuDriverRimFileID = "NV_GPU_DRIVER_GH100_550.90.07"
	// ExpectedGpuVbiosRimFileID is the expected file ID for the GPU VBIOS RIM.
	ExpectedGpuVbiosRimFileID = "NV_GPU_VBIOS_1010_0200_882_96009F0001"
	// SPTGPUDriverVersion is the driver version for the GPU in the SPT attestation.
	SPTGPUDriverVersion = "550.90.07"
	// SPTGPUVBiosVersion is the vbios version for the GPU in the SPT attestation.
	SPTGPUVBiosVersion = "96.00.9f.00.01"
	// PpcieGPUDriverVersion is the driver version for the GPU in the PPCIE attestation.
	PpcieGPUDriverVersion = "570.124.06"
	// PpcieGPUVBiosVersion is the vbios version for the GPU in the PPCIE attestation.
	PpcieGPUVBiosVersion = "96.00.CF.00.02"
	// NVSwitchBiosVersion is the bios version for the NVSwitch attestestation.
	NVSwitchBiosVersion = "96.10.6D.00.01"
	// MptGPUDriverVersion is the driver version for the GPU in the MPT attestation.
	MptGPUDriverVersion = "590.48.01"
	// MptGPUVBiosVersion is the vbios version for the GPU in the MPT attestation.
	MptGPUVBiosVersion = "97.00.D9.00.35"
)

func parseB64OcspResponse(b64Data string) *ocsp.Response {
	respBytes, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		log.Fatalf("base64 decode error: %v", err)
	}
	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		log.Fatalf("ocsp.ParseResponse error: %v", err)
	}
	return resp
}
