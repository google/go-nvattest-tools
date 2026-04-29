package testdata

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"

	"log"

	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"
)

//go:embed "test_ppcie_data.json"
var testJSONBytes []byte

type certificate struct {
	Pem string `json:"pem,omitempty"`
}

type attestationReport struct {
	B64Str string `json:"py/b64,omitempty"`
}

type gpuCertificateChains struct {
	Certificates []certificate `json:"GpuAttestationCertificateChain,omitempty"`
}

type gpu struct {
	UUID              string               `json:"UUID,omitempty"`
	DriverVersion     string               `json:"DriverVersion,omitempty"`
	VBiosVersion      string               `json:"VbiosVersion,omitempty"`
	CertificateChains gpuCertificateChains `json:"CertificateChains,omitempty"`
	AttestationReport attestationReport    `json:"AttestationReport,omitempty"`
}

type nvSwitch struct {
	UUID              string            `json:"uuid,omitempty"`
	CertificateChains []certificate     `json:"attestation_cert_chain,omitempty"`
	AttestationReport attestationReport `json:"attestation_report,omitempty"`
}

type data struct {
	Gpus       []gpu      `json:"gpus,omitempty"`
	NvSwitches []nvSwitch `json:"nvswitches,omitempty"`
}

func parse(jsonBytes []byte) (data, error) {
	var d data
	if err := json.Unmarshal(jsonBytes, &d); err != nil {
		return data{}, err
	}
	return d, nil
}

type testDataSet struct {
	Nonce                  []byte                             // Nonce set in the PPCIE attestation data.
	GpuAttestationQuote    *nvattestpb.GpuAttestationQuote    // Good GPU attestation quote for testing.
	SwitchAttestationQuote *nvattestpb.SwitchAttestationQuote // Good switch attestation quote for testing.
	DriverVersion          string                             // Driver version for the GPU.
	VBiosVersion           string                             // VBIOS version for the GPU.
	BiosVersion            string                             // BIOS version for the NVSwitch.
}

// PpcieAttestationDataSet contains the parsed PPCIE attestation data for testing purposes.
var PpcieAttestationDataSet = testDataSet{
	Nonce:                  decodeHexString("1234567890123456789012345678901234567890123456789012345678901234"),
	GpuAttestationQuote:    parseGpuAttestationQuote(),
	SwitchAttestationQuote: parseSwitchAttestationQuote(),
	DriverVersion:          PpcieGPUDriverVersion,
	VBiosVersion:           PpcieGPUVBiosVersion,
	BiosVersion:            NVSwitchBiosVersion,
}

func parseGpuAttestationQuote() *nvattestpb.GpuAttestationQuote {
	d, err := parse(testJSONBytes)
	if err != nil {
		log.Fatalf("Failed to parse raw JSON bytes for example data: %v", err)
	}

	var gpuInfos []*nvattestpb.GpuInfo
	for _, gpu := range d.Gpus {
		var attestationCertificationChain []byte
		for _, cert := range gpu.CertificateChains.Certificates {
			certBytes, err := base64.StdEncoding.DecodeString(cert.Pem)
			if err != nil {
				log.Fatalf("Failed to parse base64 encoded GPU attestation cert: %v", err)
			}
			attestationCertificationChain = append(attestationCertificationChain, certBytes...)
		}

		attestationReport, err := base64.StdEncoding.DecodeString(gpu.AttestationReport.B64Str)
		if err != nil {
			log.Fatalf("Failed to parse base64 encoded GPU attestation report: %v", err)
		}

		gpuInfo := &nvattestpb.GpuInfo{
			Uuid:                        gpu.UUID,
			DriverVersion:               gpu.DriverVersion,
			VbiosVersion:                gpu.VBiosVersion,
			AttestationCertificateChain: attestationCertificationChain,
			GpuArchitecture:             nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			AttestationReport:           attestationReport,
		}

		gpuInfos = append(gpuInfos, gpuInfo)
	}

	return &nvattestpb.GpuAttestationQuote{GpuInfos: gpuInfos}
}

func parseSwitchAttestationQuote() *nvattestpb.SwitchAttestationQuote {
	d, err := parse(testJSONBytes)
	if err != nil {
		log.Fatalf("Failed to parse raw JSON bytes for example data: %v", err)
	}

	var switchInfos []*nvattestpb.SwitchInfo
	for _, nvSwitch := range d.NvSwitches {
		var attestationCertificationChain []byte
		for _, cert := range nvSwitch.CertificateChains {
			certBytes, err := base64.StdEncoding.DecodeString(cert.Pem)
			if err != nil {
				log.Fatalf("Failed to parse base64 encoded NVSwitch attestation cert: %v", err)
			}
			attestationCertificationChain = append(attestationCertificationChain, certBytes...)
		}

		attestationReport, err := base64.StdEncoding.DecodeString(nvSwitch.AttestationReport.B64Str)
		if err != nil {
			log.Fatalf("Failed to parse base64 encoded NVSwitch attestation report: %v", err)
		}

		switchInfo := &nvattestpb.SwitchInfo{
			Uuid:                        nvSwitch.UUID,
			AttestationCertificateChain: attestationCertificationChain,
			AttestationReport:           attestationReport,
		}

		switchInfos = append(switchInfos, switchInfo)
	}

	return &nvattestpb.SwitchAttestationQuote{SwitchInfos: switchInfos}
}
