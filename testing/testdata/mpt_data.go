package testdata

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"

	"log"

	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"
)

//go:embed "test_mpt_data.json"
var testMptJSONBytes []byte

type mptData struct {
	Gpus []gpu `json:"gpus,omitempty"`
}

func parseMpt(jsonBytes []byte) (mptData, error) {
	var d mptData
	if err := json.Unmarshal(jsonBytes, &d); err != nil {
		return mptData{}, err
	}
	return d, nil
}

// MptAttestationDataSet contains the parsed MPT attestation data for testing purposes.
var MptAttestationDataSet = testDataSet{
	Nonce:               decodeHexString("cdb72201e569085d6de41863745f6f77db1f75962c29564ec6abe91f0221861f"),
	GpuAttestationQuote: parseMptGpuAttestationQuote(),
	DriverVersion:       MptGPUDriverVersion,
	VBiosVersion:        MptGPUVBiosVersion,
}

func parseMptGpuAttestationQuote() *nvattestpb.GpuAttestationQuote {
	d, err := parseMpt(testMptJSONBytes)
	if err != nil {
		log.Fatalf("Failed to parse raw JSON bytes for mpt data: %v", err)
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
			GpuArchitecture:             nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL,
			AttestationReport:           attestationReport,
		}

		gpuInfos = append(gpuInfos, gpuInfo)
	}

	return &nvattestpb.GpuAttestationQuote{GpuInfos: gpuInfos}
}
