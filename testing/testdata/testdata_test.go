package testdata

import (
	"testing"
	"time"

	"github.com/google/go-nvattest-tools/abi"
	"github.com/google/go-nvattest-tools/ppcie/server"
	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
)

func TestPpcieAttestationDataSet(t *testing.T) {
	opts := ppcie.Options{
		VerificationOpts: verify.Options{
			AllowOCSPCertHold: true,
			DisableRIMCheck:   true,
			DisableOCSPCheck:  true,
			GpuOpts: verify.GPUOpts{
				GPUArch:            nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				MaxCertChainLength: 5,
			},
			SwitchOpts: verify.SwitchOpts{
				MaxCertChainLength: 5,
			},
			Now: &verify.TimeSet{
				GPUCertChain:    time.Now(), // time.Now() is used to compare with the real-time GPU device L5 certificate from attestation report.
				SwitchCertChain: time.Now(), // time.Now() is used to compare with the real-time Switch device L5 certificate from attestation report.
			},
		},
		GPUValidationOpts: validate.Options{
			Nonce:           PpcieAttestationDataSet.Nonce,
			DisableRefCheck: true,
			GpuArch:         nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			AttestationType: abi.GPU,
		},
		NVSwitchValidationOpts: validate.Options{
			Nonce:           PpcieAttestationDataSet.Nonce,
			DisableRefCheck: true,
			AttestationType: abi.SWITCH,
		},
		ExpectedGpuCount:    8, // PPCIE requires 8 GPUs.
		ExpectedSwitchCount: 4, // PPCIE requires 4 switches.
	}

	// Verify the system quotes.
	gpuState, switchState, err := ppcie.VerifySystemQuotes(t.Context(), PpcieAttestationDataSet.GpuAttestationQuote, PpcieAttestationDataSet.SwitchAttestationQuote, opts)
	if err != nil {
		t.Errorf("Failed to verify system quotes: %v", err)
	}

	var gpuAttestationReports []*nvattestpb.AttestationReport
	for _, gpuInfo := range PpcieAttestationDataSet.GpuAttestationQuote.GetGpuInfos() {
		gpuAttestationReport, err := abi.RawAttestationReportToProto(gpuInfo.GetAttestationReport(), abi.GPU)
		if err != nil {
			t.Fatalf("Failed to convert raw GPU attestation report to proto: %v", err)
		}
		gpuAttestationReports = append(gpuAttestationReports, gpuAttestationReport)
	}
	var switchAttestationReports []*nvattestpb.AttestationReport
	for _, switchInfo := range PpcieAttestationDataSet.SwitchAttestationQuote.GetSwitchInfos() {
		switchAttestationReport, err := abi.RawAttestationReportToProto(switchInfo.GetAttestationReport(), abi.SWITCH)
		if err != nil {
			t.Fatalf("Failed to convert raw switch attestation report to proto: %v", err)
		}
		switchAttestationReports = append(switchAttestationReports, switchAttestationReport)
	}

	// Validate the PPCIE topology.
	err = ppcie.ValidateSystemTopology(t.Context(), gpuAttestationReports, switchAttestationReports, &opts)
	if err != nil {
		t.Errorf("Failed to validate system topology: %v", err)
	}

	t.Logf("GPU state: %+v", gpuState)
	t.Logf("Switch state: %+v", switchState)
}
