package mpt

import (
	"testing"

	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
	"github.com/google/go-nvattest-tools/testing/testdata"
)

func TestVerifySystemQuotes_Success(t *testing.T) {
	quote := testdata.MptAttestationDataSet.GpuAttestationQuote

	if len(quote.GetGpuInfos()) == 0 {
		t.Fatalf("Expected at least one GPU quote in the dataset")
	}

	opts := Options{
		Validation: validate.Options{
			DisableRefCheck: true,
			Nonce:           testdata.MptAttestationDataSet.Nonce,
			GpuArch:         nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL,
		},
		Verification: verify.Options{
			DisableOCSPCheck: true,
			DisableRIMCheck:  true,
			GpuOpts: verify.GPUOpts{
				GPUArch:            nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL,
				MaxCertChainLength: 5,
			},
		},
	}

	quoteState, err := VerifySystemQuotes(t.Context(), quote, opts)
	if err != nil {
		t.Errorf("VerifySystemQuotes failed: %v", err)
	}

	if quoteState == nil {
		t.Errorf("Expected non-nil quoteState, got nil")
	} else if len(quoteState.GpuInfoStates) != len(quote.GetGpuInfos()) {
		t.Errorf("Expected %d GPU states, got %d", len(quote.GetGpuInfos()), len(quoteState.GpuInfoStates))
	}
}
