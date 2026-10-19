package mpt

import (
	"context"
	"errors"
	"fmt"
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

// newQuote returns a quote with n GPU reports.
func newQuote(n int) *nvattestpb.GpuAttestationQuote {
	quote := &nvattestpb.GpuAttestationQuote{}
	for i := range n {
		quote.GpuInfos = append(quote.GpuInfos, &nvattestpb.GpuInfo{Uuid: fmt.Sprintf("gpu%d", i)})
	}
	return quote
}

func TestVerifySystemQuotes_TooManyGpusFailsBeforeVerification(t *testing.T) {
	quote := newQuote(DefaultMaxGpuCount + 1)
	verifyCalls := 0
	verifyGpuInfo := func(context.Context, *nvattestpb.GpuInfo, verify.Options) (*nvattestpb.GpuInfoState, error) {
		verifyCalls++
		return nil, errors.New("not verified")
	}

	if _, err := verifySystemQuotes(t.Context(), quote, Options{}, verifyGpuInfo); err == nil {
		t.Errorf("verifySystemQuotes() with %d GPU reports = nil error, want error", len(quote.GetGpuInfos()))
	}
	if verifyCalls != 0 {
		t.Errorf("verifySystemQuotes() with %d GPU reports verified %d reports, want 0", len(quote.GetGpuInfos()), verifyCalls)
	}
}

func TestVerifySystemQuotes_MaxGpuCountRaisesLimit(t *testing.T) {
	quote := newQuote(DefaultMaxGpuCount + 1)
	verifyCalls := 0
	verifyGpuInfo := func(context.Context, *nvattestpb.GpuInfo, verify.Options) (*nvattestpb.GpuInfoState, error) {
		verifyCalls++
		return nil, errors.New("not verified")
	}

	// The count check passes, so every report reaches verification. The stub
	// rejects each report, so the call returns the verification errors.
	verifySystemQuotes(t.Context(), quote, Options{MaxGpuCount: DefaultMaxGpuCount + 1}, verifyGpuInfo)
	if verifyCalls != len(quote.GetGpuInfos()) {
		t.Errorf("verifySystemQuotes() with MaxGpuCount %d verified %d reports, want %d", DefaultMaxGpuCount+1, verifyCalls, len(quote.GetGpuInfos()))
	}
}
