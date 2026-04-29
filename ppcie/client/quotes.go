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

package client

import (
	"context"
	"fmt"

	"github.com/google/go-nvattest-tools/client"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
)

// CollectOpts holds configuration for collecting quotes.
type CollectOpts struct {
	// Nonce is the nonce to use for GPU and NVSwitch attestation.
	Nonce []byte
}

// Attestation collects attestation quotes from GPUs and NVSwitches.
type Attestation struct {
	gpuQuoteProvider    client.GpuQuoteProvider
	switchQuoteProvider client.SwitchQuoteProvider
}

// NewAttestation creates a new Attestation with default providers.
func NewAttestation() *Attestation {
	return &Attestation{
		gpuQuoteProvider:    &client.LinuxGpuQuoteProvider{},
		switchQuoteProvider: &client.LinuxSwitchQuoteProvider{},
	}
}

// CollectAllDeviceQuotes collects attestation quotes for all GPUs and NVSwitches in the system.
// It orchestrates the evidence gathering process by leveraging the client component. This
// function does not perform any verification on the collected quotes.
func (a *Attestation) CollectAllDeviceQuotes(ctx context.Context, opts CollectOpts) (*pb.GpuAttestationQuote, *pb.SwitchAttestationQuote, error) {
	if opts.Nonce == nil {
		return nil, nil, fmt.Errorf("Nonce cannot be nil")
	}
	if len(opts.Nonce) != 32 {
		return nil, nil, fmt.Errorf("nonce must be 32 bytes, got %d", len(opts.Nonce))
	}

	// SPDM specification requires a 32-byte nonce for attestation challenges.
	// See section 8.4 "CHALLENGE" in https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.3.0.pdf.
	var nonce [32]byte
	copy(nonce[:], opts.Nonce)

	// 1. Initialize GPU Quote Provider and collect GPU quotes.
	collectedGpuQuote, gpuErr := a.gpuQuoteProvider.CollectGpuEvidence(nonce)
	if gpuErr != nil {
		return nil, nil, fmt.Errorf("collecting GPU quotes: %w", gpuErr)
	}

	// 2. Initialize Switch Quote Provider and collect Switch quotes.
	collectedSwitchQuote, switchErr := a.switchQuoteProvider.CollectSwitchEvidence(nonce)
	if switchErr != nil {
		// If any step of the collection fails, return nil for both gpuQuote and switchQuote.
		return nil, nil, fmt.Errorf("collecting Switch quotes: %w", switchErr)
	}

	return collectedGpuQuote, collectedSwitchQuote, nil
}
