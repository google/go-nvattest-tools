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

// Package client provides the library functions to get a GPU quote.
package client

import (
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
)

// GpuQuoteProvider encapsulates calls to GPU attestation quote.
type GpuQuoteProvider interface {
	CollectGpuEvidence(nonce [32]byte) (*pb.GpuAttestationQuote, error)
}

// GpuQuote uses Quote provider to get the quote in byte array and convert it into proto.
func GpuQuote(p GpuQuoteProvider, nonce [32]byte) (*pb.GpuAttestationQuote, error) {
	return p.CollectGpuEvidence(nonce)
}

// SwitchQuoteProvider encapsulates calls to Switch attestation quote.
type SwitchQuoteProvider interface {
	CollectSwitchEvidence(nonce [32]byte) (*pb.SwitchAttestationQuote, error)
}

// SwitchQuote uses Quote provider to get the quote in byte array and convert it into proto.
func SwitchQuote(p SwitchQuoteProvider, nonce [32]byte) (*pb.SwitchAttestationQuote, error) {
	return p.CollectSwitchEvidence(nonce)
}
