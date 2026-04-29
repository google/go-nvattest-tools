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
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-nvattest-tools/client"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"google.golang.org/protobuf/testing/protocmp"
)

type mockGpuQuoteProvider struct {
	q   *pb.GpuAttestationQuote
	err error
}

func (m *mockGpuQuoteProvider) CollectGpuEvidence(nonce [32]byte) (*pb.GpuAttestationQuote, error) {
	return m.q, m.err
}

type mockSwitchQuoteProvider struct {
	q   *pb.SwitchAttestationQuote
	err error
}

func (m *mockSwitchQuoteProvider) CollectSwitchEvidence(nonce [32]byte) (*pb.SwitchAttestationQuote, error) {
	return m.q, m.err
}

func TestCollectAllDeviceQuotes(t *testing.T) {
	errDummy := errors.New("dummy error")
	gpuQuote := &pb.GpuAttestationQuote{
		GpuInfos: []*pb.GpuInfo{
			{Uuid: "gpu-0"},
		},
	}
	switchQuote := &pb.SwitchAttestationQuote{
		SwitchInfos: []*pb.SwitchInfo{
			{Uuid: "switch-0"},
		},
	}

	testCases := []struct {
		name            string
		opts            CollectOpts
		gpuProvider     client.GpuQuoteProvider
		switchProvider  client.SwitchQuoteProvider
		wantGpuQuote    *pb.GpuAttestationQuote
		wantSwitchQuote *pb.SwitchAttestationQuote
		wantErr         bool
	}{
		{
			name: "success",
			opts: CollectOpts{
				Nonce: []byte("01234567890123456789012345678901"),
			},
			gpuProvider:     &mockGpuQuoteProvider{q: gpuQuote},
			switchProvider:  &mockSwitchQuoteProvider{q: switchQuote},
			wantGpuQuote:    gpuQuote,
			wantSwitchQuote: switchQuote,
		},
		{
			name:           "nonce_nil",
			opts:           CollectOpts{},
			gpuProvider:    &mockGpuQuoteProvider{},
			switchProvider: &mockSwitchQuoteProvider{},
			wantErr:        true,
		},
		{
			name: "nonce_invalid_length",
			opts: CollectOpts{
				Nonce: []byte("invalid-nonce"),
			},
			gpuProvider:    &mockGpuQuoteProvider{},
			switchProvider: &mockSwitchQuoteProvider{},
			wantErr:        true,
		},
		{
			name: "gpu_quote_error",
			opts: CollectOpts{
				Nonce: []byte("01234567890123456789012345678901"),
			},
			gpuProvider:    &mockGpuQuoteProvider{err: errDummy},
			switchProvider: &mockSwitchQuoteProvider{q: switchQuote},
			wantErr:        true,
		},
		{
			name: "switch_quote_error",
			opts: CollectOpts{
				Nonce: []byte("01234567890123456789012345678901"),
			},
			gpuProvider:    &mockGpuQuoteProvider{q: gpuQuote},
			switchProvider: &mockSwitchQuoteProvider{err: errDummy},
			wantGpuQuote:   nil,
			wantErr:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attestation := NewAttestation()
			attestation.gpuQuoteProvider = tc.gpuProvider
			attestation.switchQuoteProvider = tc.switchProvider

			gotGpuQuote, gotSwitchQuote, err := attestation.CollectAllDeviceQuotes(t.Context(), tc.opts)

			if tc.wantErr {
				if err == nil {
					t.Fatal("CollectAllDeviceQuotes() succeeded, want error")
				}
			} else if err != nil {
				t.Fatalf("CollectAllDeviceQuotes() returned unexpected error: %v", err)
			}

			if diff := cmp.Diff(tc.wantGpuQuote, gotGpuQuote, protocmp.Transform()); diff != "" {
				t.Errorf("CollectAllDeviceQuotes() GPU quote mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantSwitchQuote, gotSwitchQuote, protocmp.Transform()); diff != "" {
				t.Errorf("CollectAllDeviceQuotes() Switch quote mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
