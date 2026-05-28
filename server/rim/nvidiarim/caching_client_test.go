package nvidiarim

import (
	"encoding/base64"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

	nvrimpb "github.com/google/go-nvattest-tools/proto/nvrim"
)

var (
	testCache = nvrimpb.NvidiaRims_builder{
		RimsData: map[string]string{
			"rim1": base64.StdEncoding.EncodeToString([]byte("rim1_content")),
			"rim2": base64.StdEncoding.EncodeToString([]byte("rim2_content")),
		},
	}.Build()
)

func TestCachingClient_ListRIMs(t *testing.T) {
	tests := []struct {
		name    string
		client  *CachingClient
		want    []string
		wantErr bool
	}{
		{
			name:   "Success",
			client: &CachingClient{cache: testCache},
			want:   []string{"rim1", "rim2"},
		},
		{
			name:   "UnloadedCache",
			client: &CachingClient{cache: nil},
			want:   nil,
		},
		{
			name:   "EmptyCache",
			client: &CachingClient{cache: nvrimpb.NvidiaRims_builder{RimsData: map[string]string{}}.Build()},
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.client.ListRIMs(t.Context())
			if (err != nil) != tt.wantErr {
				t.Errorf("CachingClient.ListRIMs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			sort.Strings(got)
			sort.Strings(tt.want)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("CachingClient.ListRIMs() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCachingClient_FetchRIM(t *testing.T) {
	tests := []struct {
		name    string
		client  *CachingClient
		rimID   string
		want    []byte
		wantErr bool
	}{
		{
			name:   "Success",
			client: &CachingClient{cache: testCache},
			rimID:  "rim1",
			want:   []byte("rim1_content"),
		},
		{
			name:    "NotFound",
			client:  &CachingClient{cache: testCache},
			rimID:   "rim3",
			wantErr: true,
		},
		{
			name:    "UnloadedCache",
			client:  &CachingClient{cache: nil},
			rimID:   "any",
			wantErr: true,
		},
		{
			name: "Base64DecodeError",
			client: &CachingClient{cache: nvrimpb.NvidiaRims_builder{
				RimsData: map[string]string{
					"rim_invalid_base64": "invalid-base64-string",
				},
			}.Build()},
			rimID:   "rim_invalid_base64",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.client.FetchRIM(t.Context(), tt.rimID)
			if (err != nil) != tt.wantErr {
				t.Errorf("CachingClient.FetchRIM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("CachingClient.FetchRIM() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
