// Package nvidiarim provides a client for accessing cached NVIDIA RIMs (Reference Integrity Manifests).
package nvidiarim

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/google/go-nvattest-tools/server/rim"

	nvrimpb "github.com/google/go-nvattest-tools/proto/nvrim"
)

var _ rim.Client = (*CachingClient)(nil)

// CachingClient is a client that fetches RIMs from an in-memory cache.
type CachingClient struct {
	cache *nvrimpb.NvidiaRims
}

// NewClient creates a new caching client from a NvidiaRims proto.
func NewClient(cache *nvrimpb.NvidiaRims) *CachingClient {
	return &CachingClient{cache: cache}
}

// ListRIMs lists the available RIMs.
func (c *CachingClient) ListRIMs(_ context.Context) ([]string, error) {
	var rimIDs []string
	for id := range c.cache.GetRimsData() {
		rimIDs = append(rimIDs, id)
	}
	return rimIDs, nil
}

// FetchRIM fetches the RIM with the given ID.
func (c *CachingClient) FetchRIM(_ context.Context, rimID string) ([]byte, error) {
	rimData, ok := c.cache.GetRimsData()[rimID]
	if !ok {
		return nil, fmt.Errorf("RIM ID %s not found in cache", rimID)
	}
	decodedData, err := base64.StdEncoding.DecodeString(rimData)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode RIM data for RIM ID %q: %w", rimID, err)
	}
	return decodedData, nil
}
