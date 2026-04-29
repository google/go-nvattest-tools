package abi

import pb "github.com/google/go-nvattest-tools/proto/nvattest"

// opaqueDataParser is an interface for parsing opaque data.
type opaqueDataParser interface {
	// ParseOpaqueData parses the opaque data from the given byte slice.
	ParseOpaqueData(b []uint8, opaqueLength int) (od *pb.OpaqueData, err error)
}
