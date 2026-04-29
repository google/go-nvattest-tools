package abi

import (
	"fmt"
	"strconv"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
)

// ExtractOpaqueValue extracts the value from the opaque field data list for the given data type.
func ExtractOpaqueValue(opaqueFieldDataList []*pb.OpaqueFieldData, dataType pb.OpaqueDataType) []byte {
	for _, fieldData := range opaqueFieldDataList {
		if fieldData.GetDataType() == dataType {
			return fieldData.GetValue()
		}
	}
	return nil
}

// clone makes a deep copy of a byte slice.
func clone(b []byte) []byte {
	result := make([]byte, len(b))
	copy(result, b)
	return result
}

// hexToBinary converts a hexadecimal string to its binary string representation.
func hexToBinary(hexString string) (string, error) {
	decimal, err := strconv.ParseUint(hexString, 16, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse hex string: %w", err)
	}

	binaryString := strconv.FormatUint(decimal, 2)

	return binaryString, nil
}
