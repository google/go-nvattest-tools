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

// ExtractOpaqueFieldByRawType extracts the OpaqueFieldData matching the raw uint16 type ID.
// For backward compatibility with manually constructed OpaqueFieldData messages that do not set
// RawDataType, it also falls back to matching the mapped OpaqueDataType when RawDataType is 0.
func ExtractOpaqueFieldByRawType(opaqueFieldDataList []*pb.OpaqueFieldData, rawDataType uint16) *pb.OpaqueFieldData {
	mappedType, hasMapped := gpuOpaqueDataTypes[rawDataType]
	for _, fieldData := range opaqueFieldDataList {
		if rawDataType == 0 {
			if fieldData.GetRawDataType() == 0 && fieldData.GetDataType() == pb.OpaqueDataType_OPAQUE_FIELD_ID_UNSPECIFIED {
				return fieldData
			}
			continue
		}
		if fieldData.GetRawDataType() == uint32(rawDataType) {
			return fieldData
		}
		if fieldData.GetRawDataType() == 0 && hasMapped && mappedType != pb.OpaqueDataType_OPAQUE_FIELD_ID_UNSPECIFIED && fieldData.GetDataType() == mappedType {
			return fieldData
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
