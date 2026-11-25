package abi

import "fmt"

// OutOfRangeRuntimeError is returned when a slice bounds out of range.
const OutOfRangeRuntimeError = "runtime error: slice bounds out of range"

// IncorrectLengthError is returned when the length of a buffer is incorrect.
type IncorrectLengthError struct {
	Context  string
	Expected int
	Actual   int
}

func (e *IncorrectLengthError) Error() string {
	return fmt.Sprintf("incorrect length of %v, expected: %v, actual: %v", e.Context, e.Expected, e.Actual)
}

// ParsingError is returned when parsing a buffer fails.
type ParsingError struct {
	Context string
	Info    string
}

func (e *ParsingError) Error() string {
	return fmt.Sprintf("error while parsing %v : %v", e.Context, e.Info)
}

// UnsupportedDmtfMeasurementSpecificationError is returned when the measurement specification is unsupported.
type UnsupportedDmtfMeasurementSpecificationError struct {
	Index uint8
}

func (e *UnsupportedDmtfMeasurementSpecificationError) Error() string {
	return fmt.Sprintf("unsupported measurement specification at index %d", e.Index)
}

// NoMeasurementBlocksError is returned when no measurement blocks are found.
type NoMeasurementBlocksError struct{}

func (e *NoMeasurementBlocksError) Error() string {
	return "there are no measurement blocks in the measurement record"
}

// InvalidSizeMeasurementCountsError is returned when the size of the measurement counts is invalid.
type InvalidSizeMeasurementCountsError struct {
	Expected int
	Actual   int
}

func (e *InvalidSizeMeasurementCountsError) Error() string {
	return fmt.Sprintf("invalid size of %d bytes for measurement counts, expected multiple of %d bytes", e.Actual, e.Expected)
}

// InvalidSizeSwitchPdisError is returned when the size of the switch pdis is invalid.
type InvalidSizeSwitchPdisError struct {
	Expected int
	Actual   int
}

func (e *InvalidSizeSwitchPdisError) Error() string {
	return fmt.Sprintf("invalid size of %d bytes for switch PDI data, expected multiple of %d bytes", e.Actual, e.Expected)
}

// UnsupportedAttestationTypeError is returned when the attestation type is unsupported.
type UnsupportedAttestationTypeError struct {
	AttestationType AttestationType
}

func (e *UnsupportedAttestationTypeError) Error() string {
	return fmt.Sprintf("unsupported attestation type: %v", e.AttestationType)
}

// UnsupportedOpaqueDataProfileError is returned when the NVDAOD header profile is unsupported.
type UnsupportedOpaqueDataProfileError struct {
	Profile uint16
}

func (e *UnsupportedOpaqueDataProfileError) Error() string {
	return fmt.Sprintf("unsupported opaque data profile: %d", e.Profile)
}

// UnsupportedOpaqueDataVersionError is returned when the opaque data version exceeds MaxOpaqueDataVersion.
type UnsupportedOpaqueDataVersionError struct {
	Version uint64
	Max     uint64
}

func (e *UnsupportedOpaqueDataVersionError) Error() string {
	return fmt.Sprintf("opaque data version %d exceeds max supported %d", e.Version, e.Max)
}
