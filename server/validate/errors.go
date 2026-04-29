package validate

import (
	"fmt"
	"strings"
)

type mismatchedMeasurement struct {
	index                   int
	goldenMeasurementValues []string
	runtimeMeasurementValue string
}

// MismatchedMeasurementsError is returned when the golden and runtime measurements do not match.
type MismatchedMeasurementsError struct {
	mismatchedMeasurements []mismatchedMeasurement
}

func (e *MismatchedMeasurementsError) Error() string {
	return fmt.Sprintf("mismatched measurements at indices: %v", e.mismatchedMeasurements)
}

// NoMeasurementsError is returned when no measurements are found in a data source.
type NoMeasurementsError struct {
	measurementType string
	dataSource      string
}

func (e *NoMeasurementsError) Error() string {
	return fmt.Sprintf("no %s measurements found in %s", e.measurementType, e.dataSource)
}

// InvalidComparisonError is returned when golden measurements in RIM are more than runtime measurements in attestation report.
type InvalidComparisonError struct{}

func (e *InvalidComparisonError) Error() string {
	return "golden measurements in RIM are more than runtime measurements in attestation report"
}

// MultipleMeasurementsWithSameIndexError is returned when there are multiple measurements with the same index in RIM.
type MultipleMeasurementsWithSameIndexError struct {
	index int
}

func (e *MultipleMeasurementsWithSameIndexError) Error() string {
	return fmt.Sprintf("invalid measurement index: multiple measurements have the same index %d", e.index)
}

// NonceMismatchError is returned when the nonce in the attestation report does not match the expected nonce.
type NonceMismatchError struct {
	actual   []byte
	expected []byte
}

func (e *NonceMismatchError) Error() string {
	return fmt.Sprintf("nonce mismatch: got %x, expected %x", e.actual, e.expected)
}

// DriverVersionMismatchError is returned when the driver version in the attestation report does not match the expected driver version.
type DriverVersionMismatchError struct {
	actual   string
	expected string
}

func (e *DriverVersionMismatchError) Error() string {
	return fmt.Sprintf("driver version mismatch: got %s, expected %s", e.actual, e.expected)
}

// VBiosVersionMismatchError is returned when the vbios version in the attestation report does not match the expected vbios version.
type VBiosVersionMismatchError struct {
	actual   string
	expected string
}

func (e *VBiosVersionMismatchError) Error() string {
	return fmt.Sprintf("vbios version mismatch: got %s, expected %s", strings.ToLower(e.actual), e.expected)
}
