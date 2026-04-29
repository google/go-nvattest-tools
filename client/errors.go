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
	"fmt"
)

const (
	// NvmlLibraryInitFailed is returned when the NVML library fails to initialize.
	NvmlLibraryInitFailed = "nvml library init failed"
	// NvmlLibraryShutdownFailed is returned when the NVML library fails to shutdown.
	NvmlLibraryShutdownFailed = "nvml library shutdown failed"
	// NvmlDeviceGetCountFailed is returned when the NVML library fails to get the device count.
	NvmlDeviceGetCountFailed = "nvml device get count failed"
	// NvmlDeviceGetHandleByIndexFailed is returned when the NVML library fails to get a device handle by index.
	NvmlDeviceGetHandleByIndexFailed = "nvml device get handle failed"
	// NvmlSystemGetDriverVersionFailed is returned when the NVML library fails to get the driver version.
	NvmlSystemGetDriverVersionFailed = "nvml system get driver version failed"
	// NvmlDeviceGetUUIDFailed is returned when the NVML library fails to get the device UUID.
	NvmlDeviceGetUUIDFailed = "nvml device get uuid failed"
	// NvmlDeviceGetVbiosVersionFailed is returned when the NVML library fails to get the device VBIOS version.
	NvmlDeviceGetVbiosVersionFailed = "nvml device get vbios version failed"
	// NvmlDeviceGetArchitectureFailed is returned when the NVML library fails to get the device architecture.
	NvmlDeviceGetArchitectureFailed = "nvml device get architecture failed"
	// NvmlDeviceGetConfComputeGpuAttestationReportFailed is returned when the NVML library fails to get the device conf compute GPU attestation report.
	NvmlDeviceGetConfComputeGpuAttestationReportFailed = "nvml device get conf compute GPU attestation report failed"
	// NvmlDeviceGetConfComputeGpuCertificateFailed is returned when the NVML library fails to get the device conf compute GPU certificate.
	NvmlDeviceGetConfComputeGpuCertificateFailed = "nvml device get conf compute GPU certificate failed"

	// NscqLibraryInitFailed is returned when the NSCQ library fails to initialize.
	NscqLibraryInitFailed = "nscq library init failed"
	// NscqLibraryShutdownFailed is returned when the NSCQ library fails to shutdown.
	NscqLibraryShutdownFailed = "nscq library shutdown failed"
	// NscqSessionCreateFailed is returned when the NSCQ library fails to create a session.
	NscqSessionCreateFailed = "nscq session create failed"
	// NscqSessionDestroyFailed is returned when the NSCQ library fails to destroy a session.
	NscqSessionDestroyFailed = "nscq session destroy failed"
	// NscqSwitchDeviceUUIDsFailed is returned when the NSCQ library fails to get the switch device UUIDs.
	NscqSwitchDeviceUUIDsFailed = "nscq switch device UUIDs failed"
	// NscqSwitchArchitectureFailed is returned when the NSCQ library fails to get the switch architecture.
	NscqSwitchArchitectureFailed = "nscq switch architecture failed"
	// NscqSwitchAttestationReportFailed is returned when the NSCQ library fails to get the switch attestation report.
	NscqSwitchAttestationReportFailed = "nscq switch attestation report failed"
	// NscqSwitchAttestationCertificateChainFailed is returned when the NSCQ library fails to get the switch attestation certificate chain.
	NscqSwitchAttestationCertificateChainFailed = "nscq switch attestation certificate chain failed"

	noGpuDevicesFound    = "no GPU devices found"
	noSwitchDevicesFound = "no switch devices found"
	nilLibInterface      = "unable to create a new %v interface"
)

// LibError is a generic error for library failures.
type LibError struct {
	// Operation is the name of the attempted operation.
	Operation string
	// ReturnCode is the error code returned by the library.
	ReturnCode any
}

func (e *LibError) Error() string {
	return fmt.Sprintf("%s: %v", e.Operation, e.ReturnCode)
}

// Unwrap allows errors.Is and errors.As to work with the wrapped return code.
func (e *LibError) Unwrap() error {
	if err, ok := e.ReturnCode.(error); ok {
		return err
	}
	return nil
}

// NoGpuDevicesError is returned when no GPU devices are found.
type NoGpuDevicesError struct{}

func (e *NoGpuDevicesError) Error() string {
	return noGpuDevicesFound
}

// PlatformNotSupportedError is returned when the Windows platform is not supported.
type PlatformNotSupportedError struct {
	platform string
}

func (e *PlatformNotSupportedError) Error() string {
	return fmt.Sprintf("%v platform is not supported", e.platform)
}

// IncorrectLengthError is returned when the length of a buffer is incorrect.
type IncorrectLengthError struct {
	context  string
	expected int
	actual   int
}

func (e *IncorrectLengthError) Error() string {
	return fmt.Sprintf("incorrect length of %v, expected: %v, actual: %v", e.context, e.expected, e.actual)
}

// NilLibInterfaceError is returned when the library interface is nil.
type NilLibInterfaceError struct {
	lib string
}

func (e *NilLibInterfaceError) Error() string {
	return fmt.Sprintf(nilLibInterface, e.lib)
}

// NoSwitchDevicesError is returned when no switch devices are found.
type NoSwitchDevicesError struct{}

func (e *NoSwitchDevicesError) Error() string {
	return noSwitchDevicesFound
}
