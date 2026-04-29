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

package client

import (
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/google/go-nvattest-tools/internal/nvnscq/pkg/nscq"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
)

var (
	_ GpuQuoteProvider    = (*LinuxGpuQuoteProvider)(nil)
	_ SwitchQuoteProvider = (*LinuxSwitchQuoteProvider)(nil)
)

// LinuxGpuQuoteProvider encapsulates calls to GPU attestation quote for Linux.
type LinuxGpuQuoteProvider struct {
	nvmlFactory func(opts ...nvml.LibraryOption) nvml.Interface
}

// CollectGpuEvidence collects GPU information for all GPU devices.
func (p *LinuxGpuQuoteProvider) CollectGpuEvidence(nonce [32]byte) (q *pb.GpuAttestationQuote, err error) {
	factory := p.nvmlFactory
	if factory == nil {
		factory = nvml.New
	}
	nvmlInterface := factory()

	if nvmlInterface == nil {
		return nil, &NilLibInterfaceError{lib: "NVML"}
	}

	ret := nvmlInterface.Init()
	if ret != nvml.SUCCESS {
		return nil, &LibError{
			Operation:  NvmlLibraryInitFailed,
			ReturnCode: ret,
		}
	}

	defer func() {
		ret := nvmlInterface.Shutdown()
		if ret != nvml.SUCCESS {
			if err == nil {
				err = &LibError{
					Operation:  NvmlLibraryShutdownFailed,
					ReturnCode: ret,
				}
			}
		}
	}()

	numberOfGpus, ret := nvmlInterface.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, &LibError{
			Operation:  NvmlDeviceGetCountFailed,
			ReturnCode: ret,
		}
	}

	if numberOfGpus == 0 {
		return nil, &NoGpuDevicesError{}
	}

	var gpuInfos []*pb.GpuInfo
	for index := 0; index < numberOfGpus; index++ {
		device, ret := nvmlInterface.DeviceGetHandleByIndex(index)
		if ret != nvml.SUCCESS {
			return nil, &LibError{
				Operation:  fmt.Sprintf("GPU index %d: %v", index, NvmlDeviceGetHandleByIndexFailed),
				ReturnCode: ret,
			}
		}

		uuid, ret := device.GetUUID()
		if ret != nvml.SUCCESS {
			return nil, &LibError{
				Operation:  fmt.Sprintf("%v for GPU at index: %v", NvmlDeviceGetUUIDFailed, index),
				ReturnCode: ret,
			}
		}

		driverVersion, ret := nvmlInterface.SystemGetDriverVersion()
		if ret != nvml.SUCCESS {
			return nil, &LibError{
				Operation:  NvmlSystemGetDriverVersionFailed,
				ReturnCode: ret,
			}
		}

		vbiosVersion, ret := device.GetVbiosVersion()
		if ret != nvml.SUCCESS {
			return nil, &LibError{
				Operation:  fmt.Sprintf("%v for GPU UUID: %q", NvmlDeviceGetVbiosVersionFailed, uuid),
				ReturnCode: ret,
			}
		}

		architecture, ret := device.GetArchitecture()
		if ret != nvml.SUCCESS {
			return nil, &LibError{
				Operation:  fmt.Sprintf("%v for GPU UUID: %q", NvmlDeviceGetArchitectureFailed, uuid),
				ReturnCode: ret,
			}
		}
		architectureType := getArchitectureType(architecture)

		attestationReportData := &nvml.ConfComputeGpuAttestationReport{Nonce: nonce}
		ret = device.GetConfComputeGpuAttestationReport(attestationReportData)
		if ret != nvml.SUCCESS {
			return nil, &LibError{
				Operation:  fmt.Sprintf("%v for GPU UUID: %q", NvmlDeviceGetConfComputeGpuAttestationReportFailed, uuid),
				ReturnCode: ret,
			}
		}

		if len(attestationReportData.AttestationReport) < int(attestationReportData.AttestationReportSize) {
			return nil, &IncorrectLengthError{
				context:  fmt.Sprintf("attestation report for GPU UUID: %q", uuid),
				expected: int(attestationReportData.AttestationReportSize),
				actual:   len(attestationReportData.AttestationReport),
			}
		}

		attestationReport := attestationReportData.AttestationReport[:attestationReportData.AttestationReportSize]

		gpuCertChain, ret := device.GetConfComputeGpuCertificate()
		if ret != nvml.SUCCESS {
			return nil, &LibError{
				Operation:  fmt.Sprintf("%v for GPU UUID: %q", NvmlDeviceGetConfComputeGpuCertificateFailed, uuid),
				ReturnCode: ret,
			}
		}

		if len(gpuCertChain.AttestationCertChain) < int(gpuCertChain.AttestationCertChainSize) {
			return nil, &IncorrectLengthError{
				context:  fmt.Sprintf("attestation certificate chain for GPU UUID: %q", uuid),
				expected: int(gpuCertChain.AttestationCertChainSize),
				actual:   len(gpuCertChain.AttestationCertChain),
			}
		}

		attestationCertificateChain := gpuCertChain.AttestationCertChain[:gpuCertChain.AttestationCertChainSize]

		gpuInfo := &pb.GpuInfo{
			Uuid:                        uuid,
			DriverVersion:               driverVersion,
			VbiosVersion:                vbiosVersion,
			GpuArchitecture:             architectureType,
			AttestationCertificateChain: attestationCertificateChain,
			AttestationReport:           attestationReport,
		}

		gpuInfos = append(gpuInfos, gpuInfo)
	}

	return &pb.GpuAttestationQuote{GpuInfos: gpuInfos}, err
}

// getArchitectureType returns the GPU architecture type.
func getArchitectureType(arch nvml.DeviceArchitecture) pb.GpuArchitectureType {
	switch arch {
	case nvml.DEVICE_ARCH_KEPLER:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_KEPLER
	case nvml.DEVICE_ARCH_MAXWELL:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_MAXWELL
	case nvml.DEVICE_ARCH_PASCAL:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_PASCAL
	case nvml.DEVICE_ARCH_VOLTA:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_VOLTA
	case nvml.DEVICE_ARCH_TURING:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_TURING
	case nvml.DEVICE_ARCH_AMPERE:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_AMPERE
	case nvml.DEVICE_ARCH_ADA:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_ADA
	case nvml.DEVICE_ARCH_HOPPER:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER
	case nvml.DEVICE_ARCH_BLACKWELL:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL
	default:
		return pb.GpuArchitectureType_GPU_ARCHITECTURE_UNKNOWN
	}
}

// LinuxSwitchQuoteProvider encapsulates calls to Switch attestation quote for Linux.
type LinuxSwitchQuoteProvider struct {
	nscqFactory func(opts ...nscq.LibraryOption) nscq.Interface
}

// CollectSwitchEvidence collects Switch information for all Switch devices.
func (p *LinuxSwitchQuoteProvider) CollectSwitchEvidence(nonce [32]byte) (q *pb.SwitchAttestationQuote, err error) {
	factory := p.nscqFactory
	if factory == nil {
		factory = nscq.New
	}
	nscqInterface := factory()

	if nscqInterface == nil {
		return nil, &NilLibInterfaceError{lib: "NSCQ"}
	}

	ret := nscqInterface.Init()
	if ret != nscq.Success {
		return nil, &LibError{
			Operation:  NscqLibraryInitFailed,
			ReturnCode: ret,
		}
	}

	session, ret := nscqInterface.SessionCreate(1)
	if ret != nscq.Success {
		return nil, &LibError{
			Operation:  NscqSessionCreateFailed,
			ReturnCode: ret,
		}
	}

	defer func() {
		ret := nscqInterface.SessionDestroy(session)
		if ret != nscq.Success {
			if err == nil {
				err = &LibError{
					Operation:  NscqSessionDestroyFailed,
					ReturnCode: ret,
				}
			}
		}
		ret = nscqInterface.Shutdown()
		if ret != nscq.Success {
			if err == nil {
				err = &LibError{
					Operation:  NscqLibraryShutdownFailed,
					ReturnCode: ret,
				}
			}
		}
	}()

	switchUUIDs, ret := nscqInterface.SwitchDeviceUUIDs(session)
	if ret != nscq.Success {
		return nil, &LibError{
			Operation:  NscqSwitchDeviceUUIDsFailed,
			ReturnCode: ret,
		}
	}

	if len(switchUUIDs) == 0 {
		return nil, &NoSwitchDevicesError{}
	}

	var switchInfos []*pb.SwitchInfo

	for _, uuid := range switchUUIDs {
		attestationReport, ret := nscqInterface.SwitchAttestationReport(session, nonce, uuid)
		if ret != nscq.Success {
			return nil, &LibError{
				Operation:  fmt.Sprintf("%v for switch UUID: %q", NscqSwitchAttestationReportFailed, uuid),
				ReturnCode: ret,
			}
		}

		attestationCertChain, ret := nscqInterface.SwitchAttestationCertificateChain(session, uuid)
		if ret != nscq.Success {
			return nil, &LibError{
				Operation:  fmt.Sprintf("%v for switch UUID: %q", NscqSwitchAttestationCertificateChainFailed, uuid),
				ReturnCode: ret,
			}
		}

		switchInfo := &pb.SwitchInfo{
			Uuid:                        uuid,
			AttestationCertificateChain: attestationCertChain,
			AttestationReport:           attestationReport,
		}

		switchInfos = append(switchInfos, switchInfo)
	}

	return &pb.SwitchAttestationQuote{SwitchInfos: switchInfos}, err
}
