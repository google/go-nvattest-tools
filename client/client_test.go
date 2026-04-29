package client

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/google/go-nvattest-tools/internal/nvnscq/pkg/nscq"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	testdata "github.com/google/go-nvattest-tools/testing/testdata"
	test "github.com/google/go-nvattest-tools/testing"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestGpuQuote(t *testing.T) {

	testCases := []struct {
		name              string
		nonce             [32]byte
		nvmlInterfaceFunc func() nvml.Interface
		gpuQuote          *pb.GpuAttestationQuote
		wantErr           error
	}{
		{
			name:  "valid_gpu_quote",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				return test.DefaultMockGpuInterface()
			},
			gpuQuote: &pb.GpuAttestationQuote{
				GpuInfos: []*pb.GpuInfo{
					&pb.GpuInfo{
						Uuid:                        test.TestUUID,
						DriverVersion:               test.TestDriverVersion,
						VbiosVersion:                test.TestVBIOSVersion,
						GpuArchitecture:             getArchitectureType(test.TestArchitecture),
						AttestationCertificateChain: testdata.GpuAttestationCertificateChain[:test.TestAttestationCertChainSize],
						AttestationReport:           testdata.RawGpuAttestationReportTestData.RawAttestationReport[:test.TestGpuAttestationReportSize],
					},
					&pb.GpuInfo{
						Uuid:                        test.TestUUID,
						DriverVersion:               test.TestDriverVersion,
						VbiosVersion:                test.TestVBIOSVersion,
						GpuArchitecture:             getArchitectureType(test.TestArchitecture),
						AttestationCertificateChain: testdata.GpuAttestationCertificateChain[:test.TestAttestationCertChainSize],
						AttestationReport:           testdata.RawGpuAttestationReportTestData.RawAttestationReport[:test.TestGpuAttestationReportSize],
					},
				},
			},
			wantErr: nil,
		},
		{
			name:  "nil_nvml_interface",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				return nil
			},
			wantErr: &NilLibInterfaceError{lib: "NVML"},
		},
		{
			name:  "init_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.InitFunc = test.NvmlErrorInitFunc
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  NvmlLibraryInitFailed,
				ReturnCode: nvml.ERROR_LIBRARY_NOT_FOUND,
			},
		},
		{
			name:  "device_count_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.DeviceGetCountFunc = test.NvmlErrorDeviceGetCountFunc
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  NvmlDeviceGetCountFailed,
				ReturnCode: nvml.ERROR_UNKNOWN,
			},
		},
		{
			name:  "no_gpus",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.DeviceGetCountFunc = test.NvmlSuccessDeviceGetCountNoGpusFunc
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr:  &NoGpuDevicesError{},
		},
		{
			name:  "device_get_handle_by_index_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.DeviceGetHandleByIndexFunc = test.NvmlErrorDeviceGetHandleByIndexFunc
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  fmt.Sprintf("GPU index 0: %v", NvmlDeviceGetHandleByIndexFailed),
				ReturnCode: nvml.ERROR_UNKNOWN,
			},
		},
		{
			name:  "device_uuid_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.DeviceGetHandleByIndexFunc = func(index int) (nvml.Device, nvml.Return) {
					gpuDevice := test.DefaultMockGpuDevice()
					gpuDevice.GetUUIDFunc = test.NvmlErrorGetUUIDFunc
					return gpuDevice, nvml.SUCCESS
				}
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  fmt.Sprintf("%v for GPU at index: 0", NvmlDeviceGetUUIDFailed),
				ReturnCode: nvml.ERROR_UNKNOWN,
			},
		},
		{
			name:  "driver_version_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.SystemGetDriverVersionFunc = test.NvmlErrorSystemGetDriverVersionFunc
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  NvmlSystemGetDriverVersionFailed,
				ReturnCode: nvml.ERROR_UNKNOWN,
			},
		},
		{
			name:  "device_vbios_version_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.DeviceGetHandleByIndexFunc = func(index int) (nvml.Device, nvml.Return) {
					gpuDevice := test.DefaultMockGpuDevice()
					gpuDevice.GetVbiosVersionFunc = test.NvmlErrorGetVbiosVersionFunc
					return gpuDevice, nvml.SUCCESS
				}
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  fmt.Sprintf("%v for GPU UUID: %q", NvmlDeviceGetVbiosVersionFailed, test.TestUUID),
				ReturnCode: nvml.ERROR_UNKNOWN,
			},
		},
		{
			name:  "device_architecture_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.DeviceGetHandleByIndexFunc = func(index int) (nvml.Device, nvml.Return) {
					gpuDevice := test.DefaultMockGpuDevice()
					gpuDevice.GetArchitectureFunc = test.NvmlErrorGetArchitectureFunc
					return gpuDevice, nvml.SUCCESS
				}
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  fmt.Sprintf("%v for GPU UUID: %q", NvmlDeviceGetArchitectureFailed, test.TestUUID),
				ReturnCode: nvml.ERROR_UNKNOWN,
			},
		},
		{
			name:  "device_attestation_report_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.DeviceGetHandleByIndexFunc = func(index int) (nvml.Device, nvml.Return) {
					gpuDevice := test.DefaultMockGpuDevice()
					gpuDevice.GetConfComputeGpuAttestationReportFunc = test.NvmlErrorGetConfComputeGpuAttestationReportFunc
					return gpuDevice, nvml.SUCCESS
				}
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  fmt.Sprintf("%v for GPU UUID: %q", NvmlDeviceGetConfComputeGpuAttestationReportFailed, test.TestUUID),
				ReturnCode: nvml.ERROR_UNKNOWN,
			},
		},
		{
			name:  "device_certificate_chain_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.DeviceGetHandleByIndexFunc = func(index int) (nvml.Device, nvml.Return) {
					gpuDevice := test.DefaultMockGpuDevice()
					gpuDevice.GetConfComputeGpuCertificateFunc = test.NvmlErrorGetConfComputeGpuCertificateFunc
					return gpuDevice, nvml.SUCCESS
				}
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  fmt.Sprintf("%v for GPU UUID: %q", NvmlDeviceGetConfComputeGpuCertificateFailed, test.TestUUID),
				ReturnCode: nvml.ERROR_UNKNOWN,
			},
		},
		{
			name:  "shutdown_error",
			nonce: testdata.Nonce,
			nvmlInterfaceFunc: func() nvml.Interface {
				gpuInterface := test.DefaultMockGpuInterface()
				gpuInterface.ShutdownFunc = test.NvmlErrorShutdownFunc
				return gpuInterface
			},
			gpuQuote: nil,
			wantErr: &LibError{
				Operation:  NvmlLibraryShutdownFailed,
				ReturnCode: nvml.ERROR_UNKNOWN,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gpuQuoteProvider := &LinuxGpuQuoteProvider{
				nvmlFactory: func(opts ...nvml.LibraryOption) nvml.Interface {
					return tc.nvmlInterfaceFunc()
				},
			}
			got, err := GpuQuote(gpuQuoteProvider, tc.nonce)
			if diff := cmp.Diff(tc.wantErr, err, cmp.AllowUnexported(LibError{}, NilLibInterfaceError{})); diff != "" {
				t.Fatalf("GpuQuote(%v) = %v, want %v", tc.nonce, err, tc.wantErr)
			}
			if tc.wantErr == nil {
				if diff := cmp.Diff(got, tc.gpuQuote, protocmp.Transform()); diff != "" {
					t.Errorf("GpuQuote(%v) = %v, want %v (diff -want, +got): %v", tc.nonce, got, tc.gpuQuote, diff)
				}
			}
		})
	}
}

func TestSwitchQuote(t *testing.T) {

	testCases := []struct {
		name              string
		nonce             [32]byte
		nscqInterfaceFunc func() nscq.Interface
		switchQuote       *pb.SwitchAttestationQuote
		wantErr           error
	}{
		{
			name:  "valid_switch_quote",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				return test.DefaultMockSwitchInterface()
			},
			switchQuote: &pb.SwitchAttestationQuote{
				SwitchInfos: []*pb.SwitchInfo{
					&pb.SwitchInfo{
						Uuid:                        test.TestUUID,
						AttestationCertificateChain: testdata.SwitchAttestationCertificateChain[:test.TestAttestationCertChainSize],
						AttestationReport:           testdata.RawSwitchAttestationReportTestData.RawAttestationReport[:test.TestSwitchAttestationReportSize],
					},
				},
			},
			wantErr: nil,
		},
		{
			name:  "nil_nscq_interface",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				return nil
			},
			wantErr: &NilLibInterfaceError{lib: "NSCQ"},
		},
		{
			name:  "init_error",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				nscqInterface := test.DefaultMockSwitchInterface()
				nscqInterface.InitFunc = func() nscq.Return {
					return nscq.ErrorLibraryNotLoaded
				}
				return nscqInterface
			},
			switchQuote: nil,
			wantErr: &LibError{
				Operation:  NscqLibraryInitFailed,
				ReturnCode: nscq.ErrorLibraryNotLoaded,
			},
		},
		{
			name:  "session_create_error",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				nscqInterface := test.DefaultMockSwitchInterface()
				nscqInterface.SessionCreateFunc = func(uint32) (*nscq.Session, nscq.Return) {
					return nil, nscq.ErrorUnspecified
				}
				return nscqInterface
			},
			switchQuote: nil,
			wantErr: &LibError{
				Operation:  NscqSessionCreateFailed,
				ReturnCode: nscq.ErrorUnspecified,
			},
		},
		{
			name:  "switch_device_uuids_error",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				nscqInterface := test.DefaultMockSwitchInterface()
				nscqInterface.SwitchDeviceUUIDsFunc = func(session *nscq.Session) ([]string, nscq.Return) {
					return nil, nscq.ErrorUnspecified
				}
				return nscqInterface
			},
			switchQuote: nil,
			wantErr: &LibError{
				Operation:  NscqSwitchDeviceUUIDsFailed,
				ReturnCode: nscq.ErrorUnspecified,
			},
		},
		{
			name:  "switch_device_uuids_empty",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				nscqInterface := test.DefaultMockSwitchInterface()
				nscqInterface.SwitchDeviceUUIDsFunc = func(session *nscq.Session) ([]string, nscq.Return) {
					return []string{}, nscq.Success
				}
				return nscqInterface
			},
			switchQuote: nil,
			wantErr:     &NoSwitchDevicesError{},
		},
		{
			name:  "device_attestation_report_error",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				nscqInterface := test.DefaultMockSwitchInterface()
				nscqInterface.SwitchAttestationReportFunc = func(session *nscq.Session, nonce [32]uint8, uuid string) ([]uint8, nscq.Return) {
					return nil, nscq.ErrorUnspecified
				}
				return nscqInterface
			},
			switchQuote: nil,
			wantErr: &LibError{
				Operation:  fmt.Sprintf("%v for switch UUID: %q", NscqSwitchAttestationReportFailed, test.TestUUID),
				ReturnCode: nscq.ErrorUnspecified,
			},
		},
		{
			name:  "device_certificate_chain_error",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				nscqInterface := test.DefaultMockSwitchInterface()
				nscqInterface.SwitchAttestationCertificateChainFunc = func(session *nscq.Session, uuid string) ([]uint8, nscq.Return) {
					return nil, nscq.ErrorUnspecified
				}
				return nscqInterface
			},
			switchQuote: nil,
			wantErr: &LibError{
				Operation:  fmt.Sprintf("%v for switch UUID: %q", NscqSwitchAttestationCertificateChainFailed, test.TestUUID),
				ReturnCode: nscq.ErrorUnspecified,
			},
		},
		{
			name:  "session_destroy_error",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				nscqInterface := test.DefaultMockSwitchInterface()
				nscqInterface.SessionDestroyFunc = func(session *nscq.Session) nscq.Return {
					return nscq.ErrorUnspecified
				}
				return nscqInterface
			},
			switchQuote: nil,
			wantErr: &LibError{
				Operation:  NscqSessionDestroyFailed,
				ReturnCode: nscq.ErrorUnspecified,
			},
		},
		{
			name:  "shutdown_error",
			nonce: testdata.Nonce,
			nscqInterfaceFunc: func() nscq.Interface {
				nscqInterface := test.DefaultMockSwitchInterface()
				nscqInterface.ShutdownFunc = func() nscq.Return {
					return nscq.ErrorUnspecified
				}
				return nscqInterface
			},
			switchQuote: nil,
			wantErr: &LibError{
				Operation:  NscqLibraryShutdownFailed,
				ReturnCode: nscq.ErrorUnspecified,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			switchQuoteProvider := &LinuxSwitchQuoteProvider{
				nscqFactory: func(opts ...nscq.LibraryOption) nscq.Interface {
					return tc.nscqInterfaceFunc()
				},
			}
			got, err := SwitchQuote(switchQuoteProvider, tc.nonce)
			if diff := cmp.Diff(tc.wantErr, err, cmp.AllowUnexported(LibError{}, NilLibInterfaceError{})); diff != "" {
				t.Fatalf("SwitchQuote(%v) = %v, want %v", tc.nonce, err, tc.wantErr)
			}
			if tc.wantErr == nil {
				if diff := cmp.Diff(got, tc.switchQuote, protocmp.Transform()); diff != "" {
					t.Errorf("SwitchQuote(%v) = %v, want %v (diff -want, +got): %v", tc.nonce, got, tc.switchQuote, diff)
				}
			}
		})
	}
}
