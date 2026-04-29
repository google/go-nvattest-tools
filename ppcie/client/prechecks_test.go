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
	"testing"

	attestclient "github.com/google/go-nvattest-tools/client"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/NVIDIA/go-nvml/pkg/nvml/mock"
	"github.com/NVIDIA/go-nvml/pkg/nvml"
	nscqmock "github.com/google/go-nvattest-tools/internal/nvnscq/pkg/nscq/mock"
	"github.com/google/go-nvattest-tools/internal/nvnscq/pkg/nscq"
)

// newSuccessMockNvml creates a mock pre-configured for the happy path.
// This avoids redefining the success case in every test.
func newSuccessMockNvml(expectedGpuCount int) *mock.Interface {
	return &mock.Interface{
		InitFunc: func() nvml.Return { return nvml.SUCCESS },
		DeviceGetCountFunc: func() (int, nvml.Return) {
			return expectedGpuCount, nvml.SUCCESS
		},
		SystemGetConfComputeSettingsFunc: func() (nvml.SystemConfComputeSettings, nvml.Return) {
			return nvml.SystemConfComputeSettings{MultiGpuMode: 1}, nvml.SUCCESS
		},
		ShutdownFunc: func() nvml.Return { return nvml.SUCCESS },
	}
}

func TestPerformGPUPreChecks(t *testing.T) {
	ctx := t.Context()
	defaultOpts := &Options{ExpectedGpuCount: 8}

	testCases := []struct {
		name string
		opts *Options
		// setupMock allows each test case to modify the default success mock.
		setupMock func(m *mock.Interface)
		wantErrs  []error
	}{
		{
			name: "success",
			opts: defaultOpts,
			// No setup needed; the default mock is perfect for the success case.
		},
		{
			name: "init_failure",
			opts: defaultOpts,
			setupMock: func(m *mock.Interface) {
				m.InitFunc = func() nvml.Return { return nvml.ERROR_UNINITIALIZED }
			},
			wantErrs: []error{&attestclient.LibError{Operation: "initialize NVML", ReturnCode: nvml.ERROR_UNINITIALIZED}},
		},
		{
			name: "shutdown_failure_propagates_error",
			opts: defaultOpts,
			setupMock: func(m *mock.Interface) {
				m.ShutdownFunc = func() nvml.Return { return nvml.ERROR_UNINITIALIZED }
			},
			wantErrs: []error{&attestclient.LibError{Operation: "shutdown NVML", ReturnCode: nvml.ERROR_UNINITIALIZED}},
		},
		{
			name: "multiple_errors",
			opts: defaultOpts,
			setupMock: func(m *mock.Interface) {
				m.DeviceGetCountFunc = func() (int, nvml.Return) { return 0, nvml.ERROR_UNKNOWN }
				m.SystemGetConfComputeSettingsFunc = func() (nvml.SystemConfComputeSettings, nvml.Return) {
					return nvml.SystemConfComputeSettings{}, nvml.ERROR_UNKNOWN
				}
			},
			wantErrs: []error{
				&attestclient.LibError{Operation: "get GPU count", ReturnCode: nvml.ERROR_UNKNOWN},
				&attestclient.LibError{Operation: "get system-wide TNVL mode", ReturnCode: nvml.ERROR_UNKNOWN},
			},
		},
		{
			name: "device_get_count_failure",
			opts: defaultOpts,
			setupMock: func(m *mock.Interface) {
				m.DeviceGetCountFunc = func() (int, nvml.Return) { return 0, nvml.ERROR_UNKNOWN }
			},
			wantErrs: []error{&attestclient.LibError{Operation: "get GPU count", ReturnCode: nvml.ERROR_UNKNOWN}},
		},
		{
			name: "gpu_count_mismatch",
			opts: defaultOpts, // Expects 8 GPUs
			setupMock: func(m *mock.Interface) {
				// But the mock returns 4.
				m.DeviceGetCountFunc = func() (int, nvml.Return) { return 4, nvml.SUCCESS }
			},
			wantErrs: []error{&GpuCountMismatchError{Want: 8, Got: 4}},
		},
		{
			name: "get_settings_failure",
			opts: defaultOpts,
			setupMock: func(m *mock.Interface) {
				m.SystemGetConfComputeSettingsFunc = func() (nvml.SystemConfComputeSettings, nvml.Return) {
					return nvml.SystemConfComputeSettings{}, nvml.ERROR_UNKNOWN
				}
			},
			wantErrs: []error{&attestclient.LibError{Operation: "get system-wide TNVL mode", ReturnCode: nvml.ERROR_UNKNOWN}},
		},
		{
			name: "tnvl_disabled",
			opts: defaultOpts,
			setupMock: func(m *mock.Interface) {
				m.SystemGetConfComputeSettingsFunc = func() (nvml.SystemConfComputeSettings, nvml.Return) {
					return nvml.SystemConfComputeSettings{MultiGpuMode: 0}, nvml.SUCCESS
				}
			},
			wantErrs: []error{&GpuTnvlDisabledError{}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Start with a fresh "happy path" mock for each test.
			mockAPI := newSuccessMockNvml(tc.opts.ExpectedGpuCount)
			if tc.setupMock != nil {
				// Apply the test-specific modifications.
				tc.setupMock(mockAPI)
			}
			p := &Prechecker{
				NVML: mockAPI,
			}

			// Act
			errs := p.performGPUPreChecks(ctx, tc.opts)

			// Assert
			if diff := cmp.Diff(tc.wantErrs, errs, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("performGPUPreChecks(%v) returned incorrect set of errors (-want +got):\n%s", tc.opts, diff)
			}
		})
	}
}

// newSuccessMockNscq creates a mock pre-configured for the happy path.
func newSuccessMockNscq(expectedSwitchCount int) *nscqmock.Interface {
	uuids := make([]string, expectedSwitchCount)
	for i := 0; i < expectedSwitchCount; i++ {
		uuids[i] = fmt.Sprintf("fake-uuid-%d", i)
	}
	return &nscqmock.Interface{
		InitFunc: func() nscq.Return { return nscq.Success },
		SessionCreateFunc: func(flags uint32) (*nscq.Session, nscq.Return) {
			return &nscq.Session{}, nscq.Success
		},
		SwitchDeviceUUIDsFunc: func(session *nscq.Session) ([]string, nscq.Return) {
			return uuids, nscq.Success
		},
		SwitchPCIEModeFunc: func(session *nscq.Session, uuid string) (int8, nscq.Return) {
			return 3, nscq.Success
		},
		SessionDestroyFunc: func(session *nscq.Session) nscq.Return { return nscq.Success },
		ShutdownFunc:       func() nscq.Return { return nscq.Success },
	}
}

func TestPerformNvSwitchPreChecks(t *testing.T) {
	ctx := t.Context()
	defaultOpts := &Options{ExpectedSwitchCount: 4}

	testCases := []struct {
		name      string
		opts      *Options
		setupMock func(m nscq.Interface)
		wantErrs  []error
	}{
		{
			name: "success",
			opts: defaultOpts,
		},
		{
			name: "init_failure",
			opts: defaultOpts,
			setupMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).InitFunc = func() nscq.Return { return nscq.ErrorLibraryNotLoaded }
			},
			wantErrs: []error{&attestclient.LibError{Operation: "initialize NSCQ", ReturnCode: nscq.ErrorLibraryNotLoaded}},
		},
		{
			name: "shutdown_failure_propagates_error",
			opts: defaultOpts,
			setupMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).ShutdownFunc = func() nscq.Return { return nscq.ErrorLibraryNotLoaded }
			},
			wantErrs: []error{&attestclient.LibError{Operation: "shutdown NSCQ", ReturnCode: nscq.ErrorLibraryNotLoaded}},
		},
		{
			name: "multiple_errors",
			opts: defaultOpts,
			setupMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).SwitchDeviceUUIDsFunc = func(*nscq.Session) ([]string, nscq.Return) {
					return []string{"fake-uuid-0", "fake-uuid-1"}, nscq.Success
				}
				m.(*nscqmock.Interface).SwitchPCIEModeFunc = func(*nscq.Session, string) (int8, nscq.Return) {
					return 0, nscq.ErrorUnspecified
				}
			},
			wantErrs: []error{
				&NvSwitchCountMismatchError{Want: 4, Got: 2},
				&attestclient.LibError{Operation: "get PCIe mode for NVSwitch fake-uuid-0", ReturnCode: nscq.ErrorUnspecified},
				&attestclient.LibError{Operation: "get PCIe mode for NVSwitch fake-uuid-1", ReturnCode: nscq.ErrorUnspecified},
			},
		},
		{
			name: "session_create_failure",
			opts: defaultOpts,
			setupMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).SessionCreateFunc = func(uint32) (*nscq.Session, nscq.Return) {
					return nil, nscq.ErrorUnspecified
				}
			},
			wantErrs: []error{&attestclient.LibError{Operation: "create NSCQ session", ReturnCode: nscq.ErrorUnspecified}},
		},
		{
			name: "session_destroy_failure_propagates_error",
			opts: defaultOpts,
			setupMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).SessionDestroyFunc = func(*nscq.Session) nscq.Return {
					return nscq.ErrorUnspecified
				}
			},
			wantErrs: []error{&attestclient.LibError{Operation: "destroy NSCQ session", ReturnCode: nscq.ErrorUnspecified}},
		},
		{
			name: "get_all_device_uuids_failure_also_causes_count_mismatch",
			opts: defaultOpts,
			setupMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).SwitchDeviceUUIDsFunc = func(*nscq.Session) ([]string, nscq.Return) {
					return nil, nscq.ErrorUnspecified
				}
			},
			wantErrs: []error{
				&attestclient.LibError{Operation: "get all device UUIDs", ReturnCode: nscq.ErrorUnspecified},
				&NvSwitchCountMismatchError{Want: 4, Got: 0},
			},
		},
		{
			name: "switch_count_mismatch",
			opts: defaultOpts, // Expects 4 switches
			setupMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).SwitchDeviceUUIDsFunc = func(*nscq.Session) ([]string, nscq.Return) {
					return make([]string, 2), nscq.Success // But mock returns 2
				}
			},
			wantErrs: []error{&NvSwitchCountMismatchError{Want: 4, Got: 2}},
		},
		{
			name: "get_pcie_mode_failure",
			opts: defaultOpts,
			setupMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).SwitchPCIEModeFunc = func(*nscq.Session, string) (int8, nscq.Return) {
					return 0, nscq.ErrorUnspecified
				}
			},
			wantErrs: []error{
				&attestclient.LibError{Operation: "get PCIe mode for NVSwitch fake-uuid-0", ReturnCode: nscq.ErrorUnspecified},
				&attestclient.LibError{Operation: "get PCIe mode for NVSwitch fake-uuid-1", ReturnCode: nscq.ErrorUnspecified},
				&attestclient.LibError{Operation: "get PCIe mode for NVSwitch fake-uuid-2", ReturnCode: nscq.ErrorUnspecified},
				&attestclient.LibError{Operation: "get PCIe mode for NVSwitch fake-uuid-3", ReturnCode: nscq.ErrorUnspecified},
			},
		},
		{
			name: "tnvl_disabled",
			opts: defaultOpts,
			setupMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).SwitchPCIEModeFunc = func(_ *nscq.Session, uuid string) (int8, nscq.Return) {
					if uuid == "fake-uuid-1" {
						return 1, nscq.Success // Incorrect mode
					}
					return 3, nscq.Success
				}
			},
			wantErrs: []error{&NvSwitchTnvlDisabledError{UUID: "fake-uuid-1", Mode: 1}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockAPI := newSuccessMockNscq(tc.opts.ExpectedSwitchCount)
			if tc.setupMock != nil {
				tc.setupMock(mockAPI)
			}
			p := &Prechecker{
				NSCQ: mockAPI,
			}

			errs := p.performNvSwitchPreChecks(ctx, tc.opts)

			if diff := cmp.Diff(tc.wantErrs, errs, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("performNvSwitchPreChecks(%v) returned incorrect set of errors (-want +got):\n%s", tc.opts, diff)
			}
		})
	}
}

func TestPrecheck(t *testing.T) {
	ctx := t.Context()
	defaultOpts := &Options{ExpectedGpuCount: 8, ExpectedSwitchCount: 4}

	testCases := []struct {
		name          string
		setupNvmlMock func(m *mock.Interface)
		setupNscqMock func(m nscq.Interface)
		wantErr       error
	}{
		{
			name: "gpu_prechecks_fail",
			setupNvmlMock: func(m *mock.Interface) {
				m.InitFunc = func() nvml.Return { return nvml.ERROR_UNINITIALIZED }
			},
			wantErr: fmt.Errorf("pre-validation checks failed: %s", (&attestclient.LibError{Operation: "initialize NVML", ReturnCode: nvml.ERROR_UNINITIALIZED}).Error()),
		},
		{
			name: "nvswitch_prechecks_fail",
			setupNscqMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).InitFunc = func() nscq.Return { return nscq.ErrorLibraryNotLoaded }
			},
			wantErr: fmt.Errorf("pre-validation checks failed: %s", (&attestclient.LibError{Operation: "initialize NSCQ", ReturnCode: nscq.ErrorLibraryNotLoaded}).Error()),
		},
		{
			name: "gpu_and_nvswitch_prechecks_fail",
			setupNvmlMock: func(m *mock.Interface) {
				m.InitFunc = func() nvml.Return { return nvml.ERROR_UNINITIALIZED }
			},
			setupNscqMock: func(m nscq.Interface) {
				m.(*nscqmock.Interface).InitFunc = func() nscq.Return { return nscq.ErrorLibraryNotLoaded }
			},
			wantErr: fmt.Errorf("pre-validation checks failed: %s\n%s",
				(&attestclient.LibError{Operation: "initialize NVML", ReturnCode: nvml.ERROR_UNINITIALIZED}).Error(),
				(&attestclient.LibError{Operation: "initialize NSCQ", ReturnCode: nscq.ErrorLibraryNotLoaded}).Error(),
			),
		},
		{
			name: "success",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nvmlMock := newSuccessMockNvml(defaultOpts.ExpectedGpuCount)
			if tc.setupNvmlMock != nil {
				tc.setupNvmlMock(nvmlMock)
			}

			nscqMock := newSuccessMockNscq(defaultOpts.ExpectedSwitchCount)
			if tc.setupNscqMock != nil {
				tc.setupNscqMock(nscqMock)
			}

			p := &Prechecker{
				NVML: nvmlMock,
				NSCQ: nscqMock,
			}

			err := p.Precheck(ctx, defaultOpts)

			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("Precheck(%v) returned error %v, want nil", defaultOpts, err)
				}
			} else {
				if err == nil || err.Error() != tc.wantErr.Error() {
					t.Errorf("Precheck(%v) returned error %v, want %v", defaultOpts, err, tc.wantErr)
				}
			}
		})
	}
}

func TestDefaultPrechecker(t *testing.T) {
	p := DefaultPrechecker()
	if p == nil {
		t.Fatal("DefaultPrechecker() returned nil")
	}
	if p.NVML == nil {
		t.Error("DefaultPrechecker() returned Prechecker with nil NVML")
	}
	if p.NSCQ == nil {
		t.Error("DefaultPrechecker() returned Prechecker with nil NSCQ")
	}
}

func TestPackagePrecheck(t *testing.T) {
	// This test covers the package-level Precheck function which uses DefaultPrechecker.
	// Since this uses the real NVML/NSCQ implementations, we expect it to fail in the
	// test environment (due to missing hardware/libraries), but it should not panic.
	ctx := t.Context()
	opts := &Options{
		ExpectedGpuCount:    8,
		ExpectedSwitchCount: 4,
	}

	err := Precheck(ctx, opts)
	if err == nil {
		t.Log("Precheck succeeded (unexpected but acceptable)")
	} else {
		t.Logf("Precheck failed as expected in test env: %v", err)
	}
}
