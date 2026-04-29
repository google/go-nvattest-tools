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

// GpuTnvlDisabledError indicates that the system is not in multi-GPU TNVL mode.
type GpuTnvlDisabledError struct{}

func (e *GpuTnvlDisabledError) Error() string {
	return "PPCIE: system not in required multi-GPU TNVL mode"
}

// GpuCountMismatchError indicates that the number of GPUs on the system does not match the expected count.
type GpuCountMismatchError struct {
	Want int
	Got  int
}

func (e *GpuCountMismatchError) Error() string {
	return fmt.Sprintf("mismatched GPU count: want %d, got %d", e.Want, e.Got)
}

// NvSwitchCountMismatchError indicates that the number of NVSwitches on the system does not match the expected count.
type NvSwitchCountMismatchError struct {
	Want int
	Got  int
}

func (e *NvSwitchCountMismatchError) Error() string {
	return fmt.Sprintf("mismatched NVSwitch count: want %d, got %d", e.Want, e.Got)
}

// NvSwitchTnvlDisabledError indicates that an NVSwitch is not in the required TNVL mode.
type NvSwitchTnvlDisabledError struct {
	UUID string
	Mode int8
}

func (e *NvSwitchTnvlDisabledError) Error() string {
	return fmt.Sprintf("NVSwitch %s not in required TNVL mode: got mode %d, want mode 3 (TNVL enabled and locked)", e.UUID, e.Mode)
}
