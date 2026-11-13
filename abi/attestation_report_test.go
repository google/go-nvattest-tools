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

package abi

import (
	"testing"

	"github.com/google/go-nvattest-tools/testing/testdata"
)

// fixtureFor maps a fuzz input's type selector to the attestation type and
// the known-good report that seeds it.
func fixtureFor(isSwitch bool) (AttestationType, testdata.RawAttestationReportTestData) {
	if isSwitch {
		return SWITCH, testdata.RawSwitchAttestationReportTestData
	}
	return GPU, testdata.RawGpuAttestationReportTestData
}

// FuzzRawAttestationReportToProto feeds bytes to the attestation report parser
// and parses the feature flag of each report that the parser accepts.
func FuzzRawAttestationReportToProto(f *testing.F) {
	for _, isSwitch := range []bool{false, true} {
		_, td := fixtureFor(isSwitch)
		f.Add(isSwitch, td.RawAttestationReport)
		f.Add(isSwitch, td.RawAttestationReport[:SpdmRequestSize])
		f.Add(isSwitch, td.RawAttestationReport[:SpdmRequestSize+SpdmMeasurementResponseHeaderSize])
	}
	for _, gpu := range testdata.MptAttestationDataSet.GpuAttestationQuote.GetGpuInfos() {
		f.Add(false, gpu.GetAttestationReport())
	}

	f.Fuzz(func(t *testing.T, isSwitch bool, data []byte) {
		at, _ := fixtureFor(isSwitch)
		report, err := RawAttestationReportToProto(data, at)
		if (err == nil) == (report == nil) {
			t.Errorf("RawAttestationReportToProto(data, %v) = %v, %v; want exactly one non-nil", at, report, err)
		}
		if err == nil {
			ParseFeatureFlag(report)
		}
	})
}
