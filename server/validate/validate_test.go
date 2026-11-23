package validate

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-nvattest-tools/abi"
	"github.com/google/go-nvattest-tools/server/rim"
	"github.com/google/go-nvattest-tools/server/utility"
	testdata "github.com/google/go-nvattest-tools/testing/testdata"
	test "github.com/google/go-nvattest-tools/testing"
	"github.com/stretchr/testify/require"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
)

var testGpuGoldenMeasurementsValues = map[int]rim.GoldenMeasurement{
	3: rim.GoldenMeasurement{
		Values:       []string{"73bbf35822549e28ba8fb2671fb7b58f46424a0069205b3ecf1d0fa762adef90b538cc9d692eb5c050147f2f1e8214ab"},
		Index:        3,
		Alternatives: 1,
		Size:         48,
		Active:       true,
	},
	9: rim.GoldenMeasurement{
		Values:       []string{"059b32e712a153f490dbfb7976a9e275d789e28bd4803c357def2b6123327c430526bfaecc200f496d4e149fc5eade03"},
		Index:        9,
		Alternatives: 1,
		Size:         48,
		Active:       true,
	},
	11: rim.GoldenMeasurement{
		Values:       []string{"b78e1d1ce915550eef32922eed060abfca6556aebde3d1b728b157b79c93b00620a5e14132fb3b75bb7084c0a88695c0"},
		Index:        11,
		Alternatives: 1,
		Size:         48,
		Active:       true,
	},
	12: rim.GoldenMeasurement{
		Values: []string{
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"758af96044c700f98a85347be27124d51c05b8784ba216b629b9aaab6d538c759aed9922a133e4ac473564d359b271d5",
			"7df046f26d0536f3a0b06d288ce6e5c659cad7a9c45cbd3a82c5df248755e4ddeff5871045acc6366ccab178b0d6568e",
			"cb09606fa5c052f0bc4cfa86dbeb4e3e70500bfbeeb7193256ac24ed4464a607366df16a3547b7c17ebd741eb43f1adf",
		},
		Index:        12,
		Alternatives: 4,
		Size:         48,
		Active:       true,
	},
	13: rim.GoldenMeasurement{
		Values:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
		Index:        13,
		Alternatives: 1,
		Size:         48,
		Active:       false,
	},
	14: rim.GoldenMeasurement{
		Values:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
		Index:        14,
		Alternatives: 1,
		Size:         48,
		Active:       false,
	},
	21: rim.GoldenMeasurement{
		Values:       []string{"29a210939024df30808819c8022d92639497d7b689afb9228725d0d8f29347c395f34813866814180e835daf0b39db6d"},
		Index:        21,
		Alternatives: 1,
		Size:         48,
		Active:       true,
	},
	35: rim.GoldenMeasurement{
		Values:       []string{"c0962ed90316ecea959dd0b6632d0c4f4d3bfbf72c4cd9031efe48154ed9ca59b41cd20ce06a7f9ca5cd8b0687cf1258"},
		Index:        35,
		Alternatives: 1,
		Size:         48,
		Active:       true,
	},
	40: rim.GoldenMeasurement{
		Values:       []string{"0d2c6389c070dde430ffd510cad0c546fb9a73b9ee7a478fa804d2ab14c674487abdc7aa12d90215ced4f3678f2765fa"},
		Index:        40,
		Alternatives: 1,
		Size:         48,
		Active:       true,
	},
}

var testSwitchGoldenMeasurementsValues = map[int]rim.GoldenMeasurement{
	13: rim.GoldenMeasurement{
		Values:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
		Index:        13,
		Alternatives: 1,
		Size:         48,
		Active:       false,
	},
	21: rim.GoldenMeasurement{
		Values:       []string{"adbc0cdbd5c945de0e2c38c1ad4a4af0fb6bf1f3fea7a5cd9e6f3004ac91b44c239c6f7e06d8a8f50c7b4eaef3e388b5"},
		Index:        21,
		Alternatives: 1,
		Size:         48,
		Active:       true,
	},
}

func TestDoMeasurementsMatch(t *testing.T) {
	defaultGpuAttestationReportFunc := func() *pb.AttestationReport {
		report, _ := abi.RawAttestationReportToProto(testdata.RawGpuAttestationReportTestData.RawAttestationReport, abi.GPU)
		return report
	}

	defaultSwitchAttestationReportFunc := func() *pb.AttestationReport {
		report, _ := abi.RawAttestationReportToProto(testdata.RawSwitchAttestationReportTestData.RawAttestationReport, abi.SWITCH)
		return report
	}

	testcases := []struct {
		name                     string
		driverGoldenMeasurements []rim.GoldenMeasurement
		vbiosGoldenMeasurements  []rim.GoldenMeasurement
		attestationReportFunc    func() *pb.AttestationReport
		attestationType          abi.AttestationType
		wantErr                  error
	}{
		{
			name: "valid_match_gpu",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[3],
				testGpuGoldenMeasurementsValues[9],
				testGpuGoldenMeasurementsValues[14],
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[12],
				testGpuGoldenMeasurementsValues[13],
			},
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			wantErr:               nil,
		},
		{
			name: "valid_match_switch",
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				testSwitchGoldenMeasurementsValues[13],
				testSwitchGoldenMeasurementsValues[21],
			},
			attestationReportFunc: defaultSwitchAttestationReportFunc,
			attestationType:       abi.SWITCH,
			wantErr:               nil,
		},
		{
			name: "nvdec0_status_disabled_skipMSRpMttruepu",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[msr35Index],
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{},
			attestationReportFunc: func() *pb.AttestationReport {
				return &pb.AttestationReport{
					SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
						MeasurementRecord: &pb.MeasurementRecord{
							MeasurementBlocks: []*pb.MeasurementBlock{
								{
									Index: msr35Index + 1,
									DmtfMeasurement: &pb.DmtfMeasurement{
										Value: []byte("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
									},
								},
							},
						},
						OpaqueData: &pb.OpaqueData{
							OpaqueFieldData: []*pb.OpaqueFieldData{
								{
									DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_NVDEC0_STATUS,
									Data:     &pb.OpaqueFieldData_Value{Value: []byte(disabledMsr35Value)},
								},
							},
						},
					},
				}
			},
			attestationType: abi.GPU,
			wantErr:         nil,
		},
		{
			name: "nvdec0_status_disabled_skipMSRpMfalse_switch",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[msr35Index],
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{},
			attestationReportFunc: func() *pb.AttestationReport {
				return &pb.AttestationReport{
					SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
						MeasurementRecord: &pb.MeasurementRecord{
							MeasurementBlocks: []*pb.MeasurementBlock{
								{
									Index: msr35Index + 1,
									DmtfMeasurement: &pb.DmtfMeasurement{
										Value: []byte("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
									},
								},
							},
						},
						OpaqueData: &pb.OpaqueData{
							OpaqueFieldData: []*pb.OpaqueFieldData{
								{
									DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_NVDEC0_STATUS,
									Data:     &pb.OpaqueFieldData_Value{Value: []byte(disabledMsr35Value)},
								},
							},
						},
					},
				}
			},
			attestationType: abi.SWITCH,
			wantErr:         &MismatchedMeasurementsError{[]mismatchedMeasurement{{index: 35, goldenMeasurementValues: testGpuGoldenMeasurementsValues[35].Values, runtimeMeasurementValue: "303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030"}}},
		},
		{
			name: "nvdec0_status_enabled_skipMSRpMffalse_gpu",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[msr35Index],
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{},
			attestationReportFunc: func() *pb.AttestationReport {
				return &pb.AttestationReport{
					SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
						MeasurementRecord: &pb.MeasurementRecord{
							MeasurementBlocks: []*pb.MeasurementBlock{
								{
									Index: msr35Index + 1,
									DmtfMeasurement: &pb.DmtfMeasurement{
										Value: []byte("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
									},
								},
							},
						},
						OpaqueData: &pb.OpaqueData{
							OpaqueFieldData: []*pb.OpaqueFieldData{
								{
									DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_NVDEC0_STATUS,
									Data:     &pb.OpaqueFieldData_Value{Value: []byte("\xAA")},
								},
							},
						},
					},
				}
			},
			attestationType: abi.GPU,
			wantErr:         &MismatchedMeasurementsError{[]mismatchedMeasurement{{index: 35, goldenMeasurementValues: testGpuGoldenMeasurementsValues[35].Values, runtimeMeasurementValue: "303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030"}}},
		},
		{
			name: "vpr_disabled_skipMSRpMffalse_gpu",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[msr35Index],
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{},
			attestationReportFunc: func() *pb.AttestationReport {
				return &pb.AttestationReport{
					SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
						MeasurementRecord: &pb.MeasurementRecord{
							MeasurementBlocks: []*pb.MeasurementBlock{
								{
									Index: msr35Index + 1,
									DmtfMeasurement: &pb.DmtfMeasurement{
										Value: []byte("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
									},
								},
							},
						},
						OpaqueData: &pb.OpaqueData{
							OpaqueFieldData: []*pb.OpaqueFieldData{
								{
									DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VPR,
									Data:     &pb.OpaqueFieldData_Value{Value: []byte(disabledMsr35Value)},
								},
							},
						},
					},
				}
			},
			attestationType: abi.GPU,
			wantErr:         &MismatchedMeasurementsError{[]mismatchedMeasurement{{index: 35, goldenMeasurementValues: testGpuGoldenMeasurementsValues[35].Values, runtimeMeasurementValue: "303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030"}}},
		},
		{
			name: "multiple_measurements_with_same_index_error",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[3],
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[3],
			},
			attestationReportFunc: func() *pb.AttestationReport {
				return &pb.AttestationReport{
					SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
						MeasurementRecord: &pb.MeasurementRecord{
							MeasurementBlocks: []*pb.MeasurementBlock{
								{
									Index: 3,
									DmtfMeasurement: &pb.DmtfMeasurement{
										Value: []byte("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
									},
								},
							},
						},
					},
				}
			},
			attestationType: abi.GPU,
			wantErr:         &MultipleMeasurementsWithSameIndexError{index: 3},
		},
		{
			name:                     "no_golden_measurements_error",
			driverGoldenMeasurements: []rim.GoldenMeasurement{},
			vbiosGoldenMeasurements:  []rim.GoldenMeasurement{},
			attestationReportFunc:    defaultGpuAttestationReportFunc,
			attestationType:          abi.GPU,
			wantErr:                  &NoMeasurementsError{measurementType: "golden", dataSource: "RIM"},
		},
		{
			name: "no_runtime_measurements_error",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[3],
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[12],
			},
			attestationReportFunc: func() *pb.AttestationReport {
				return &pb.AttestationReport{
					SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
						MeasurementRecord: &pb.MeasurementRecord{
							MeasurementBlocks: []*pb.MeasurementBlock{},
						},
					},
				}
			},
			attestationType: abi.GPU,
			wantErr:         &NoMeasurementsError{measurementType: "runtime", dataSource: "attestation report"},
		},
		{
			name: "invalid_comparison_error",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[3],
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[12],
			},
			attestationReportFunc: func() *pb.AttestationReport {
				return &pb.AttestationReport{
					SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
						MeasurementRecord: &pb.MeasurementRecord{
							MeasurementBlocks: []*pb.MeasurementBlock{
								{
									Index: 3,
									DmtfMeasurement: &pb.DmtfMeasurement{
										Value: []byte("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
									},
								},
							},
						},
					},
				}
			},
			attestationType: abi.GPU,
			wantErr:         &InvalidComparisonError{},
		},
		{
			name: "mismatch_error",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[40],
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				testGpuGoldenMeasurementsValues[11],
			},
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			wantErr:               &MismatchedMeasurementsError{[]mismatchedMeasurement{{index: 11, goldenMeasurementValues: testGpuGoldenMeasurementsValues[11].Values, runtimeMeasurementValue: "413d008cedd5526a79455a178154328ce960af252bdb06e7fe4080049add412488cac39ecf3d80efbdc6bdd363861773"}, {index: 40, goldenMeasurementValues: testGpuGoldenMeasurementsValues[40].Values, runtimeMeasurementValue: "9d2c6389c070dde430ffd510cad0c546fb9a73b9ee7a478fa804d2ab14c674487abdc7aa12d90215ced4f3678f2765fa"}}},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			goldenMeasurements := map[RimType][]rim.GoldenMeasurement{
				Driver: tc.driverGoldenMeasurements,
				VBios:  tc.vbiosGoldenMeasurements,
			}
			got := doMeasurementsMatch(tc.attestationReportFunc(), Options{AttestationType: tc.attestationType, goldenMeasurements: goldenMeasurements})
			if diff := cmp.Diff(tc.wantErr, got, cmp.AllowUnexported(MismatchedMeasurementsError{}, mismatchedMeasurement{}, MultipleMeasurementsWithSameIndexError{}, NoMeasurementsError{})); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", got, tc.wantErr, diff)
			}
		})
	}
}

func TestRuntimeMeasurements(t *testing.T) {
	testcases := []struct {
		name              string
		measurementBlocks []*pb.MeasurementBlock
	}{
		{
			name:              "empty_measurement_blocks",
			measurementBlocks: []*pb.MeasurementBlock{},
		},
		{
			name: "non_empty_measurement_blocks",
			measurementBlocks: []*pb.MeasurementBlock{
				{
					Index: 2,
					DmtfMeasurement: &pb.DmtfMeasurement{
						Value: []byte{0x00},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := runtimeMeasurements(tc.measurementBlocks)
			require.Equal(t, len(tc.measurementBlocks), len(got))
			if len(tc.measurementBlocks) > 0 {
				if _, exists := got[int(tc.measurementBlocks[0].GetIndex())-1]; !exists {
					t.Errorf("measurement block with index %v not found", tc.measurementBlocks[0].GetIndex())
				}
				require.Equal(t, hex.EncodeToString(tc.measurementBlocks[0].GetDmtfMeasurement().GetValue()), got[1])
			}
		})
	}
}

func TestCombineActiveDriverAndVBiosGoldenMeasurements(t *testing.T) {
	testcases := []struct {
		name                     string
		driverGoldenMeasurements []rim.GoldenMeasurement
		vbiosGoldenMeasurements  []rim.GoldenMeasurement
		count                    int
		wantErr                  error
	}{
		{
			name: "driver_and_vbios_golden_measurements",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				{
					Index:  1,
					Active: true,
				},
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				{
					Index:  2,
					Active: true,
				},
			},
			count:   2,
			wantErr: nil,
		},
		{
			name: "driver_active_golden_measurements",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				{
					Index:  1,
					Active: true,
				},
			},
			count:   1,
			wantErr: nil,
		},
		{
			name: "driver_inactive_golden_measurements",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				{
					Index:  1,
					Active: false,
				},
			},
			count:   0,
			wantErr: nil,
		},
		{
			name: "vbios_active_golden_measurements",
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				{
					Index:  1,
					Active: true,
				},
			},
			count:   1,
			wantErr: nil,
		},
		{
			name: "vbios_inactive_golden_measurements",
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				{
					Index:  1,
					Active: false,
				},
			},
			count:   0,
			wantErr: nil,
		},
		{
			name: "multiple_measurements_with_same_index",
			driverGoldenMeasurements: []rim.GoldenMeasurement{
				{
					Index:  1,
					Active: true,
				},
			},
			vbiosGoldenMeasurements: []rim.GoldenMeasurement{
				{
					Index:  1,
					Active: true,
				},
			},
			count:   0,
			wantErr: &MultipleMeasurementsWithSameIndexError{index: 1},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			goldenMeasurements := map[RimType][]rim.GoldenMeasurement{Driver: tc.driverGoldenMeasurements, VBios: tc.vbiosGoldenMeasurements}
			got, err := combineActiveDriverAndVBiosGoldenMeasurements(goldenMeasurements)
			if err == nil {
				require.Equal(t, tc.count, len(got))
			}
			if diff := cmp.Diff(tc.wantErr, err, cmp.AllowUnexported(MultipleMeasurementsWithSameIndexError{})); diff != "" {
				t.Errorf("returned err: %v, wantErr %v (diff -wantErr, +got): %v", err, tc.wantErr, diff)
			}
		})
	}
}

func TestAttestationReport(t *testing.T) {
	invalidNonce, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	invalidDriverVersion := "1.2.3.4"
	invalidVBiosVersion := "1.2.3f.4.01"
	rimDriverErr := fmt.Errorf("rim driver error")
	rimVbiosErr := fmt.Errorf("rim vbios error")
	measurementDriverErr := fmt.Errorf("measurement driver error")
	measurementVbiosErr := fmt.Errorf("measurement vbios error")

	defaultGpuAttestationReportFunc := func() (*pb.AttestationReport, error) {
		return abi.RawAttestationReportToProto(testdata.RawGpuAttestationReportTestData.RawAttestationReport, abi.GPU)
	}
	defaultSwitchAttestationReportFunc := func() (*pb.AttestationReport, error) {
		return abi.RawAttestationReportToProto(testdata.RawSwitchAttestationReportTestData.RawAttestationReport, abi.SWITCH)
	}
	errorAttestationReportFunc := func() (*pb.AttestationReport, error) {
		return nil, &abi.ParsingError{Context: "test", Info: "error"}
	}

	gpuDriverMeasurements := []rim.GoldenMeasurement{
		testGpuGoldenMeasurementsValues[3],
		testGpuGoldenMeasurementsValues[9],
		testGpuGoldenMeasurementsValues[14],
	}
	gpuVBiosMeasurements := []rim.GoldenMeasurement{
		testGpuGoldenMeasurementsValues[12],
		testGpuGoldenMeasurementsValues[13],
	}
	switchVBiosMeasurements := []rim.GoldenMeasurement{
		testSwitchGoldenMeasurementsValues[13],
		testSwitchGoldenMeasurementsValues[21],
	}

	testcases := []struct {
		name                  string
		nonce                 []byte
		driverVersion         string
		vbiosVersion          string
		attestationReportFunc func() (*pb.AttestationReport, error)
		attestationType       abi.AttestationType
		disableRefCheck       bool
		rimClient             rim.Client
		// Stubs for RIM path
		driverRIMDataErr      error
		vbiosRIMDataErr       error
		driverMeasurements    []rim.GoldenMeasurement
		driverMeasurementsErr error
		vbiosMeasurements     []rim.GoldenMeasurement
		vbiosMeasurementsErr  error
		// Expected results
		wantErr                   error
		wantDefaultRIMClientCalls int
	}{
		{
			name:                  "valid_match_gpu",
			nonce:                 testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:         testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:          testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			rimClient:             &test.MockRimClient{},
			driverMeasurements:    gpuDriverMeasurements,
			vbiosMeasurements:     gpuVBiosMeasurements,
			wantErr:               nil,
		},
		{
			name:                  "valid_match_switch",
			nonce:                 testdata.RawSwitchAttestationReportTestData.Nonce,
			vbiosVersion:          testdata.RawSwitchAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultSwitchAttestationReportFunc,
			attestationType:       abi.SWITCH,
			rimClient:             &test.MockRimClient{},
			vbiosMeasurements:     switchVBiosMeasurements,
			wantErr:               nil,
		},
		{
			name:                      "valid_match_gpu_default_rim_client",
			nonce:                     testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:             testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:              testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc:     defaultGpuAttestationReportFunc,
			attestationType:           abi.GPU,
			driverMeasurements:        gpuDriverMeasurements,
			vbiosMeasurements:         gpuVBiosMeasurements,
			wantErr:                   nil,
			wantDefaultRIMClientCalls: 1,
		},
		{
			name:                  "disable_ref_check",
			nonce:                 testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:         testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:          testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			rimClient:             &test.MockRimClient{},
			attestationType:       abi.GPU,
			disableRefCheck:       true,
			wantErr:               nil,
		},
		{
			name:                  "parse_attestation_report_error",
			attestationReportFunc: errorAttestationReportFunc,
			attestationType:       abi.GPU,
			wantErr:               &abi.ParsingError{Context: "test", Info: "error"},
		},
		{
			name:                  "nonce_mismatch_error_gpu",
			nonce:                 invalidNonce,
			driverVersion:         testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:          testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			rimClient:             &test.MockRimClient{},
			wantErr:               &NonceMismatchError{actual: testdata.RawGpuAttestationReportTestData.Nonce, expected: invalidNonce},
		},
		{
			name:                  "driver_version_mismatch_error_gpu",
			nonce:                 testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:         invalidDriverVersion,
			vbiosVersion:          testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			rimClient:             &test.MockRimClient{},
			wantErr:               &DriverVersionMismatchError{actual: testdata.RawGpuAttestationReportTestData.DriverVersion, expected: invalidDriverVersion},
		},
		{
			name:                  "vbios_version_mismatch_error_gpu",
			nonce:                 testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:         testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:          invalidVBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			rimClient:             &test.MockRimClient{},
			wantErr:               &VBiosVersionMismatchError{actual: testdata.RawGpuAttestationReportTestData.VBiosVersion, expected: invalidVBiosVersion},
		},
		{
			name:                  "nonce_mismatch_error_switch",
			nonce:                 invalidNonce,
			vbiosVersion:          testdata.RawSwitchAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultSwitchAttestationReportFunc,
			attestationType:       abi.SWITCH,
			rimClient:             &test.MockRimClient{},
			vbiosMeasurements:     switchVBiosMeasurements,
			wantErr:               &NonceMismatchError{actual: testdata.RawSwitchAttestationReportTestData.Nonce, expected: invalidNonce},
		},
		{
			name:                  "vbios_version_mismatch_error_switch",
			nonce:                 testdata.RawSwitchAttestationReportTestData.Nonce,
			vbiosVersion:          invalidVBiosVersion,
			attestationReportFunc: defaultSwitchAttestationReportFunc,
			attestationType:       abi.SWITCH,
			rimClient:             &test.MockRimClient{},
			vbiosMeasurements:     switchVBiosMeasurements,
			wantErr:               &VBiosVersionMismatchError{actual: testdata.RawSwitchAttestationReportTestData.VBiosVersion, expected: invalidVBiosVersion},
		},
		{
			name:                  "measurement_mismatch_error_switch",
			nonce:                 testdata.RawSwitchAttestationReportTestData.Nonce,
			vbiosVersion:          testdata.RawSwitchAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultSwitchAttestationReportFunc,
			attestationType:       abi.SWITCH,
			rimClient:             &test.MockRimClient{},
			vbiosMeasurements:     []rim.GoldenMeasurement{testGpuGoldenMeasurementsValues[11]},
			wantErr:               &MismatchedMeasurementsError{[]mismatchedMeasurement{{index: 11, goldenMeasurementValues: testGpuGoldenMeasurementsValues[11].Values, runtimeMeasurementValue: "d48958361c65b3be773140e83e8312cc860066f51524dc8d6f3cd255d2bcc30166c32e7529f4ec18ec2936ae385940e3"}}},
		},
		{
			name:                  "gpu_driver_rim_fetch_error",
			nonce:                 testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:         testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:          testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			rimClient:             &test.MockRimClient{},
			driverRIMDataErr:      rimDriverErr,
			wantErr:               rimDriverErr,
		},
		{
			name:                  "gpu_vbios_rim_fetch_error",
			nonce:                 testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:         testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:          testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			rimClient:             &test.MockRimClient{},
			vbiosRIMDataErr:       rimVbiosErr,
			wantErr:               rimVbiosErr,
		},
		{
			name:                  "switch_vbios_rim_fetch_error",
			nonce:                 testdata.RawSwitchAttestationReportTestData.Nonce,
			vbiosVersion:          testdata.RawSwitchAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultSwitchAttestationReportFunc,
			attestationType:       abi.SWITCH,
			rimClient:             &test.MockRimClient{},
			vbiosRIMDataErr:       rimVbiosErr,
			wantErr:               rimVbiosErr,
		},
		{
			name:                  "gpu_driver_extract_measurement_error",
			nonce:                 testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:         testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:          testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			rimClient:             &test.MockRimClient{},
			driverMeasurementsErr: measurementDriverErr,
			wantErr:               measurementDriverErr,
		},
		{
			name:                  "gpu_vbios_extract_measurement_error",
			nonce:                 testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:         testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:          testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			rimClient:             &test.MockRimClient{},
			vbiosMeasurementsErr:  measurementVbiosErr,
			wantErr:               measurementVbiosErr,
		},
		{
			name:                  "switch_vbios_extract_measurement_error",
			nonce:                 testdata.RawSwitchAttestationReportTestData.Nonce,
			vbiosVersion:          testdata.RawSwitchAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultSwitchAttestationReportFunc,
			attestationType:       abi.SWITCH,
			rimClient:             &test.MockRimClient{},
			vbiosMeasurementsErr:  measurementVbiosErr,
			wantErr:               measurementVbiosErr,
		},
		{
			name:                  "measurement_mismatch_error_gpu",
			nonce:                 testdata.RawGpuAttestationReportTestData.Nonce,
			driverVersion:         testdata.RawGpuAttestationReportTestData.DriverVersion,
			vbiosVersion:          testdata.RawGpuAttestationReportTestData.VBiosVersion,
			attestationReportFunc: defaultGpuAttestationReportFunc,
			attestationType:       abi.GPU,
			rimClient:             &test.MockRimClient{},
			driverMeasurements:    []rim.GoldenMeasurement{testGpuGoldenMeasurementsValues[40]},
			vbiosMeasurements:     []rim.GoldenMeasurement{testGpuGoldenMeasurementsValues[11]},
			wantErr:               &MismatchedMeasurementsError{[]mismatchedMeasurement{{index: 11, goldenMeasurementValues: testGpuGoldenMeasurementsValues[11].Values, runtimeMeasurementValue: "413d008cedd5526a79455a178154328ce960af252bdb06e7fe4080049add412488cac39ecf3d80efbdc6bdd363861773"}, {index: 40, goldenMeasurementValues: testGpuGoldenMeasurementsValues[40].Values, runtimeMeasurementValue: "9d2c6389c070dde430ffd510cad0c546fb9a73b9ee7a478fa804d2ab14c674487abdc7aa12d90215ced4f3678f2765fa"}}},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			utility.DriverRIMData = func(context.Context, string, *pb.AttestationReport, rim.Client, pb.GpuArchitectureType) (*rim.Data, error) {
				return &rim.Data{}, tc.driverRIMDataErr
			}
			utility.GpuVbiosRIMData = func(context.Context, *pb.AttestationReport, rim.Client) (*rim.Data, error) {
				return &rim.Data{}, tc.vbiosRIMDataErr
			}
			utility.SwitchBiosRIMData = func(context.Context, *pb.AttestationReport, rim.Client) (*rim.Data, error) {
				return &rim.Data{}, tc.vbiosRIMDataErr
			}
			utility.DriverGoldenMeasurements = func(utility.RIMExtractor) ([]rim.GoldenMeasurement, error) {
				return tc.driverMeasurements, tc.driverMeasurementsErr
			}
			utility.VbiosGoldenMeasurements = func(utility.RIMExtractor) ([]rim.GoldenMeasurement, error) {
				return tc.vbiosMeasurements, tc.vbiosMeasurementsErr
			}

			defaultRimClientCallCount := 0
			opts := Options{
				Nonce:           tc.nonce,
				DriverVersion:   tc.driverVersion,
				VBiosVersion:    tc.vbiosVersion,
				AttestationType: tc.attestationType,
				DisableRefCheck: tc.disableRefCheck,
				RimClient:       tc.rimClient,
				GpuArch:         pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				parseAttestationReport: func(b []byte, at abi.AttestationType) (*pb.AttestationReport, error) {
					return tc.attestationReportFunc()
				},
				NewRimClient: func(httpClient *http.Client, serviceKey string) rim.Client {
					defaultRimClientCallCount++
					return &test.MockRimClient{ContentToReturn: []byte("<rim/>")}
				},
			}
			got := AttestationReport(context.Background(), nil, opts)
			if !cmp.Equal(tc.wantErr, got, cmp.Comparer(func(x, y error) bool {
				if x == nil || y == nil {
					return x == y
				}
				return x.Error() == y.Error()
			}), cmp.AllowUnexported(MismatchedMeasurementsError{}, mismatchedMeasurement{}, NonceMismatchError{}, DriverVersionMismatchError{}, VBiosVersionMismatchError{}, abi.ParsingError{})) {
				t.Errorf("AttestationReport() error = %v, want %v", got, tc.wantErr)
			}
			if defaultRimClientCallCount != tc.wantDefaultRIMClientCalls {
				t.Errorf("AttestationReport() defaultRimClient call count mismatch: got %d, want %d", defaultRimClientCallCount, tc.wantDefaultRIMClientCalls)
			}
		})
	}
}

func TestAttestationReportReadsFirstOpaqueField(t *testing.T) {
	nonce := []byte("test-nonce")
	testcases := []struct {
		name            string
		attestationType abi.AttestationType
		driverVersion   string
		vbiosVersion    string
		ofds            []*pb.OpaqueFieldData
		wantErr         error
	}{
		{
			name:            "driver_version_gpu",
			attestationType: abi.GPU,
			driverVersion:   "535.104.05",
			ofds: []*pb.OpaqueFieldData{
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("999.99.99")}},
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("535.104.05")}},
			},
			wantErr: &DriverVersionMismatchError{actual: "999.99.99", expected: "535.104.05"},
		},
		{
			name:            "driver_version_ignores_second_copy_gpu",
			attestationType: abi.GPU,
			driverVersion:   "535.104.05",
			vbiosVersion:    "04.03.02.01.05",
			ofds: []*pb.OpaqueFieldData{
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("535.104.05")}},
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("999.99.99")}},
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}}},
			},
			wantErr: nil,
		},
		{
			name:            "vbios_version_gpu",
			attestationType: abi.GPU,
			driverVersion:   "535.104.05",
			vbiosVersion:    "04.03.02.01.05",
			ofds: []*pb.OpaqueFieldData{
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("535.104.05")}},
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}}},
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}}},
			},
			wantErr: &VBiosVersionMismatchError{actual: "14.13.12.11.15", expected: "04.03.02.01.05"},
		},
		{
			name:            "vbios_version_ignores_malformed_second_copy_gpu",
			attestationType: abi.GPU,
			driverVersion:   "535.104.05",
			vbiosVersion:    "04.03.02.01.05",
			ofds: []*pb.OpaqueFieldData{
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("535.104.05")}},
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}}},
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte{0x01}}},
			},
			wantErr: nil,
		},
		{
			name:            "vbios_version_switch",
			attestationType: abi.SWITCH,
			vbiosVersion:    "96.10.6D.00.01",
			ofds: []*pb.OpaqueFieldData{
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("99.99.99.99.99")}},
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("96.10.6D.00.01")}},
			},
			wantErr: &VBiosVersionMismatchError{actual: "99.99.99.99.99", expected: "96.10.6D.00.01"},
		},
		{
			name:            "vbios_version_ignores_second_copy_switch",
			attestationType: abi.SWITCH,
			vbiosVersion:    "96.10.6D.00.01",
			ofds: []*pb.OpaqueFieldData{
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("96.10.6D.00.01")}},
				{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte("99.99.99.99.99")}},
			},
			wantErr: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			report := &pb.AttestationReport{
				SpdmMeasurementRequest:  &pb.SpdmMeasurementRequest{Nonce: nonce},
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{OpaqueData: &pb.OpaqueData{OpaqueFieldData: tc.ofds}},
			}
			got := AttestationReport(t.Context(), nil, Options{
				Nonce:           nonce,
				DriverVersion:   tc.driverVersion,
				VBiosVersion:    tc.vbiosVersion,
				AttestationType: tc.attestationType,
				DisableRefCheck: true,
				parseAttestationReport: func([]byte, abi.AttestationType) (*pb.AttestationReport, error) {
					return report, nil
				},
			})
			if diff := cmp.Diff(tc.wantErr, got, cmp.AllowUnexported(DriverVersionMismatchError{}, VBiosVersionMismatchError{})); diff != "" {
				t.Errorf("AttestationReport() with opaque fields %v error mismatch (-want +got):\n%s", tc.ofds, diff)
			}
		})
	}
}

func TestAttestationReportMalformedVBIOSVersion(t *testing.T) {
	nonce := []byte("test-nonce")
	const driverVersion = "535.104.05"
	report := &pb.AttestationReport{
		SpdmMeasurementRequest: &pb.SpdmMeasurementRequest{Nonce: nonce},
		SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{OpaqueData: &pb.OpaqueData{OpaqueFieldData: []*pb.OpaqueFieldData{
			{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_DRIVER_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte(driverVersion)}},
			{DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION, Data: &pb.OpaqueFieldData_Value{Value: []byte{0x01}}},
		}}},
	}

	err := AttestationReport(t.Context(), nil, Options{
		Nonce:           nonce,
		DriverVersion:   driverVersion,
		VBiosVersion:    "96.00.9F.00.01",
		AttestationType: abi.GPU,
		DisableRefCheck: true,
		parseAttestationReport: func([]byte, abi.AttestationType) (*pb.AttestationReport, error) {
			return report, nil
		},
	})
	if err == nil {
		t.Fatal("AttestationReport() with a 1-byte GPU VBIOS version succeeded, want error")
	}
	var vbiosMismatchErr *VBiosVersionMismatchError
	var driverMismatchErr *DriverVersionMismatchError
	if errors.As(err, &vbiosMismatchErr) || errors.As(err, &driverMismatchErr) {
		t.Errorf("AttestationReport() with a 1-byte GPU VBIOS version error = %v, want a VBIOS format error, not a version mismatch", err)
	}
}

func TestDoMeasurementsMatchReadsFirstNVDEC0Status(t *testing.T) {
	measurementValue := make([]byte, 48)
	testcases := []struct {
		name     string
		statuses []string
		wantErr  error
	}{
		{
			name:     "enabled_then_disabled_checks_msr35",
			statuses: []string{enabledMsr35Value, disabledMsr35Value},
			wantErr: &MismatchedMeasurementsError{[]mismatchedMeasurement{{
				index:                   msr35Index,
				goldenMeasurementValues: testGpuGoldenMeasurementsValues[msr35Index].Values,
				runtimeMeasurementValue: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			}}},
		},
		{
			name:     "disabled_then_enabled_skips_msr35",
			statuses: []string{disabledMsr35Value, enabledMsr35Value},
			wantErr:  nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var ofds []*pb.OpaqueFieldData
			for _, status := range tc.statuses {
				ofds = append(ofds, &pb.OpaqueFieldData{
					DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_NVDEC0_STATUS,
					Data:     &pb.OpaqueFieldData_Value{Value: []byte(status)},
				})
			}
			report := &pb.AttestationReport{
				SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
					MeasurementRecord: &pb.MeasurementRecord{
						MeasurementBlocks: []*pb.MeasurementBlock{{
							Index:           msr35Index + 1,
							DmtfMeasurement: &pb.DmtfMeasurement{Value: measurementValue},
						}},
					},
					OpaqueData: &pb.OpaqueData{OpaqueFieldData: ofds},
				},
			}
			got := doMeasurementsMatch(report, Options{
				AttestationType: abi.GPU,
				goldenMeasurements: map[RimType][]rim.GoldenMeasurement{
					Driver: {testGpuGoldenMeasurementsValues[msr35Index]},
					VBios:  {},
				},
			})
			if diff := cmp.Diff(tc.wantErr, got, cmp.AllowUnexported(MismatchedMeasurementsError{}, mismatchedMeasurement{})); diff != "" {
				t.Errorf("doMeasurementsMatch() with NVDEC0 statuses %x error mismatch (-want +got):\n%s", tc.statuses, diff)
			}
		})
	}
}
