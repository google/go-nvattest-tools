package utility

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-nvattest-tools/abi"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/rim"
	"github.com/google/go-nvattest-tools/testing/testdata"
	mock "github.com/google/go-nvattest-tools/testing"
)

func TestReadFieldAsLittleEndian(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	got := readFieldAsLittleEndian(data)
	want := "0807060504030201"
	if got != want {
		t.Errorf("readFieldAsLittleEndian(%v) = %v, want %v", data, got, want)
	}
}

func TestFormatVbiosVersion(t *testing.T) {
	tests := []struct {
		name    string
		version []byte
		mode    abi.AttestationType
		want    string
	}{
		{name: "gpu_two_bytes", version: []byte{0xaa, 0xbb}, mode: abi.GPU, want: "aa.bb"},
		{name: "gpu_four_bytes", version: []byte{0x01, 0x02, 0x03, 0x04}, mode: abi.GPU, want: "02.01.03"},
		{name: "gpu_six_bytes", version: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, mode: abi.GPU, want: "03.02.01.04"},
		{name: "gpu_eight_bytes", version: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, mode: abi.GPU, want: "04.03.02.01.05"},
		{name: "switch", version: []byte("96.10.6D.00.01"), mode: abi.SWITCH, want: "96.10.6D.00.01"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FormatVbiosVersion(tc.version, tc.mode)
			if err != nil {
				t.Fatalf("FormatVbiosVersion(%v, %v) failed: %v", tc.version, tc.mode, err)
			}
			if got != tc.want {
				t.Errorf("FormatVbiosVersion(%v, %v) = %q, want %q", tc.version, tc.mode, got, tc.want)
			}
		})
	}
}

func TestFormatVbiosVersionError(t *testing.T) {
	tests := []struct {
		name    string
		version []byte
		mode    abi.AttestationType
	}{
		{name: "gpu_empty", version: nil, mode: abi.GPU},
		{name: "gpu_one_byte", version: []byte{0x01}, mode: abi.GPU},
		{name: "gpu_three_bytes", version: []byte{0x01, 0x02, 0x03}, mode: abi.GPU},
		// Field from a fuzzer crash input.
		{name: "gpu_five_bytes", version: []byte{0x30, 0x00, 0x00, 0x00, 0x00}, mode: abi.GPU},
		{name: "unsupported_mode", version: []byte{0x01, 0x02}, mode: abi.AttestationType(99)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := FormatVbiosVersion(tc.version, tc.mode); err == nil {
				t.Errorf("FormatVbiosVersion(%v, %v) = %q, want error", tc.version, tc.mode, got)
			}
		})
	}
}

func TestFormatVbiosVersionUnsupportedModeErrorType(t *testing.T) {
	mode := abi.AttestationType(99)
	_, err := FormatVbiosVersion([]byte{0x01, 0x02}, mode)
	var typeErr *abi.UnsupportedAttestationTypeError
	if !errors.As(err, &typeErr) {
		t.Errorf("FormatVbiosVersion(_, %v) error = %v, want *abi.UnsupportedAttestationTypeError", mode, err)
	}
}

// FuzzFormatVbiosVersion is a property test for the GPU VBIOS version formatter.
func FuzzFormatVbiosVersion(f *testing.F) {
	report, err := abi.RawAttestationReportToProto(testdata.RawGpuAttestationReportTestData.RawAttestationReport, abi.GPU)
	if err != nil {
		f.Fatalf("RawAttestationReportToProto() failed: %v", err)
	}
	f.Add(abi.ExtractOpaqueValue(report.GetSpdmMeasurementResponse().GetOpaqueData().GetOpaqueFieldData(), pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION))
	f.Add([]byte{})

	// The switch path converts the bytes to a string and has no branches to fuzz.
	f.Fuzz(func(t *testing.T, version []byte) {
		got, err := FormatVbiosVersion(version, abi.GPU)
		valid := len(version) >= 2 && len(version)%2 == 0
		if (err == nil) != valid {
			t.Fatalf("FormatVbiosVersion(%x, GPU) error = %v, want error only for odd or short input", version, err)
		}
		if err == nil && len(got) != 3*len(version)/2+2 {
			t.Errorf("FormatVbiosVersion(%x, GPU) = %q, want length %d", version, got, 3*len(version)/2+2)
		}
	})
}

func TestDriverRIMFileID(t *testing.T) {
	tests := []struct {
		name                string
		driverVersion       string
		opaqueFieldDataList []*pb.OpaqueFieldData
		gpuArch             pb.GpuArchitectureType
		want                string
		wantErr             bool
		wantErrSubstring    string
	}{
		{
			name:          "HopperArch",
			driverVersion: "535.104.05",
			gpuArch:       pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			want:          "NV_GPU_DRIVER_GH100_535.104.05",
			wantErr:       false,
		},
		{
			name:          "BlackwellArchWithChipInfo",
			driverVersion: "550.0.0",
			opaqueFieldDataList: []*pb.OpaqueFieldData{
				{
					DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_CHIP_INFO,
					Data:     &pb.OpaqueFieldData_Value{Value: []byte("GB200")},
				},
			},
			gpuArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL,
			want:    "NV_GPU_CC_DRIVER_GB200_550.0.0",
			wantErr: false,
		},
		{
			name:                "BlackwellArchNoChipInfo",
			driverVersion:       "550.0.2",
			opaqueFieldDataList: []*pb.OpaqueFieldData{},
			gpuArch:             pb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL,
			want:                "NV_GPU_CC_DRIVER__550.0.2",
			wantErr:             false,
		},
		{
			name:             "UnsupportedArch",
			driverVersion:    "123.45",
			gpuArch:          pb.GpuArchitectureType_GPU_ARCHITECTURE_PASCAL,
			want:             "",
			wantErr:          true,
			wantErrSubstring: "unsupported GPU architecture: GPU_ARCHITECTURE_PASCAL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := driverRIMFileID(tc.driverVersion, tc.opaqueFieldDataList, tc.gpuArch)

			if tc.wantErr {
				if err == nil {
					t.Errorf("driverRIMFileID(%q, %v, %q) succeeded, want error", tc.driverVersion, tc.opaqueFieldDataList, tc.gpuArch)
				} else if tc.wantErrSubstring != "" && !strings.Contains(err.Error(), tc.wantErrSubstring) {
					t.Errorf("driverRIMFileID(%q, %v, %q) error = %q, want error containing %q", tc.driverVersion, tc.opaqueFieldDataList, tc.gpuArch, err, tc.wantErrSubstring)
				}
			} else {
				if err != nil {
					t.Fatalf("driverRIMFileID(%q, %v, %q) failed unexpectedly; err = %s", tc.driverVersion, tc.opaqueFieldDataList, tc.gpuArch, err)
				}
				if got != tc.want {
					t.Errorf("driverRIMFileID(%q, %v, %q) = %q, want %q", tc.driverVersion, tc.opaqueFieldDataList, tc.gpuArch, got, tc.want)
				}
			}
		})
	}
}

func TestVbiosRIMFileID(t *testing.T) {
	gpuReportProto, err := abi.RawAttestationReportToProto(testdata.RawGpuAttestationReportTestData.RawAttestationReport, abi.GPU)
	if err != nil {
		t.Fatalf("Failed to parse attestation report: %v", err)
	}
	switchReportProto, err := abi.RawAttestationReportToProto(testdata.RawSwitchAttestationReportTestData.RawAttestationReport, abi.SWITCH)
	if err != nil {
		t.Fatalf("Failed to parse switch attestation report: %v", err)
	}

	tests := []struct {
		name                string
		opaqueFieldDataList []*pb.OpaqueFieldData
		mode                abi.AttestationType
		want                string
	}{
		{
			name:                "gpu_mode",
			opaqueFieldDataList: gpuReportProto.SpdmMeasurementResponse.GetOpaqueData().GetOpaqueFieldData(),
			mode:                abi.GPU,
			want:                "NV_GPU_VBIOS_1010_0200_882_96009F0001",
		},
		{
			name:                "switch_mode",
			opaqueFieldDataList: switchReportProto.SpdmMeasurementResponse.GetOpaqueData().GetOpaqueFieldData(),
			mode:                abi.SWITCH,
			want:                "NV_SWITCH_BIOS_5612_0002_890_96106D0001",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vbiosRIMFileID(tc.opaqueFieldDataList, tc.mode)
			if err != nil {
				t.Fatalf("vbiosRIMFileID(%v, %v) failed: %v", tc.opaqueFieldDataList, tc.mode, err)
			}
			if got != tc.want {
				t.Errorf("vbiosRIMFileID(%v, %v) = %q, want %q", tc.opaqueFieldDataList, tc.mode, got, tc.want)
			}
		})
	}
}

func TestVbiosRIMFileIDError(t *testing.T) {
	vbiosVersion := func(value []byte) []*pb.OpaqueFieldData {
		return []*pb.OpaqueFieldData{{
			DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION,
			Data:     &pb.OpaqueFieldData_Value{Value: value},
		}}
	}
	tests := []struct {
		name                string
		opaqueFieldDataList []*pb.OpaqueFieldData
		mode                abi.AttestationType
	}{
		{name: "gpu_invalid_vbios_version_length", opaqueFieldDataList: vbiosVersion([]byte{0x01, 0x02, 0x03}), mode: abi.GPU},
		{name: "gpu_missing_vbios_version", opaqueFieldDataList: nil, mode: abi.GPU},
		{name: "unsupported_mode", opaqueFieldDataList: vbiosVersion([]byte{0x01, 0x02}), mode: abi.AttestationType(99)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := vbiosRIMFileID(tc.opaqueFieldDataList, tc.mode); err == nil {
				t.Errorf("vbiosRIMFileID(%v, %v) = %q, want error", tc.opaqueFieldDataList, tc.mode, got)
			}
		})
	}
}

func TestDriverRIMData(t *testing.T) {
	errDummy := errors.New("dummy error")
	testCases := []struct {
		name          string
		driverVersion string
		reportProto   *pb.AttestationReport
		rimClient     rim.Client
		gpuArch       pb.GpuArchitectureType
		rimParse      func([]byte) (*rim.Data, error)
		wantErr       error
	}{
		{
			name:          "success",
			driverVersion: "535.104.05",
			reportProto:   &pb.AttestationReport{},
			rimClient:     &mock.MockRimClient{ContentToReturn: []byte("rim content")},
			gpuArch:       pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			rimParse: func([]byte) (*rim.Data, error) {
				return &rim.Data{}, nil
			},
		},
		{
			name:          "failure_getting_driver_rim_file_ID",
			driverVersion: "535.104.05",
			reportProto:   &pb.AttestationReport{},
			rimClient:     &mock.MockRimClient{},
			gpuArch:       pb.GpuArchitectureType_GPU_ARCHITECTURE_PASCAL,
			wantErr:       errDummy,
		},
		{
			name:          "failure_fetching_rim",
			driverVersion: "535.104.05",
			reportProto:   &pb.AttestationReport{},
			rimClient:     &mock.MockRimClient{ErrToReturn: errDummy},
			gpuArch:       pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			wantErr:       errDummy,
		},
		{
			name:          "failure_parsing_rim",
			driverVersion: "535.104.05",
			reportProto:   &pb.AttestationReport{},
			rimClient:     &mock.MockRimClient{ContentToReturn: []byte("rim content")},
			gpuArch:       pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			rimParse: func([]byte) (*rim.Data, error) {
				return nil, errDummy
			},
			wantErr: errDummy,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rimParse = rim.Parse
			if tc.rimParse != nil {
				rimParse = tc.rimParse
			}
			_, err := DriverRIMData(context.Background(), tc.driverVersion, tc.reportProto, tc.rimClient, tc.gpuArch)
			if (err != nil) != (tc.wantErr != nil) {
				t.Errorf("DriverRIMData() got err %v, want err %v", err, tc.wantErr)
			}
		})
	}
}

func TestVbiosRIMData(t *testing.T) {
	errDummy := errors.New("dummy error")
	gpuReportProto, err := abi.RawAttestationReportToProto(testdata.RawGpuAttestationReportTestData.RawAttestationReport, abi.GPU)
	if err != nil {
		t.Fatalf("Failed to parse attestation report: %v", err)
	}
	switchReportProto, err := abi.RawAttestationReportToProto(testdata.RawSwitchAttestationReportTestData.RawAttestationReport, abi.SWITCH)
	if err != nil {
		t.Fatalf("Failed to parse switch attestation report: %v", err)
	}
	testCases := []struct {
		name        string
		reportProto *pb.AttestationReport
		rimClient   rim.Client
		mode        abi.AttestationType
		rimParse    func([]byte) (*rim.Data, error)
		wantErr     error
	}{
		{
			name:        "success GPU",
			reportProto: gpuReportProto,
			rimClient:   &mock.MockRimClient{ContentToReturn: []byte("rim content")},
			mode:        abi.GPU,
			rimParse: func([]byte) (*rim.Data, error) {
				return &rim.Data{}, nil
			},
		},
		{
			name:        "success switch",
			reportProto: switchReportProto,
			rimClient:   &mock.MockRimClient{ContentToReturn: []byte("rim content")},
			mode:        abi.SWITCH,
			rimParse: func([]byte) (*rim.Data, error) {
				return &rim.Data{}, nil
			},
		},
		{
			name:        "failure fetching RIM",
			reportProto: gpuReportProto,
			rimClient:   &mock.MockRimClient{ErrToReturn: errDummy},
			mode:        abi.GPU,
			wantErr:     errDummy,
		},
		{
			name:        "failure parsing RIM",
			reportProto: gpuReportProto,
			rimClient:   &mock.MockRimClient{ContentToReturn: []byte("rim content")},
			mode:        abi.GPU,
			rimParse: func([]byte) (*rim.Data, error) {
				return nil, errDummy
			},
			wantErr: errDummy,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rimParse = rim.Parse
			if tc.rimParse != nil {
				rimParse = tc.rimParse
			}
			_, err := vbiosRIMData(context.Background(), tc.reportProto, tc.rimClient, tc.mode)
			if (err != nil) != (tc.wantErr != nil) {
				t.Errorf("vbiosRIMData() got err %v, want err %v", err, tc.wantErr)
			}
		})
	}
}

func TestGpuVbiosRIMData(t *testing.T) {
	errDummy := errors.New("dummy error")
	gpuReportProto, err := abi.RawAttestationReportToProto(testdata.RawGpuAttestationReportTestData.RawAttestationReport, abi.GPU)
	if err != nil {
		t.Fatalf("Failed to parse attestation report: %v", err)
	}
	testCases := []struct {
		name        string
		reportProto *pb.AttestationReport
		rimClient   rim.Client
		rimParse    func([]byte) (*rim.Data, error)
		wantErr     error
	}{
		{
			name:        "success",
			reportProto: gpuReportProto,
			rimClient:   &mock.MockRimClient{ContentToReturn: []byte("rim content")},
			rimParse: func([]byte) (*rim.Data, error) {
				return &rim.Data{}, nil
			},
		},
		{
			name:        "failure",
			reportProto: gpuReportProto,
			rimClient:   &mock.MockRimClient{ErrToReturn: errDummy},
			wantErr:     errDummy,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rimParse = rim.Parse
			if tc.rimParse != nil {
				rimParse = tc.rimParse
			}
			_, err := GpuVbiosRIMData(context.Background(), tc.reportProto, tc.rimClient)
			if (err != nil) != (tc.wantErr != nil) {
				t.Errorf("GpuVbiosRIMData() got err %v, want err %v", err, tc.wantErr)
			}
		})
	}
}

func TestSwitchBiosRIMData(t *testing.T) {
	errDummy := errors.New("dummy error")
	switchReportProto, err := abi.RawAttestationReportToProto(testdata.RawSwitchAttestationReportTestData.RawAttestationReport, abi.SWITCH)
	if err != nil {
		t.Fatalf("Failed to parse switch attestation report: %v", err)
	}
	testCases := []struct {
		name        string
		reportProto *pb.AttestationReport
		rimClient   rim.Client
		rimParse    func([]byte) (*rim.Data, error)
		wantErr     error
	}{
		{
			name:        "success",
			reportProto: switchReportProto,
			rimClient:   &mock.MockRimClient{ContentToReturn: []byte("rim content")},
			rimParse: func([]byte) (*rim.Data, error) {
				return &rim.Data{}, nil
			},
		},
		{
			name:        "failure",
			reportProto: switchReportProto,
			rimClient:   &mock.MockRimClient{ErrToReturn: errDummy},
			wantErr:     errDummy,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rimParse = rim.Parse
			if tc.rimParse != nil {
				rimParse = tc.rimParse
			}
			_, err := SwitchBiosRIMData(context.Background(), tc.reportProto, tc.rimClient)
			if (err != nil) != (tc.wantErr != nil) {
				t.Errorf("SwitchBiosRIMData() got err %v, want err %v", err, tc.wantErr)
			}
		})
	}
}

type mockRimDataForMeasurements struct {
	measurements []rim.GoldenMeasurement
	err          error
}

func (m *mockRimDataForMeasurements) Measurements(string, string) ([]rim.GoldenMeasurement, error) {
	return m.measurements, m.err
}

func TestDriverGoldenMeasurements(t *testing.T) {
	testCases := []struct {
		name    string
		rimData RIMExtractor
		wantErr bool
	}{
		{
			name:    "success",
			rimData: &mockRimDataForMeasurements{measurements: []rim.GoldenMeasurement{}},
			wantErr: false,
		},
		{
			name:    "failure",
			rimData: &mockRimDataForMeasurements{err: errors.New("measurements error")},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DriverGoldenMeasurements(tc.rimData)
			if (err != nil) != tc.wantErr {
				t.Errorf("DriverGoldenMeasurements() got err %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestVbiosGoldenMeasurements(t *testing.T) {
	testCases := []struct {
		name    string
		rimData RIMExtractor
		wantErr bool
	}{
		{
			name:    "success",
			rimData: &mockRimDataForMeasurements{measurements: []rim.GoldenMeasurement{}},
			wantErr: false,
		},
		{
			name:    "failure",
			rimData: &mockRimDataForMeasurements{err: errors.New("measurements error")},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VbiosGoldenMeasurements(tc.rimData)
			if (err != nil) != tc.wantErr {
				t.Errorf("VbiosGoldenMeasurements() got err %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func createAttestationReport(version string, featureFlagByte byte) *pb.AttestationReport {
	var fields []*pb.OpaqueFieldData
	if version != "" {
		fields = append(fields, &pb.OpaqueFieldData{
			DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_OPAQUE_DATA_VERSION,
			Data:     &pb.OpaqueFieldData_Value{Value: []byte(version)},
		})
	}
	if featureFlagByte != 255 {
		fields = append(fields, &pb.OpaqueFieldData{
			DataType: pb.OpaqueDataType_OPAQUE_FIELD_ID_FEATURE_FLAG,
			Data:     &pb.OpaqueFieldData_Value{Value: []byte{featureFlagByte}},
		})
	}
	return &pb.AttestationReport{
		SpdmMeasurementResponse: &pb.SpdmMeasurementResponse{
			OpaqueData: &pb.OpaqueData{
				OpaqueFieldData: fields,
			},
		},
	}
}

// makeQuote is a test helper to create a GpuAttestationQuote with n GPUs.
func makeQuote(reports []*pb.AttestationReport) *pb.GpuAttestationQuote {
	infos := make([]*pb.GpuInfo, len(reports))
	for i := range infos {
		infos[i] = &pb.GpuInfo{
			AttestationReport: []byte{byte(i)},
			Uuid:              fmt.Sprintf("gpu-%d", i),
		}
	}
	return &pb.GpuAttestationQuote{GpuInfos: infos}
}

func TestValidateModes(t *testing.T) {
	const noFeatureFlag = 255

	tests := []struct {
		name         string
		reports      []*pb.AttestationReport
		parseErr     error
		expectedMode string
		wantErr      bool
	}{
		{
			name:         "no_gpus",
			reports:      []*pb.AttestationReport{},
			expectedMode: abi.MPTMode,
		},
		{
			name:         "one_gpu_mpt",
			reports:      []*pb.AttestationReport{createAttestationReport("1", 1)}, // MPT
			expectedMode: abi.MPTMode,
		},
		{
			name: "multiple_gpus_all_mpt",
			reports: []*pb.AttestationReport{
				createAttestationReport("1", 1), // MPT
				createAttestationReport("1", 1), // MPT
			},
			expectedMode: abi.MPTMode,
		},
		{
			name: "multiple_gpus_all_legacy",
			reports: []*pb.AttestationReport{
				createAttestationReport("", noFeatureFlag),
				createAttestationReport("", noFeatureFlag),
			},
			expectedMode: abi.LegacyMode,
		},
		{
			name: "multiple_gpus_all_ppcie",
			reports: []*pb.AttestationReport{
				createAttestationReport("1", 2), // PPCIE
				createAttestationReport("1", 2), // PPCIE
			},
			expectedMode: abi.PPCIEMode,
		},
		{
			name: "mismatch_gpu_mode",
			reports: []*pb.AttestationReport{
				createAttestationReport("1", 1), // MPT
				createAttestationReport("1", 0), // SPT
			},
			expectedMode: abi.MPTMode,
			wantErr:      true,
		},
		{
			name: "mismatch_gpu_mode_version_0_skipped",
			reports: []*pb.AttestationReport{
				createAttestationReport("0.1", 1), // MPT
				createAttestationReport("0.1", 0), // SPT
			},
			expectedMode: abi.MPTMode,
		},
		{
			name: "mismatch_gpu_mode_version_1_not_skipped",
			reports: []*pb.AttestationReport{
				createAttestationReport("1.0", 1), // MPT
				createAttestationReport("1.0", 0), // SPT
			},
			expectedMode: abi.MPTMode,
			wantErr:      true, // error is not skipped
		},
		{
			name: "parsing_error",
			reports: []*pb.AttestationReport{
				createAttestationReport("1", 1),
				createAttestationReport("1", 1),
			},
			parseErr:     errors.New("parsing failed"),
			expectedMode: abi.MPTMode,
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Setup Data
			quote := makeQuote(tc.reports)

			// 2. Override parseAttestationReport function
			parseAttestationReport = func(reportBytes []byte, _ abi.AttestationType) (*pb.AttestationReport, error) {
				if tc.parseErr != nil {
					return nil, tc.parseErr
				}
				if len(reportBytes) == 0 {
					t.Fatalf("parseAttestationReport called with empty reportBytes")
				}
				reportIdx := int(reportBytes[0])
				if reportIdx >= len(tc.reports) {
					t.Fatalf("unexpected report index %d, have %d reports", reportIdx, len(tc.reports))
				}
				report := tc.reports[reportIdx]
				return report, nil
			}

			// 3. Action
			err := ValidateModes(quote, tc.expectedMode)

			// 4. Assertion
			if tc.wantErr {
				if err == nil {
					t.Errorf("ValidateModes() got nil error, want non-nil")
				}
			} else if err != nil {
				t.Errorf("ValidateModes() got error = %v, want nil", err)
			}
		})
	}
}
