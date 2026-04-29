package spt

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/validate"
	"github.com/google/go-nvattest-tools/server/verify"
	td "github.com/google/go-nvattest-tools/testing/testdata"
	testmock "github.com/google/go-nvattest-tools/testing"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/protobuf/testing/protocmp"
)
func TestVerifyGpuQuote(t *testing.T) {
	errDummy := errors.New("dummy error")
	sampleAttestationReport := td.RawGpuAttestationReportTestData.RawAttestationReport

	testCases := []struct {
		name                         string
		gpuInfo                      *pb.GpuInfo
		opts                         Options
		gpuInfoErr                   error
		validateAttestationReportErr error
		wantState                    *pb.GpuInfoState
		wantErr                      error
	}{
		{
			name:    "success_verification_and_validation",
			gpuInfo: &pb.GpuInfo{AttestationReport: sampleAttestationReport},
			opts:    Options{},
			wantState: &pb.GpuInfoState{
				GpuUuid: "gpu-verified-ok", MeasurementsMatched: true,
			},
		},
		{
			name:    "success_verification_and_validation_disable_ref_check",
			gpuInfo: &pb.GpuInfo{AttestationReport: sampleAttestationReport},
			opts:    Options{Validation: validate.Options{DisableRefCheck: true}},
			wantState: &pb.GpuInfoState{
				GpuUuid: "gpu-verified-ok", MeasurementsMatched: false,
			},
		},
		{
			name:       "failure_verify_gpu_info",
			gpuInfo:    &pb.GpuInfo{AttestationReport: sampleAttestationReport},
			opts:       Options{},
			gpuInfoErr: errDummy,
			wantErr:    errDummy,
		},
		{
			name:                         "failure_validate_report",
			gpuInfo:                      &pb.GpuInfo{AttestationReport: sampleAttestationReport},
			opts:                         Options{},
			validateAttestationReportErr: errDummy,
			wantErr:                      errDummy,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.verifyGpuInfo = func(context.Context, *pb.GpuInfo, verify.Options) (*pb.GpuInfoState, error) {
				return &pb.GpuInfoState{GpuUuid: "gpu-verified-ok"}, tc.gpuInfoErr
			}
			tc.opts.validateAttestationReport = func(context.Context, []byte, validate.Options) error {
				if tc.validateAttestationReportErr != nil {
					return tc.validateAttestationReportErr
				}
				return nil
			}
			gotState, gotErr := VerifyGpuQuote(context.Background(), tc.gpuInfo, tc.opts)

			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("VerifyGpuQuote() got error %v, want %v", gotErr, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.wantState, gotState, protocmp.Transform()); diff != "" {
				t.Errorf("VerifyGpuQuote() state mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestVerifyGpuQuoteWithActualData(t *testing.T) {
	goodOCSPState := &pb.OcspState{OcspStatus: pb.OcspStatus_OCSP_STATUS_GOOD}
	goodRimState := &pb.RimState{
		SchemaValidated:   true,
		VersionMatched:    true,
		CertChainOcsp:     goodOCSPState,
		SignatureVerified: true,
	}
	validOcspTime, err := time.Parse(time.RFC3339, "2025-09-21T00:00:00Z")
	if err != nil {
		t.Fatalf("Failed to parse validOcspTime: %v", err)
	}

	driverRimXML, err := td.ReadXMLFile("rim/NV_GPU_DRIVER_GH100_550.90.07.xml")
	if err != nil {
		t.Fatalf("Failed to read driver RIM file: %v", err)
	}
	vbiosRimXML, err := td.ReadXMLFile("rim/NV_GPU_VBIOS_1010_0200_882_96009F0001.xml")
	if err != nil {
		t.Fatalf("Failed to read vbios RIM file: %v", err)
	}

	gpuInfo := &pb.GpuInfo{
		Uuid:                        "gpu-uuid-1",
		DriverVersion:               td.RawGpuAttestationReportTestData.DriverVersion,
		VbiosVersion:                td.RawGpuAttestationReportTestData.VBiosVersion,
		GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
		AttestationCertificateChain: td.GpuAttestationCertificateChain,
		AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
	}
	rimClient := &testmock.MockRimClient{
		FetchRIMFunc: func(ctx context.Context, rimID string) ([]byte, error) {
			switch rimID {
			case td.ExpectedGpuDriverRimFileID:
				return []byte(driverRimXML), nil
			case td.ExpectedGpuVbiosRimFileID:
				return []byte(vbiosRimXML), nil
			default:
				return nil, fmt.Errorf("mock rim client: received unexpected rimID %q", rimID)
			}
		},
	}
	opts := Options{
		Verification: verify.Options{
			GpuOpts: verify.GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER, MaxCertChainLength: 5},
			OcspClient: &testmock.MockOcspClient{
				ResponsesBySerial: map[string]*ocsp.Response{
					td.ParsedGpuOcspResponseCertL4.SerialNumber.String():       td.ParsedGpuOcspResponseCertL4,
					td.ParsedGpuOcspResponseCertL3.SerialNumber.String():       td.ParsedGpuOcspResponseCertL3,
					td.ParsedGpuOcspResponseCertL2.SerialNumber.String():       td.ParsedGpuOcspResponseCertL2,
					td.ParsedDriverRimOcspResponseCertL4.SerialNumber.String(): td.ParsedDriverRimOcspResponseCertL4,
					td.ParsedVbiosRimOcspResponseCertL4.SerialNumber.String():  td.ParsedVbiosRimOcspResponseCertL4,
					td.ParsedRimOcspResponseCertL3.SerialNumber.String():       td.ParsedRimOcspResponseCertL3,
					td.ParsedRimOcspResponseCertL2.SerialNumber.String():       td.ParsedRimOcspResponseCertL2,
				},
			},
			Now:       &verify.TimeSet{DeviceOCSPCertChain: validOcspTime, RIMCertChain: validOcspTime},
			RimClient: rimClient,
		},
		Validation: validate.Options{
			RimClient: rimClient,
			Nonce:     td.RawGpuAttestationReportTestData.Nonce,
			GpuArch:   pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
		},
	}
	wantState := &pb.GpuInfoState{
		GpuUuid:                     "gpu-uuid-1",
		DriverVersion:               td.RawGpuAttestationReportTestData.DriverVersion,
		VbiosVersion:                td.RawGpuAttestationReportTestData.VBiosVersion,
		CertChainOcsp:               goodOCSPState,
		SignatureVerified:           true,
		DriverRim:                   goodRimState,
		VbiosRim:                    goodRimState,
		AttestationCertificateChain: td.GpuAttestationCertificateChain,
		MeasurementsMatched:         true,
	}

	gotInfoState, err := VerifyGpuQuote(context.Background(), gpuInfo, opts)
	if err != nil {
		t.Fatalf("VerifyGpuQuote() got unexpected error: %v", err)
	}
	if diff := cmp.Diff(wantState, gotInfoState, protocmp.Transform()); diff != "" {
		t.Errorf("VerifyGpuQuote() returned diff (-want +got):\n%s", diff)
	}
}
