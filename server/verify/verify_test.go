package verify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	nvattestocsp "github.com/google/go-nvattest-tools/server/ocsp"
	"github.com/google/go-nvattest-tools/server/rim"
	"github.com/google/go-nvattest-tools/server/utility"
	td "github.com/google/go-nvattest-tools/testing/testdata"
	test "github.com/google/go-nvattest-tools/testing"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/go-nvattest-tools/proto/nvattest"
)

// Adjust currentTime to compare against so that the validity with respect to time is always true.
var currentTime = time.Date(2025, time.September, 1, 1, 0, 0, 0, time.UTC)

// createFakeRoot generates a self-signed X.509 certificate that can act as a root CA.
func createFakeRoot() (*x509.Certificate, *rsa.PrivateKey, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Fake Root CA"},
			CommonName:   "Test Root",
		},
		NotBefore:             currentTime.Add(-10 * time.Second),
		NotAfter:              currentTime.AddDate(1, 0, 0), // Valid for one year
		IsCA:                  true,
		BasicConstraintsValid: true,

		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, rootKey, nil
}

func TestVerifyOCSPSuccess(t *testing.T) {
	// This is the simple mock pattern. It uses a single variable to capture arguments.
	var capturedArgs struct {
		callCount               int
		lastOCSPCertChainLength int
	}

	// extract certificate chain from testdata for only testing the OCSP verification flow.
	testChain, err := ParsePEMCertificateChain(td.GpuAttestationCertificateChain)
	trustedRootPool := x509.NewCertPool()
	trustedRootPool.AddCert(testChain[len(testChain)-1])
	if err != nil {
		t.Fatalf("Failed to extract certificate chain from testdata: %v", err)
	}

	testCases := []struct {
		name                     string
		mode                     verificationMode
		opts                     Options
		mockOCSPResponse         []*ocsp.Response
		wantOCSPState            *pb.OcspState
		wantVerifyChainCallCount int
		wantOCSPCertChainLength  int
	}{
		{
			name:                     "rim_mode_all_good",
			mode:                     verificationModeRIM,
			opts:                     Options{AllowOCSPCertHold: true},
			mockOCSPResponse:         test.CreateMockOcspResponses(testChain, ocsp.Good, 0),
			wantOCSPState:            &pb.OcspState{OcspStatus: pb.OcspStatus_OCSP_STATUS_GOOD},
			wantVerifyChainCallCount: 4,
			wantOCSPCertChainLength:  3,
		},
		{
			name:                     "gpu_mode_skip_leaf",
			mode:                     verificationModeGPU,
			opts:                     Options{GpuOpts: GPUOpts{MaxCertChainLength: 10}},
			mockOCSPResponse:         test.CreateMockOcspResponses(testChain[1:], ocsp.Good, 0),
			wantOCSPState:            &pb.OcspState{OcspStatus: pb.OcspStatus_OCSP_STATUS_GOOD},
			wantVerifyChainCallCount: 3,
			wantOCSPCertChainLength:  3,
		},
		{
			name:                     "switch_mode_skip_leaf",
			mode:                     verificationModeSwitch,
			opts:                     Options{SwitchOpts: SwitchOpts{MaxCertChainLength: 5}},
			mockOCSPResponse:         test.CreateMockOcspResponses(testChain[1:], ocsp.Good, 0),
			wantOCSPState:            &pb.OcspState{OcspStatus: pb.OcspStatus_OCSP_STATUS_GOOD},
			wantVerifyChainCallCount: 3,
			wantOCSPCertChainLength:  3,
		},
		{
			name:             "rim_mode_cert_hold_allowed",
			mode:             verificationModeRIM,
			opts:             Options{AllowOCSPCertHold: true},
			mockOCSPResponse: test.CreateMockOcspResponses(testChain, ocsp.Revoked, ocsp.CertificateHold),
			wantOCSPState: &pb.OcspState{
				OcspStatus:           pb.OcspStatus_OCSP_STATUS_REVOKED,
				OcspRevocationReason: "CertificateHold",
			},
			wantVerifyChainCallCount: 4,
			wantOCSPCertChainLength:  3,
		},
		{
			name:                     "disable_ocsp_check",
			mode:                     verificationModeRIM,
			opts:                     Options{DisableOCSPCheck: true},
			mockOCSPResponse:         nil,
			wantOCSPState:            nil,
			wantVerifyChainCallCount: 0,
			wantOCSPCertChainLength:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			capturedArgs.callCount = 0
			capturedArgs.lastOCSPCertChainLength = 0

			opts := tc.opts
			opts.OcspClient = &test.MockOcspClient{ResponsesToReturn: tc.mockOCSPResponse}
			opts.verifyCertificateChainWithOCSP = defaultVerifyCertificateChainWithOCSP
			opts.verifyCertificateChain = func(trustedRoots *x509.CertPool, chain []*x509.Certificate, wantLength int, timestamp time.Time, keyUsages ...x509.ExtKeyUsage) error {
				capturedArgs.callCount++
				capturedArgs.lastOCSPCertChainLength = wantLength
				return nil
			}
			opts.checkOCSPResponseSignature = func(_ *x509.Certificate, _ x509.SignatureAlgorithm, _, _ []byte) error {
				return nil // For success tests, the signature is always considered valid.
			}

			state, err := opts.verifyCertificateChainWithOCSP(context.Background(), testChain, trustedRootPool, opts, tc.mode, currentTime)
			if err != nil {
				t.Fatalf("verifyCertificateChainWithOCSP() returned unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.wantOCSPState, state, protocmp.Transform()); diff != "" {
				t.Errorf("verifyCertificateChainWithOCSP() returned unexpected diff (-want +got):\n%s", diff)
			}
			if capturedArgs.callCount != tc.wantVerifyChainCallCount {
				t.Errorf("verifyCertificateChain was called %d times, want %d", capturedArgs.callCount, tc.wantVerifyChainCallCount)
			}
			if capturedArgs.lastOCSPCertChainLength != tc.wantOCSPCertChainLength {
				t.Errorf("verifyCertificateChain was called with chain length %d, want %d", capturedArgs.lastOCSPCertChainLength, tc.wantOCSPCertChainLength)
			}

		})
	}
}

func TestVerifyOCSPFailure(t *testing.T) {
	var (
		mockSignatureErr   error
		mockVerifyChainErr error
	)

	testChain, err := ParsePEMCertificateChain(td.GpuAttestationCertificateChain)
	if err != nil {
		t.Fatalf("Failed to extract certificate chain from testdata: %v", err)
	}
	// The immediate issuer of the leaf certificate.
	leafsIssuer := testChain[1]
	// The issuer of the intermediate certificate.
	intermediatesIssuer := testChain[2]
	errMock := errors.New("mock error")
	trustedRootPool := x509.NewCertPool()
	trustedRootPool.AddCert(testChain[len(testChain)-1])

	testCases := []struct {
		name               string
		mode               verificationMode
		opts               Options
		mockOCSPResponse   []*ocsp.Response
		mockOcspClientErr  error
		mockVerifyChainErr error
		mockSignatureErr   error
		wantErr            error
		wantOCSPState      *pb.OcspState
	}{
		{
			name:              "fetch_error",
			mode:              verificationModeRIM,
			mockOCSPResponse:  []*ocsp.Response{test.CreateMockOcspResponse(ocsp.Good, 0, leafsIssuer)},
			mockOcspClientErr: errMock,
			wantErr:           errMock,
		},
		{
			name: "missing_responder_cert",
			mode: verificationModeRIM,
			mockOCSPResponse: []*ocsp.Response{
				test.CreateMockOcspResponse(ocsp.Good, 0, nil),
			},
			wantErr: ErrOCSPMissingResponderCert,
		},
		{
			name: "verify_chain_error",
			mode: verificationModeRIM,
			mockOCSPResponse: []*ocsp.Response{
				test.CreateMockOcspResponse(ocsp.Good, 0, leafsIssuer),
			},
			mockVerifyChainErr: errMock,
			wantErr:            errMock,
		},
		{
			name: "ocsp_signature_error",
			mode: verificationModeRIM,
			mockOCSPResponse: []*ocsp.Response{
				test.CreateMockOcspResponse(ocsp.Good, 0, leafsIssuer),
			},
			mockSignatureErr: errMock,
			wantErr:          errMock,
		},
		{
			name: "status_unknown",
			mode: verificationModeRIM,
			mockOCSPResponse: []*ocsp.Response{
				test.CreateMockOcspResponse(ocsp.Unknown, 0, leafsIssuer),
			},
			wantErr: ErrOCSPUnknownStatus,
			wantOCSPState: &pb.OcspState{
				OcspStatus: pb.OcspStatus_OCSP_STATUS_UNKNOWN,
			},
		},
		{
			name: "status_revoked_fatal",
			mode: verificationModeRIM,
			mockOCSPResponse: []*ocsp.Response{
				test.CreateMockOcspResponse(ocsp.Revoked, ocsp.KeyCompromise, leafsIssuer),
			},
			wantErr: ErrOCSPRevoked,
			wantOCSPState: &pb.OcspState{
				OcspStatus:           pb.OcspStatus_OCSP_STATUS_REVOKED,
				OcspRevocationReason: "KeyCompromise",
			},
		},
		{
			name: "cert_hold_disallowed_rim_mode",
			mode: verificationModeRIM,
			opts: Options{AllowOCSPCertHold: false},
			mockOCSPResponse: []*ocsp.Response{
				test.CreateMockOcspResponse(ocsp.Revoked, ocsp.CertificateHold, leafsIssuer),
			},
			wantErr: ErrOCSPRevoked,
			wantOCSPState: &pb.OcspState{
				OcspStatus:           pb.OcspStatus_OCSP_STATUS_REVOKED,
				OcspRevocationReason: "CertificateHold",
			},
		},
		{
			name: "cert_hold_allowed_gpu_mode",
			mode: verificationModeGPU,
			opts: Options{AllowOCSPCertHold: true},
			mockOCSPResponse: []*ocsp.Response{
				test.CreateMockOcspResponse(ocsp.Revoked, ocsp.CertificateHold, intermediatesIssuer),
			},
			wantErr: ErrOCSPRevoked,
			wantOCSPState: &pb.OcspState{
				OcspStatus:           pb.OcspStatus_OCSP_STATUS_REVOKED,
				OcspRevocationReason: "CertificateHold",
			},
		},
		{
			name: "rim_mode_fails_on_revoked_intermediate",
			mode: verificationModeRIM,
			opts: Options{},
			mockOCSPResponse: []*ocsp.Response{
				test.CreateMockOcspResponse(ocsp.Good, 0, leafsIssuer),
				test.CreateMockOcspResponse(ocsp.Revoked, ocsp.KeyCompromise, intermediatesIssuer),
			},
			wantErr: ErrOCSPRevoked,
			wantOCSPState: &pb.OcspState{
				OcspStatus:           pb.OcspStatus_OCSP_STATUS_REVOKED,
				OcspRevocationReason: "KeyCompromise",
			},
		},
		{
			name:             "invalid_ocsp_status",
			mode:             verificationModeRIM,
			opts:             Options{},
			mockOCSPResponse: []*ocsp.Response{test.CreateMockOcspResponse(-1, 0, leafsIssuer)},
			wantErr:          ErrInvalidOCSPStatus,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockVerifyChainErr = tc.mockVerifyChainErr
			mockSignatureErr = tc.mockSignatureErr
			opts := tc.opts
			opts.OcspClient = &test.MockOcspClient{
				ResponsesToReturn: tc.mockOCSPResponse,
				ErrToReturn:       tc.mockOcspClientErr,
			}
			opts.verifyCertificateChainWithOCSP = defaultVerifyCertificateChainWithOCSP
			opts.checkOCSPResponseSignature = func(_ *x509.Certificate, _ x509.SignatureAlgorithm, _, _ []byte) error {
				return mockSignatureErr
			}
			opts.verifyCertificateChain = func(trustedRoots *x509.CertPool, chain []*x509.Certificate, wantLength int, timestamp time.Time, keyUsages ...x509.ExtKeyUsage) error {
				return mockVerifyChainErr
			}
			gotState, err := opts.verifyCertificateChainWithOCSP(context.Background(), testChain, trustedRootPool, opts, tc.mode, currentTime)
			if err == nil {
				t.Fatalf("verifyCertificateChainWithOCSP() got nil error, want error containing %q", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("verifyCertificateChainWithOCSP() error = %v, want %v", err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.wantOCSPState, gotState, protocmp.Transform()); diff != "" {
				t.Errorf("verifyCertificateChainWithOCSP() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}

}

func TestVerifyCertificateChain(t *testing.T) {
	validCertChain, err := ParsePEMCertificateChain(td.GpuAttestationCertificateChain)
	if err != nil {
		t.Fatalf("extractCertificateChain(%v) failed: %v", td.GpuAttestationCertificateChain, err)
	}
	fakeRoot, _, err := createFakeRoot()
	if err != nil {
		t.Fatalf("createFakeRoot() failed: %v", err)
	}

	maxCertChainLength := len(validCertChain)
	strictTestChain, err := createTestChain()
	if err != nil {
		t.Fatalf("createTestChain() failed: %v", err)
	}

	trustedRootPool := x509.NewCertPool()
	trustedRootPool.AddCert(validCertChain[len(validCertChain)-1])
	untrustedRootPool := x509.NewCertPool()
	untrustedRootPool.AddCert(fakeRoot)
	trustedStrictChainRootPool := x509.NewCertPool()
	trustedStrictChainRootPool.AddCert(strictTestChain[len(strictTestChain)-1])

	testCases := []struct {
		name               string
		trustedRoots       *x509.CertPool
		certChain          []*x509.Certificate
		maxCertChainLength int
		wantErr            error
		wantErrMsg         string
	}{
		{
			name:               "valid_cert_chain",
			trustedRoots:       trustedRootPool,
			certChain:          validCertChain,
			maxCertChainLength: maxCertChainLength,
			wantErr:            nil,
		},
		{
			name:               "valid_chain_length_3",
			trustedRoots:       trustedRootPool,
			certChain:          validCertChain[:3],
			maxCertChainLength: 3,
			wantErr:            nil,
		},
		{
			name:               "valid_chain_length_2",
			trustedRoots:       trustedRootPool,
			certChain:          validCertChain[:2],
			maxCertChainLength: 2,
			wantErr:            nil,
		},
		{
			name:               "valid_chain_length_1",
			trustedRoots:       trustedRootPool,
			certChain:          validCertChain[:1],
			maxCertChainLength: 1,
			wantErr:            nil,
		},
		{
			name:               "empty_cert_chain",
			trustedRoots:       trustedRootPool,
			certChain:          nil,
			maxCertChainLength: maxCertChainLength,
			wantErr:            ErrNoCertificateChain,
		},
		{
			name:               "incorrect_cert_chain_length",
			trustedRoots:       trustedRootPool,
			certChain:          validCertChain[:len(validCertChain)-1],
			maxCertChainLength: maxCertChainLength,
			wantErr:            ErrIncorrectNumberOfCertificates,
		},
		{
			name:               "invalid_cert_chain",
			trustedRoots:       untrustedRootPool,
			certChain:          validCertChain,
			maxCertChainLength: maxCertChainLength,
			wantErrMsg:         "verifying certificate chain",
		},
		{
			name:               "chain_with_intermediate",
			trustedRoots:       trustedStrictChainRootPool,
			certChain:          strictTestChain,
			maxCertChainLength: 3,
			wantErr:            nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := defaultVerifyCertificateChain(tc.trustedRoots, tc.certChain, tc.maxCertChainLength, currentTime)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("verifyCertificateChain() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErrMsg != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrMsg)) {
				t.Errorf("verifyCertificateChain() error = %v, want %v", err, tc.wantErrMsg)
			}
		})
	}
}

func setUpTestDataForVerifyReport(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	certChain, err := ParsePEMCertificateChain(td.GpuAttestationCertificateChain)
	if err != nil {
		t.Fatalf("Failed to extract certificate chain: %v", err)
	}
	leafCert := certChain[0]
	return leafCert, td.RawGpuAttestationReportTestData.RawAttestationReport
}

func TestVerifyAttestationReportSignature(t *testing.T) {
	leafCert, rawReport := setUpTestDataForVerifyReport(t)
	corruptedReport := make([]byte, len(rawReport))
	copy(corruptedReport, rawReport)
	corruptedReport[55] ^= 0xFF
	rsaRootCert, _, err := createFakeRoot()
	if err != nil {
		t.Fatalf("Failed to create fake root for testing: %v", err)
	}

	testCases := []struct {
		name              string
		mode              verificationMode
		attestationReport []byte
		leafCertificate   *x509.Certificate
		wantErr           error
	}{
		{
			name:              "success_from_valid_attestation_report",
			mode:              verificationModeGPU,
			attestationReport: rawReport,
			leafCertificate:   leafCert,
			wantErr:           nil,
		},
		{
			name:              "failure_from_attestation_report_invalid",
			mode:              verificationModeGPU,
			attestationReport: corruptedReport,
			leafCertificate:   leafCert,
			wantErr:           ErrSignatureVerificationFailed,
		},
		{
			name:              "failure_from_invalid_public_key_type",
			mode:              verificationModeGPU,
			attestationReport: rawReport,
			leafCertificate:   rsaRootCert,
			wantErr:           ErrInvalidPublicKey,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := defaultVerifyAttestationReportSignature(tc.attestationReport, tc.leafCertificate, tc.mode)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("verifyAttestationReport() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestExtractGPUFWID(t *testing.T) {
	fwidOid := asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}
	validFwidBytes := make([]byte, 48)
	irrelevantOid := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	testCases := []struct {
		name          string
		cert          *x509.Certificate
		arch          pb.GpuArchitectureType
		wantErrString string
	}{
		{
			name:          "failure_no_fwid_extension",
			cert:          &x509.Certificate{},
			arch:          pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			wantErrString: ErrNoFwidFound.Error(),
		},
		{
			name: "failure_unsupported_arch",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{{Id: fwidOid, Value: validFwidBytes}},
			},
			arch:          pb.GpuArchitectureType_GPU_ARCHITECTURE_UNKNOWN,
			wantErrString: "unsupported GPU architecture",
		},
		{
			name: "failure_fwid_too_short",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{{Id: fwidOid, Value: []byte("not valid asn1")}},
			},
			arch:          pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			wantErrString: "extension value is too short",
		},
		{
			name: "success_dispatch_with_correct_extension",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{{Id: fwidOid, Value: validFwidBytes}},
			},
			arch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
		},
		{
			name: "success_with_irrelevant_extension_present",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{Id: irrelevantOid, Value: []byte("noise")}, // This should be ignored.
					{Id: fwidOid, Value: validFwidBytes},        // This should be found.
				},
			},
			arch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extractGPUFWID(tc.cert, tc.arch)
			if tc.wantErrString != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrString) {
					t.Fatalf("extractGpuFwid(%v, %v) = %v, want error containing %q", tc.cert, tc.arch, err, tc.wantErrString)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractGpuFwid(%v, %v): did not expect an error but got: %v", tc.cert, tc.arch, err)
			}
		})
	}
}

func TestExtractHopperFWID(t *testing.T) {
	// The desired 48-byte FWID payload we expect to extract.
	fwidPayload, err := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("test setup failed to decode fwidPayload hex string: %v", err)
	}

	testCases := []struct {
		name    string
		input   []byte
		want    string
		wantErr bool
	}{
		{
			name:    "success_valid_with_48_byte_payload",
			input:   fwidPayload,
			want:    hex.EncodeToString(fwidPayload),
			wantErr: false,
		},
		{
			name:    "success_with_longer_payload",
			input:   append([]byte{0xDE, 0xAD, 0xBE, 0xEF}, fwidPayload...),
			want:    hex.EncodeToString(fwidPayload),
			wantErr: false,
		},
		{
			name:    "failure_payload_too_short",
			input:   make([]byte, 47),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractHopperFWID(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("extractHopperFwid(%v): expected an error but got none", tc.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("extractHopperFwid(%v): did not expect an error but got: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("extractHopperFwid(%v): got %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestExtractBlackwellFWID(t *testing.T) {
	// --- Test Setup ---
	validFwidBytes, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	validTcbInfo := DiceTCBInfo{
		FWIDs: []FWID{{
			HashAlg: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			Digest:  validFwidBytes,
		}},
	}
	validOuterAsn1, _ := asn1.Marshal(validTcbInfo)

	// Create valid data followed by extra garbage data to test trailing data checks.
	trailingDataOuterAsn1 := append(validOuterAsn1, []byte("trailing garbage")...)

	emptyFwidsTcbInfo := DiceTCBInfo{FWIDs: nil}
	emptyFwidsOuterAsn1, _ := asn1.Marshal(emptyFwidsTcbInfo)

	malformedTcbInfoOuterAsn1 := []byte("this is not a tcbinfo struct")

	testCases := []struct {
		name    string
		input   []byte
		want    string
		wantErr error
	}{
		{
			name:    "Success_Valid_FWID",
			input:   validOuterAsn1,
			want:    hex.EncodeToString(validFwidBytes),
			wantErr: nil,
		},
		{
			name:    "Failure_Malformed_ASN1",
			input:   malformedTcbInfoOuterAsn1,
			wantErr: fmt.Errorf("failed to parse DiceTCBInfo ASN.1 structure"),
		},
		{
			name:    "Failure_Trailing_Data",
			input:   trailingDataOuterAsn1,
			wantErr: ErrTrailingData,
		},
		{
			name:    "Failure_Empty_Fwids_Slice",
			input:   emptyFwidsOuterAsn1,
			wantErr: ErrNoFwidFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractBlackwellFWID(tc.input)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("extractBlackwellFwid(%v): Expected an error but got none. Wanted error: %v", tc.input, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr.Error()) {
					t.Errorf("extractBlackwellFwid(%v): Mismatched error.\n GOT: %v\nWANT: %v", tc.input, err, tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("extractBlackwellFwid(%v): Expected no error but got: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("extractBlackwellFwid(%v): Mismatched output.\n GOT: %q\nWANT: %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestExtractSwitchFWID(t *testing.T) {
	tcgDiceFwidOid := asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}

	validFwidBytes := make([]byte, 48)
	for i := range validFwidBytes {
		validFwidBytes[i] = byte(i)
	}

	testCases := []struct {
		name          string
		cert          *x509.Certificate
		want          string
		wantErrString string
	}{
		{
			name:          "failure_no_matching_fwid_extension",
			cert:          &x509.Certificate{},
			wantErrString: ErrNoFwidFound.Error(),
		},
		{
			name: "failure_fwid_too_short",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{Id: tcgDiceFwidOid, Value: make([]byte, 47)},
				},
			},
			wantErrString: "extension value is too short",
		},
		{
			name: "success_valid_fwid",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{Id: tcgDiceFwidOid, Value: validFwidBytes},
				},
			},
			want: hex.EncodeToString(validFwidBytes),
		},
		{
			name: "success_longer_length_fwid_payload",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{Id: tcgDiceFwidOid, Value: append([]byte{0xDE, 0xAD, 0xBE, 0xEF}, validFwidBytes...)},
				},
			},
			want: hex.EncodeToString(validFwidBytes),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractSwitchFWID(tc.cert)

			if tc.wantErrString != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q but got none", tc.wantErrString)
				}
				if !strings.Contains(err.Error(), tc.wantErrString) {
					t.Fatalf("error mismatch:\n got: %v\nwant to contain: %q", err, tc.wantErrString)
				}
				return
			}

			if err != nil {
				t.Fatalf("extractSwitchFwid(%v): did not expect an error but got: %v", tc.cert, err)
			}

			if got != tc.want {
				t.Errorf("extractSwitchFwid(%v): output mismatch:\n got: %q\nwant: %q", tc.cert, got, tc.want)
			}
		})
	}
}

func TestRIMState(t *testing.T) {
	goodOCSPState := &pb.OcspState{OcspStatus: pb.OcspStatus_OCSP_STATUS_GOOD}
	dummyErr := errors.New("dummy error")

	testCases := []struct {
		name             string
		rimData          Evaluator
		version          string
		setup            func(t *testing.T)
		mockCertChainErr error
		mockOCSPErr      error
		mockOCSPState    *pb.OcspState
		wantErr          error
		wantErrMsg       string
		wantRimState     *pb.RimState
	}{
		{
			name:          "success_valid_rim",
			rimData:       &test.MockRimData{MockVersion: "96.10.6d.00.01"},
			version:       "96.10.6D.00.01",
			mockOCSPState: goodOCSPState,
			wantRimState: &pb.RimState{
				SchemaValidated:   true,
				VersionMatched:    true,
				CertChainOcsp:     goodOCSPState,
				SignatureVerified: true,
			},
		},
		{
			name: "failure_schema_validation",
			rimData: &test.MockRimData{
				MockSchemaErr: errors.New("invalid schema"),
			},
			version:       "1.0",
			mockOCSPState: goodOCSPState,
			wantRimState:  &pb.RimState{},
			wantErr:       ErrRimVerificationFailed,
			wantErrMsg:    "invalid schema",
		},
		{
			name: "warning_version_mismatch",
			rimData: &test.MockRimData{
				MockVersion: "1.0",
			},
			version:       "2.0",
			mockOCSPState: goodOCSPState,
			wantRimState: &pb.RimState{
				SchemaValidated:   true,
				VersionMatched:    false,
				CertChainOcsp:     goodOCSPState,
				SignatureVerified: true,
			},
		},
		{
			name:             "failure_cert_chain_verification",
			rimData:          &test.MockRimData{MockVersion: "1.0", MockCertChain: []*x509.Certificate{}},
			version:          "1.0",
			mockCertChainErr: dummyErr,
			wantRimState: &pb.RimState{
				SchemaValidated:   true,
				VersionMatched:    true,
				SignatureVerified: false,
			},
			wantErr:    ErrRimVerificationFailed,
			wantErrMsg: "could not verify certificate chain",
		},
		{
			name:          "failure_ocsp_verification",
			rimData:       &test.MockRimData{MockVersion: "1.0", MockCertChain: []*x509.Certificate{}},
			version:       "1.0",
			mockOCSPErr:   dummyErr,
			wantErr:       ErrRimVerificationFailed,
			wantErrMsg:    "could not verify OCSP status",
			mockOCSPState: &pb.OcspState{OcspStatus: pb.OcspStatus_OCSP_STATUS_UNKNOWN},
			wantRimState: &pb.RimState{
				SchemaValidated:   true,
				VersionMatched:    true,
				CertChainOcsp:     &pb.OcspState{OcspStatus: pb.OcspStatus_OCSP_STATUS_UNKNOWN},
				SignatureVerified: false,
			},
		},
		{
			name: "failure_rim_signature_verification",
			rimData: &test.MockRimData{
				MockVersion:   "1.0",
				MockCertChain: []*x509.Certificate{},
				MockSigErr:    dummyErr,
			},
			version:       "1.0",
			mockOCSPState: goodOCSPState,
			wantRimState: &pb.RimState{
				SchemaValidated:   true,
				VersionMatched:    true,
				CertChainOcsp:     goodOCSPState,
				SignatureVerified: false,
			},
			wantErr: ErrRimVerificationFailed,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}
			tempDir := t.TempDir()
			opts := Options{rimSchemaPath: filepath.Join(tempDir, "schema.xsd"), Now: &TimeSet{RIMCertChain: currentTime}}
			if err := os.WriteFile(opts.rimSchemaPath, []byte("<schema/>"), 0644); err != nil {
				t.Fatalf("Failed to write schema file: %v", err)
			}
			opts.verifyCertificateChain = func(_ *x509.CertPool, _ []*x509.Certificate, _ int, _ time.Time, keyUsages ...x509.ExtKeyUsage) error {
				return tc.mockCertChainErr
			}
			opts.verifyCertificateChainWithOCSP = func(_ context.Context, _ []*x509.Certificate, _ *x509.CertPool, _ Options, _ verificationMode, _ time.Time) (*pb.OcspState, error) {
				return tc.mockOCSPState, tc.mockOCSPErr
			}
			gotRimState, err := defaultVerifyRIM(t.Context(), opts, tc.rimData, tc.version)

			if tc.wantErr != nil || tc.wantErrMsg != "" {
				if err == nil {
					t.Fatal("verifyRIM() got nil error; want a non-nil error")
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("verifyRIM() error = %v; want to wrap %v", err, tc.wantErr)
				}
				if tc.wantErrMsg != "" && !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("verifyRIM() error = %v; want to contain %q", err, tc.wantErrMsg)
				}
			} else if err != nil {
				t.Fatalf("verifyRIM() got unexpected error: %v", err)
			}

			if diff := cmp.Diff(tc.wantRimState, gotRimState, protocmp.Transform()); diff != "" {
				t.Errorf("verifyRIM() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

// createTestChain builds a valid, self-contained 3-level certificate chain
// (Leaf -> Intermediate -> Root) that is ideal for strict testing.
func createTestChain() ([]*x509.Certificate, error) {
	// Step 1: Create our Root CA using your existing helper function.
	rootCert, rootKey, err := createFakeRoot()
	if err != nil {
		return nil, fmt.Errorf("createTestChain(): failed to create root CA: %w", err)
	}

	// Step 2: Create the Intermediate CA, signed by the Root CA.
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("createTestChain(): failed to generate intermediate key: %w", err)
	}
	intermediateTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Intermediate CA"},
			CommonName:   "Test Intermediate",
		},
		NotBefore:             currentTime.Add(-10 * time.Second),
		NotAfter:              currentTime.AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// Create the certificate, signing the intermediate template with the root's private key.
	intermediateDER, err := x509.CreateCertificate(rand.Reader, &intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("createTestChain(): failed to create intermediate certificate: %w", err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		return nil, fmt.Errorf("createTestChain(): failed to parse intermediate certificate: %w", err)
	}

	// Step 3: Create the Leaf (end-entity) certificate, signed by the Intermediate CA.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("createTestChain(): failed to generate leaf key: %w", err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Application"},
			CommonName:   "Test Leaf",
		},
		NotBefore:   currentTime.Add(-10 * time.Second),
		NotAfter:    currentTime.AddDate(1, 0, 0),
		IsCA:        false,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// Create the certificate, signing the leaf template with the intermediate's private key.
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		return nil, fmt.Errorf("createTestChain(): failed to create leaf certificate: %w", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("createTestChain(): failed to parse leaf certificate: %w", err)
	}

	// Step 4: Return the complete chain in the standard order: [leaf, intermediate, ..., root].
	return []*x509.Certificate{leafCert, intermediateCert, rootCert}, nil
}

func TestGpuInfo(t *testing.T) {
	dummyErr := errors.New("dummy error")
	goodOCSPState := &pb.OcspState{OcspStatus: pb.OcspStatus_OCSP_STATUS_GOOD}
	goodRimState := &pb.RimState{
		SchemaValidated:   true,
		VersionMatched:    true,
		CertChainOcsp:     goodOCSPState,
		SignatureVerified: true,
	}
	origDriverRIMData := utility.DriverRIMData
	origGpuVbiosRIMData := utility.GpuVbiosRIMData
	t.Cleanup(func() {
		utility.DriverRIMData = origDriverRIMData
		utility.GpuVbiosRIMData = origGpuVbiosRIMData
	})

	testCases := []struct {
		name                                string
		gpuInfo                             *pb.GpuInfo
		opts                                Options
		driverRimFetchErr                   error
		vbiosRimFetchErr                    error
		verifyGPUCertificateChainErr        error
		verifyCertificateChainWithOCSPErr   error
		verifyAttestationReportSignatureErr error
		driverRimVerifyErr                  error
		vbiosRimVerifyErr                   error
		wantState                           *pb.GpuInfoState
		wantErr                             error
		wantErrMsg                          string
		wantDefaultRIMClientCalls           int
		wantDefaultOCSPClientCalls          int
	}{
		{
			name: "success_valid_gpu_info",
			gpuInfo: &pb.GpuInfo{
				Uuid:                        "gpu-uuid-1",
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				GpuOpts:    GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER},
				OcspClient: &test.MockOcspClient{},
				RimClient:  &test.MockRimClient{ContentToReturn: []byte("<rim/>")},
			},
			wantState: &pb.GpuInfoState{
				GpuUuid:                     "gpu-uuid-1",
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				CertChainOcsp:               goodOCSPState,
				SignatureVerified:           true,
				DriverRim:                   goodRimState,
				VbiosRim:                    goodRimState,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
			},
		},
		{
			name: "success_rim_check_disabled",
			gpuInfo: &pb.GpuInfo{
				Uuid:                        "gpu-uuid-1",
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				GpuOpts:         GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER},
				OcspClient:      &test.MockOcspClient{},
				DisableRIMCheck: true,
			},
			wantState: &pb.GpuInfoState{
				GpuUuid:                     "gpu-uuid-1",
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				CertChainOcsp:               goodOCSPState,
				SignatureVerified:           true,
				DriverRim:                   nil,
				VbiosRim:                    nil,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
			},
			wantDefaultRIMClientCalls: 1,
		},
		{
			name: "success_ocsp_check_disabled",
			gpuInfo: &pb.GpuInfo{
				Uuid:                        "gpu-uuid-1",
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				GpuOpts:          GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER},
				RimClient:        &test.MockRimClient{ContentToReturn: []byte("<rim/>")},
				DisableOCSPCheck: true,
			},
			wantState: &pb.GpuInfoState{
				GpuUuid:                     "gpu-uuid-1",
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				CertChainOcsp:               nil,
				SignatureVerified:           true,
				DriverRim:                   goodRimState,
				VbiosRim:                    goodRimState,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
			},
			wantDefaultOCSPClientCalls: 1,
		},
		{
			name: "failure_driver_rim_fetch_error",
			gpuInfo: &pb.GpuInfo{
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				GpuOpts:    GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER},
				OcspClient: &test.MockOcspClient{},
				RimClient:  &test.MockRimClient{},
			},
			driverRimFetchErr: dummyErr,
			wantErr:           dummyErr,
		},
		{
			name: "failure_vbios_rim_fetch_error",
			gpuInfo: &pb.GpuInfo{
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				GpuOpts:    GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER},
				OcspClient: &test.MockOcspClient{},
				RimClient:  &test.MockRimClient{},
			},
			vbiosRimFetchErr: dummyErr,
			wantErr:          dummyErr,
		},
		{
			name: "failure_parse_attestation_report",
			gpuInfo: &pb.GpuInfo{
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           make([]byte, 0),
			},
			opts:       Options{GpuOpts: GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER}},
			wantErrMsg: "incorrect length of raw attestation report SPDM measurement request size",
		},
		{
			name: "failure_parse_cert_chain",
			gpuInfo: &pb.GpuInfo{
				Uuid:                        "gpu-uuid-3",
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: []byte("invalid cert"),
			},
			opts:    Options{GpuOpts: GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER}},
			wantErr: ErrNoCertificateChain,
		},
		{
			name: "failure_gpu_arch_mismatch",
			gpuInfo: &pb.GpuInfo{
				Uuid:            "gpu-uuid-13",
				GpuArchitecture: pb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL,
			},
			opts:    Options{GpuOpts: GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER}},
			wantErr: ErrGPUArchitectureMismatch,
		},
		{
			name: "failure_verify_gpu_cert_chain",
			gpuInfo: &pb.GpuInfo{
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts:                         Options{GpuOpts: GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER}},
			verifyGPUCertificateChainErr: dummyErr,
			wantErr:                      dummyErr,
		},
		{
			name: "failure_verify_ocsp",
			gpuInfo: &pb.GpuInfo{
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts:                              Options{GpuOpts: GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER}},
			verifyCertificateChainWithOCSPErr: dummyErr,
			wantErr:                           dummyErr,
		},
		{
			name: "failure_verify_signature",
			gpuInfo: &pb.GpuInfo{
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts:                                Options{GpuOpts: GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER}},
			verifyAttestationReportSignatureErr: dummyErr,
			wantErr:                             dummyErr,
		},
		{
			name: "failure_verify_driver_rim",
			gpuInfo: &pb.GpuInfo{
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				GpuOpts:    GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER},
				OcspClient: &test.MockOcspClient{},
				RimClient:  &test.MockRimClient{ContentToReturn: []byte("<rim/>")},
			},
			driverRimVerifyErr: dummyErr,
			wantErr:            dummyErr,
		},
		{
			name: "failure_verify_vbios_rim",
			gpuInfo: &pb.GpuInfo{
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				GpuOpts:    GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER},
				OcspClient: &test.MockOcspClient{},
				RimClient:  &test.MockRimClient{ContentToReturn: []byte("<rim/>")},
			},
			vbiosRimVerifyErr: dummyErr,
			wantErr:           dummyErr,
		},
		{
			name: "success_valid_gpu_info_with_default_rim_and_ocsp_clients",
			gpuInfo: &pb.GpuInfo{
				Uuid:                        "gpu-uuid-1",
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				GpuArchitecture:             pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
				AttestationReport:           td.RawGpuAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				GpuOpts: GPUOpts{GPUArch: pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER},
			},
			wantState: &pb.GpuInfoState{
				GpuUuid:                     "gpu-uuid-1",
				DriverVersion:               "driver-version-1",
				VbiosVersion:                "vbios-version-1",
				CertChainOcsp:               goodOCSPState,
				SignatureVerified:           true,
				DriverRim:                   goodRimState,
				VbiosRim:                    goodRimState,
				AttestationCertificateChain: td.GpuAttestationCertificateChain,
			},
			wantDefaultRIMClientCalls:  1,
			wantDefaultOCSPClientCalls: 1,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var defaultRimClientCallCount int
			tc.opts.newRimClient = func(httpClient *http.Client, serviceKey string) rim.Client {
				defaultRimClientCallCount++
				return &test.MockRimClient{ContentToReturn: []byte("<rim/>")}
			}
			var defaultOcspClientCallCount int
			tc.opts.newOcspClient = func(httpClient *http.Client, serviceKey string) nvattestocsp.Client {
				defaultOcspClientCallCount++
				return &test.MockOcspClient{}
			}

			tc.opts.verifyGPUCertificateChain = func([]*x509.Certificate, *x509.CertPool, Options, string) error {
				return tc.verifyGPUCertificateChainErr
			}
			tc.opts.verifyCertificateChainWithOCSP = func(context.Context, []*x509.Certificate, *x509.CertPool, Options, verificationMode, time.Time) (*pb.OcspState, error) {
				if tc.opts.DisableOCSPCheck {
					return nil, nil
				}
				return goodOCSPState, tc.verifyCertificateChainWithOCSPErr
			}

			tc.opts.verifyRIM = func(ctx context.Context, opts Options, evaluator Evaluator, version string) (*pb.RimState, error) {
				if tc.gpuInfo != nil {
					if version == tc.gpuInfo.GetDriverVersion() && tc.driverRimVerifyErr != nil {
						return nil, tc.driverRimVerifyErr
					}
					if version == tc.gpuInfo.GetVbiosVersion() && tc.vbiosRimVerifyErr != nil {
						return nil, tc.vbiosRimVerifyErr
					}
				}
				if evaluator == nil {
					return &pb.RimState{}, nil
				}
				return goodRimState, nil
			}

			utility.DriverRIMData = func(ctx context.Context, driverVersion string, reportProto *pb.AttestationReport, newRimClient rim.Client, gpuArch pb.GpuArchitectureType) (*rim.Data, error) {
				if tc.driverRimFetchErr != nil {
					return nil, tc.driverRimFetchErr
				}
				return &rim.Data{}, nil
			}
			utility.GpuVbiosRIMData = func(ctx context.Context, reportProto *pb.AttestationReport, newRimClient rim.Client) (*rim.Data, error) {
				if tc.vbiosRimFetchErr != nil {
					return nil, tc.vbiosRimFetchErr
				}
				return &rim.Data{}, nil
			}
			tc.opts.verifyAttestationReportSignature = func([]byte, *x509.Certificate, verificationMode) error {
				return tc.verifyAttestationReportSignatureErr
			}

			gotInfoState, err := GpuInfo(context.Background(), tc.gpuInfo, tc.opts)

			if tc.wantErr != nil || tc.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("GpuInfo() got nil error, want error containing %q", tc.wantErr)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("GpuInfo() error mismatch: got %v, want %v", err, tc.wantErr)
				}
				if tc.wantErrMsg != "" && !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("GpuInfo() error mismatch: got %v, want to contain %q", err, tc.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("GpuInfo() got unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.wantState, gotInfoState, protocmp.Transform()); diff != "" {
				t.Errorf("GpuInfo() returned diff (-want +got):\n%s", diff)
			}
			if defaultRimClientCallCount != tc.wantDefaultRIMClientCalls {
				t.Errorf("GpuInfo() defaultRimClient call count mismatch: got %d, want %d", defaultRimClientCallCount, tc.wantDefaultRIMClientCalls)
			}
			if defaultOcspClientCallCount != tc.wantDefaultOCSPClientCalls {
				t.Errorf("GpuInfo() defaultOcspClient call count mismatch: got %d, want %d", defaultOcspClientCallCount, tc.wantDefaultOCSPClientCalls)
			}
		})
	}
}

func TestSwitchInfo(t *testing.T) {
	dummyErr := errors.New("dummy error")
	goodOCSPState := &pb.OcspState{OcspStatus: pb.OcspStatus_OCSP_STATUS_GOOD}
	goodRimState := &pb.RimState{
		SchemaValidated:   true,
		VersionMatched:    true,
		CertChainOcsp:     goodOCSPState,
		SignatureVerified: true,
	}

	testCases := []struct {
		name                                string
		switchInfo                          *pb.SwitchInfo
		opts                                Options
		biosRimFetchErr                     error
		verifySwitchCertificateChainErr     error
		verifyCertificateChainWithOCSPErr   error
		verifyAttestationReportSignatureErr error
		biosRimVerifyErr                    error
		wantState                           *pb.SwitchInfoState
		wantErr                             error
		wantErrMsg                          string
		wantDefaultRIMClientCalls           int
		wantDefaultOCSPClientCalls          int
	}{
		{
			name: "success_valid_switch_info",
			switchInfo: &pb.SwitchInfo{
				Uuid:                        "switch-uuid-1",
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				OcspClient: &test.MockOcspClient{},
				RimClient:  &test.MockRimClient{ContentToReturn: []byte("<rim/>")},
			},
			wantState: &pb.SwitchInfoState{
				BiosVersion:                 "96.10.6D.00.01",
				SwitchUuid:                  "switch-uuid-1",
				CertChainOcsp:               goodOCSPState,
				SignatureVerified:           true,
				BiosRim:                     goodRimState,
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
			},
		},
		{
			name: "success_rim_check_disabled",
			switchInfo: &pb.SwitchInfo{
				Uuid:                        "switch-uuid-1",
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				OcspClient:      &test.MockOcspClient{},
				DisableRIMCheck: true,
			},
			wantState: &pb.SwitchInfoState{
				BiosVersion:                 "96.10.6D.00.01",
				SwitchUuid:                  "switch-uuid-1",
				CertChainOcsp:               goodOCSPState,
				SignatureVerified:           true,
				BiosRim:                     nil,
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
			},
			wantDefaultRIMClientCalls: 1,
		},
		{
			name: "success_ocsp_check_disabled",
			switchInfo: &pb.SwitchInfo{
				Uuid:                        "switch-uuid-1",
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				RimClient:        &test.MockRimClient{ContentToReturn: []byte("<rim/>")},
				DisableOCSPCheck: true,
			},
			wantState: &pb.SwitchInfoState{
				BiosVersion:                 "96.10.6D.00.01",
				SwitchUuid:                  "switch-uuid-1",
				CertChainOcsp:               nil,
				SignatureVerified:           true,
				BiosRim:                     goodRimState,
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
			},
			wantDefaultOCSPClientCalls: 1,
		},
		{
			name: "failure_bios_rim_fetch_error",
			switchInfo: &pb.SwitchInfo{
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				OcspClient: &test.MockOcspClient{},
				RimClient:  &test.MockRimClient{},
			},
			biosRimFetchErr: dummyErr,
			wantErr:         dummyErr,
		},
		{
			name: "failure_parse_attestation_report",
			switchInfo: &pb.SwitchInfo{
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           make([]byte, 0),
			},
			wantErrMsg: "incorrect length of raw attestation report SPDM measurement request size",
		},
		{
			name: "failure_parse_cert_chain",
			switchInfo: &pb.SwitchInfo{
				Uuid:                        "switch-uuid-3",
				AttestationCertificateChain: []byte("invalid cert"),
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			wantErr: ErrNoCertificateChain,
		},
		{
			name: "failure_verify_switch_cert_chain",
			switchInfo: &pb.SwitchInfo{
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			verifySwitchCertificateChainErr: dummyErr,
			wantErr:                         dummyErr,
		},
		{
			name: "failure_verify_ocsp",
			switchInfo: &pb.SwitchInfo{
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			verifyCertificateChainWithOCSPErr: dummyErr,
			wantErr:                           dummyErr,
		},
		{
			name: "failure_verify_signature",
			switchInfo: &pb.SwitchInfo{
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			verifyAttestationReportSignatureErr: dummyErr,
			wantErr:                             dummyErr,
		},
		{
			name: "failure_verify_bios_rim",
			switchInfo: &pb.SwitchInfo{
				Uuid:                        "switch-uuid-12",
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{
				OcspClient: &test.MockOcspClient{},
				RimClient:  &test.MockRimClient{ContentToReturn: []byte("<rim/>")},
			},
			biosRimVerifyErr: dummyErr,
			wantErr:          dummyErr,
		},
		{
			name: "success_valid_switch_info_with_default_clients",
			switchInfo: &pb.SwitchInfo{
				Uuid:                        "switch-uuid-1",
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
				AttestationReport:           td.RawSwitchAttestationReportTestData.RawAttestationReport,
			},
			opts: Options{},
			wantState: &pb.SwitchInfoState{
				BiosVersion:                 "96.10.6D.00.01",
				SwitchUuid:                  "switch-uuid-1",
				CertChainOcsp:               goodOCSPState,
				SignatureVerified:           true,
				BiosRim:                     goodRimState,
				AttestationCertificateChain: td.SwitchAttestationCertificateChain,
			},
			wantDefaultRIMClientCalls:  1,
			wantDefaultOCSPClientCalls: 1,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var defaultRimClientCallCount int
			tc.opts.newRimClient = func(httpClient *http.Client, serviceKey string) rim.Client {
				defaultRimClientCallCount++
				return &test.MockRimClient{ContentToReturn: []byte("<rim/>")}
			}
			var defaultOcspClientCallCount int
			tc.opts.newOcspClient = func(httpClient *http.Client, serviceKey string) nvattestocsp.Client {
				defaultOcspClientCallCount++
				return &test.MockOcspClient{}
			}

			tc.opts.verifySwitchCertificateChain = func([]*x509.Certificate, *x509.CertPool, Options, string) error {
				return tc.verifySwitchCertificateChainErr
			}
			tc.opts.verifyCertificateChainWithOCSP = func(context.Context, []*x509.Certificate, *x509.CertPool, Options, verificationMode, time.Time) (*pb.OcspState, error) {
				if tc.opts.DisableOCSPCheck {
					return nil, nil
				}
				return goodOCSPState, tc.verifyCertificateChainWithOCSPErr
			}
			tc.opts.verifyAttestationReportSignature = func([]byte, *x509.Certificate, verificationMode) error {
				return tc.verifyAttestationReportSignatureErr
			}
			tc.opts.verifyRIM = func(ctx context.Context, opts Options, evaluator Evaluator, version string) (*pb.RimState, error) {
				if tc.biosRimVerifyErr != nil {
					return nil, tc.biosRimVerifyErr
				}
				if evaluator == nil {
					return &pb.RimState{}, nil
				}
				return goodRimState, nil
			}
			utility.SwitchBiosRIMData = func(ctx context.Context, reportProto *pb.AttestationReport, newRimClient rim.Client) (*rim.Data, error) {
				if tc.biosRimFetchErr != nil {
					return nil, tc.biosRimFetchErr
				}
				return &rim.Data{}, nil
			}

			gotInfoState, err := SwitchInfo(context.Background(), tc.switchInfo, tc.opts)

			if tc.wantErr != nil || tc.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("SwitchInfo() got nil error, want error containing %q", tc.wantErr)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("SwitchInfo() error mismatch: got %v, want %v", err, tc.wantErr)
				}
				if tc.wantErrMsg != "" && !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("SwitchInfo() error mismatch: got %v, want to contain %q", err, tc.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("SwitchInfo() got unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.wantState, gotInfoState, protocmp.Transform()); diff != "" {
				t.Errorf("SwitchInfo() returned diff (-want +got):\n%s", diff)
			}
			if defaultRimClientCallCount != tc.wantDefaultRIMClientCalls {
				t.Errorf("SwitchInfo() defaultRimClient call count mismatch: got %d, want %d", defaultRimClientCallCount, tc.wantDefaultRIMClientCalls)
			}
			if defaultOcspClientCallCount != tc.wantDefaultOCSPClientCalls {
				t.Errorf("SwitchInfo() defaultOcspClient call count mismatch: got %d, want %d", defaultOcspClientCallCount, tc.wantDefaultOCSPClientCalls)
			}
		})
	}
}
