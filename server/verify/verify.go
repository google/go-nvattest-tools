// Package verify provides the implementation for GPU and Switch devices verification.
package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-nvattest-tools/abi"
	pb "github.com/google/go-nvattest-tools/proto/nvattest"
	"github.com/google/go-nvattest-tools/server/cert"
	nvattestocsp "github.com/google/go-nvattest-tools/server/ocsp"
	"github.com/google/go-nvattest-tools/server/rim"
	"github.com/google/go-nvattest-tools/server/utility"
	"golang.org/x/crypto/ocsp"
)

type verificationMode int

const (
	// signatureLength specifies the byte length for a raw ECDSA signature using the P-384 curve.
	signatureLength                                    = 96
	minCertChainLengthForIntermediate                  = 3
	verificationModeGPU               verificationMode = 0
	verificationModeSwitch            verificationMode = 1
	verificationModeRIM               verificationMode = 2
)

var (
	// ErrNoCertificateChain is returned when no certificate chain is found in the attestation report.
	ErrNoCertificateChain = fmt.Errorf("no certificate chain found in the attestation report")
	// ErrIncorrectNumberOfCertificates is returned when the number of certificates in the certificate chain is not as expected.
	ErrIncorrectNumberOfCertificates = fmt.Errorf("incorrect number of certificates in the certificate chain")
	// ErrNoFwidFound is returned when no FWID is found in the certificate.
	ErrNoFwidFound = fmt.Errorf("no FWID found in the certificate")
	// ErrOCSPMissingResponderCert is returned when the OCSP response is missing the responder's certificate.
	ErrOCSPMissingResponderCert = fmt.Errorf("OCSP response for cert is missing the responder's certificate")
	// ErrOCSPUnknownStatus is returned when the OCSP status is UNKNOWN.
	ErrOCSPUnknownStatus = fmt.Errorf("OCSP status is UNKNOWN")
	// ErrOCSPRevoked is returned when the OCSP status is REVOKED.
	ErrOCSPRevoked = fmt.Errorf("OCSP status is REVOKED")
	// ErrInvalidPublicKey is returned when the public key is not an ECDSA key.
	ErrInvalidPublicKey = fmt.Errorf("public key is not an ECDSA key")
	// ErrSignatureVerificationFailed is returned when the signature verification fails.
	ErrSignatureVerificationFailed = fmt.Errorf("ECDSA signature verification failed")
	// ErrRimVerificationFailed is returned when the RIM verification fails.
	ErrRimVerificationFailed = fmt.Errorf("RIM verification failed")
	// ErrInvalidOCSPStatus is returned when the OCSP status is invalid.
	ErrInvalidOCSPStatus = fmt.Errorf("invalid OCSP status")
	// ErrTrailingData is returned when unexpected trailing data is found in the ASN.1 structure.
	ErrTrailingData = fmt.Errorf("unexpected trailing data found in the ASN.1 structure")
	// ErrGPUArchitectureMismatch is returned when the GPU architecture in the attestation report does not match the expected architecture.
	ErrGPUArchitectureMismatch = fmt.Errorf("GPU architecture mismatch")
)

// Options holds configuration parameters needed for the verification process provided by the user.
type Options struct {
	AllowOCSPCertHold bool                // If true, the OCSP revocation reason `CertificateHold` is considered valid.
	DisableRIMCheck   bool                // If true, skip RIM check for driver + vbios for GPU, and bios for switch.
	DisableOCSPCheck  bool                // If true, skip OCSP check for certificate chain.
	rimSchemaPath     string              // rimSchemaPath is the path to the RIM schema file that is used to validate the RIM XML file.
	RimClient         rim.Client          // RIM client to fetch RIM data, including driver+vbios for GPU, and bios for switch.
	OcspClient        nvattestocsp.Client // OCSP client to fetch OCSP responses for RIM and device certificate chains.
	GpuOpts           GPUOpts             // GPU-specific configs for verifying GPU attestation.
	SwitchOpts        SwitchOpts          // Switch-specific configs for verifying switch attestation.
	// Now is a time set at which to verify the validity of certificate chains. If unset, uses defaultTimeset().
	Now *TimeSet

	newRimClient                     func(httpClient *http.Client, serviceKey string) rim.Client
	newOcspClient                    func(httpClient *http.Client, serviceKey string) nvattestocsp.Client
	verifyGPUCertificateChain        func([]*x509.Certificate, *x509.CertPool, Options, string) error
	verifySwitchCertificateChain     func([]*x509.Certificate, *x509.CertPool, Options, string) error
	verifyCertificateChain           func(trustedRoots *x509.CertPool, certChain []*x509.Certificate, expectedCertChainLength int, now time.Time, keyUsages ...x509.ExtKeyUsage) error
	verifyAttestationReportSignature func([]byte, *x509.Certificate, verificationMode) error
	verifyRIM                        func(ctx context.Context, opts Options, evaluator Evaluator, version string) (*pb.RimState, error)
	verifyCertificateChainWithOCSP   func(context.Context, []*x509.Certificate, *x509.CertPool, Options, verificationMode, time.Time) (*pb.OcspState, error)
	checkOCSPResponseSignature       func(*x509.Certificate, x509.SignatureAlgorithm, []byte, []byte) error
}

// TimeSet holds a set of time instances to ensure accurate timing comparison.
type TimeSet struct {
	GPUCertChain        time.Time // GPUCertChain is the time at which to verify the validity of the GPU certificate chain.
	SwitchCertChain     time.Time // SwitchCertChain is the time at which to verify the validity of the Switch certificate chain.
	RIMCertChain        time.Time // RIMCertChain is the time at which to verify the validity of the RIM certificate chain.
	RIMOCSPCertChain    time.Time // RIMOCSPCertChain is the time at which to verify the validity of the RIM OCSP responder certificate chain.
	DeviceOCSPCertChain time.Time // DeviceOCSPCertChain is the time at which to verify the validity of the device OCSP responder certificate chain.
}

func defaultTimeset() *TimeSet {
	return &TimeSet{
		GPUCertChain:        time.Now(),
		SwitchCertChain:     time.Now(),
		RIMCertChain:        time.Now(),
		RIMOCSPCertChain:    time.Now(),
		DeviceOCSPCertChain: time.Now(),
	}
}

func setupOptions(opts *Options) {
	if opts.newRimClient == nil {
		opts.newRimClient = rim.NewDefaultNvidiaClient
	}
	if opts.newOcspClient == nil {
		opts.newOcspClient = nvattestocsp.NewDefaultNvidiaClient
	}
	if opts.RimClient == nil {
		opts.RimClient = opts.newRimClient(nil, "")
	}
	if opts.OcspClient == nil {
		opts.OcspClient = opts.newOcspClient(nil, "")
	}
	if opts.Now == nil {
		opts.Now = defaultTimeset()
	}
	if opts.verifyGPUCertificateChain == nil {
		opts.verifyGPUCertificateChain = defaultVerifyGPUCertificateChain
	}
	if opts.verifySwitchCertificateChain == nil {
		opts.verifySwitchCertificateChain = defaultVerifySwitchCertificateChain
	}
	if opts.verifyCertificateChain == nil {
		opts.verifyCertificateChain = defaultVerifyCertificateChain
	}
	if opts.verifyAttestationReportSignature == nil {
		opts.verifyAttestationReportSignature = defaultVerifyAttestationReportSignature
	}
	if opts.verifyRIM == nil {
		opts.verifyRIM = defaultVerifyRIM
	}
	if opts.verifyCertificateChainWithOCSP == nil {
		opts.verifyCertificateChainWithOCSP = defaultVerifyCertificateChainWithOCSP
	}
	if opts.checkOCSPResponseSignature == nil {
		opts.checkOCSPResponseSignature = defaultCheckOCSPResponseSignature
	}
}

// GPUOpts holds GPU-specific configuration parameters provided by the user.
type GPUOpts struct {
	GPUArch            pb.GpuArchitectureType // GPUArch is the expected GPU architecture of the GPU device, it helps extract GPU FWID from the L5 certificate.
	MaxCertChainLength int                    // MaxCertChainLength is the maximum number of certificates expected in the GPU attestation report.
}

// SwitchOpts holds Switch-specific configuration parameters provided by the user.
type SwitchOpts struct {
	MaxCertChainLength int // MaxCertChainLength is the maximum number of certificates expected in the NVSwitch attestation report.
}

// Evaluator is an interface for accessing RIM data and evaluating it.
type Evaluator interface {
	ValidateSchema(schemaPath string) error
	VerifyXMLSignature(now time.Time) error
	ColloquialVersion() string
	CertificateChain() []*x509.Certificate
}

// GpuInfo verifies the GPU Info for a single GPU device and returns the verification results.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin.py#L337
func GpuInfo(ctx context.Context, gpuInfo *pb.GpuInfo, opts Options) (*pb.GpuInfoState, error) {
	setupOptions(&opts)
	gpuInfoState := &pb.GpuInfoState{}
	gpuInfoState.GpuUuid = gpuInfo.GetUuid()
	gpuInfoState.DriverVersion = gpuInfo.GetDriverVersion()
	gpuInfoState.VbiosVersion = gpuInfo.GetVbiosVersion()

	// 1. verify the GPU architecture.
	if gpuInfo.GetGpuArchitecture() != opts.GpuOpts.GPUArch {
		return nil, ErrGPUArchitectureMismatch
	}

	// 2. verify the certificate chain for GPU device.
	certificateChain, err := ParsePEMCertificateChain(gpuInfo.GetAttestationCertificateChain())
	if err != nil {
		return nil, err
	}

	// 1. parse the attestation report.
	reportProto, err := abi.RawAttestationReportToProto(gpuInfo.GetAttestationReport(), abi.AttestationType(verificationModeGPU))
	if err != nil {
		return nil, err
	}

	opaqueFieldDataList := reportProto.SpdmMeasurementResponse.GetOpaqueData().GetOpaqueFieldData()
	attestationReportFWID := hex.EncodeToString(abi.ExtractOpaqueValue(opaqueFieldDataList, pb.OpaqueDataType_OPAQUE_FIELD_ID_FWID))
	if err := opts.verifyGPUCertificateChain(certificateChain, cert.DeviceRootCertPool, opts, attestationReportFWID); err != nil {
		return nil, err
	}
	gpuInfoState.AttestationCertificateChain = gpuInfo.GetAttestationCertificateChain()

	// 3. verify OCSP status for the certificate chain.
	ocspState, err := opts.verifyCertificateChainWithOCSP(ctx, certificateChain, cert.DeviceRootCertPool, opts, verificationModeGPU, opts.Now.DeviceOCSPCertChain)
	if ocspState != nil {
		gpuInfoState.CertChainOcsp = ocspState
	}
	if err != nil {
		return nil, err
	}

	// 4. verify the signature of the attestation report.
	if err := opts.verifyAttestationReportSignature(gpuInfo.GetAttestationReport(), certificateChain[0], verificationModeGPU); err != nil {
		return nil, err
	}
	gpuInfoState.SignatureVerified = true

	// 5. Fetch and verify RIMs.
	if opts.DisableRIMCheck {
		return gpuInfoState, nil
	}

	// Fetch and verify driver RIM.
	driverRimData, err := utility.DriverRIMData(ctx, gpuInfo.GetDriverVersion(), reportProto, opts.RimClient, opts.GpuOpts.GPUArch)
	if err != nil {
		return nil, err
	}
	driverRimState, err := opts.verifyRIM(ctx, opts, driverRimData, gpuInfo.GetDriverVersion())
	gpuInfoState.DriverRim = driverRimState
	if err != nil {
		return nil, err
	}

	// Fetch and verify VBIOS RIM.
	vbiosRimData, err := utility.GpuVbiosRIMData(ctx, reportProto, opts.RimClient)
	if err != nil {
		return nil, err
	}
	vbiosRimState, err := opts.verifyRIM(ctx, opts, vbiosRimData, gpuInfo.GetVbiosVersion())
	gpuInfoState.VbiosRim = vbiosRimState
	if err != nil {
		return nil, err
	}

	return gpuInfoState, nil
}

// SwitchInfo verifies the Switch Info for a single Switch device and returns the verification results.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/nvswitch_admin.py#L122
func SwitchInfo(ctx context.Context, switchInfo *pb.SwitchInfo, opts Options) (*pb.SwitchInfoState, error) {
	setupOptions(&opts)

	switchInfoState := &pb.SwitchInfoState{}
	switchInfoState.SwitchUuid = switchInfo.GetUuid()

	// 1. parse the attestation report.
	reportProto, err := abi.RawAttestationReportToProto(switchInfo.GetAttestationReport(), abi.AttestationType(verificationModeSwitch))
	if err != nil {
		return nil, err
	}

	// 2. verify the certificate chain for switch device.
	certificateChain, err := ParsePEMCertificateChain(switchInfo.GetAttestationCertificateChain())
	if err != nil {
		return nil, err
	}

	opaqueFieldDataList := reportProto.SpdmMeasurementResponse.GetOpaqueData().GetOpaqueFieldData()
	attestationReportFWID := hex.EncodeToString(abi.ExtractOpaqueValue(opaqueFieldDataList, pb.OpaqueDataType_OPAQUE_FIELD_ID_FWID))
	if err := opts.verifySwitchCertificateChain(certificateChain, cert.DeviceRootCertPool, opts, attestationReportFWID); err != nil {
		return nil, err
	}
	switchInfoState.AttestationCertificateChain = switchInfo.GetAttestationCertificateChain()

	// 3. verify OCSP status for the certificate chain.
	ocspState, err := opts.verifyCertificateChainWithOCSP(ctx, certificateChain, cert.DeviceRootCertPool, opts, verificationModeSwitch, opts.Now.DeviceOCSPCertChain)
	if ocspState != nil {
		switchInfoState.CertChainOcsp = ocspState
	}
	if err != nil {
		return nil, err
	}

	// 4. verify the signature of the attestation report.
	if err := opts.verifyAttestationReportSignature(switchInfo.GetAttestationReport(), certificateChain[0], verificationModeSwitch); err != nil {
		return nil, err
	}
	switchInfoState.SignatureVerified = true

	version := utility.FormatVbiosVersion(abi.ExtractOpaqueValue(opaqueFieldDataList, pb.OpaqueDataType_OPAQUE_FIELD_ID_VBIOS_VERSION), abi.SWITCH)
	switchInfoState.BiosVersion = version

	// 5. Fetch and Verify RIM.
	if opts.DisableRIMCheck {
		return switchInfoState, nil
	}

	biosRimData, err := utility.SwitchBiosRIMData(ctx, reportProto, opts.RimClient)
	if err != nil {
		return nil, err
	}
	biosRimState, err := opts.verifyRIM(ctx, opts, biosRimData, version)
	if err != nil {
		return nil, err
	}
	switchInfoState.BiosRim = biosRimState

	return switchInfoState, nil
}

// verifyGPUCertificateChain verifies the certificate chain for a GPU device.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin.py#L395
var defaultVerifyGPUCertificateChain = func(certChain []*x509.Certificate, trustedRoots *x509.CertPool, opts Options, attestationReportFWID string) error {
	if attestationReportFWID != "" && len(certChain) > 0 {
		certFWID, err := extractGPUFWID(certChain[0], opts.GpuOpts.GPUArch)
		if err != nil {
			return err
		}
		if certFWID != attestationReportFWID {
			return fmt.Errorf("FWID mismatch: %s != %s", certFWID, attestationReportFWID)
		}
	}
	return opts.verifyCertificateChain(trustedRoots, certChain, opts.GpuOpts.MaxCertChainLength, opts.Now.GPUCertChain)
}

// defaultVerifySwitchCertificateChain verifies the certificate chain for a Switch device.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/nvswitch_admin.py#L213
var defaultVerifySwitchCertificateChain = func(certChain []*x509.Certificate, trustedRoots *x509.CertPool, opts Options, attestationReportFWID string) error {
	if attestationReportFWID != "" && len(certChain) > 0 {
		certFWID, err := extractSwitchFWID(certChain[0])
		if err != nil {
			return err
		}
		if certFWID != attestationReportFWID {
			return fmt.Errorf("FWID mismatch: %s != %s", certFWID, attestationReportFWID)
		}
	}
	return opts.verifyCertificateChain(trustedRoots, certChain, opts.SwitchOpts.MaxCertChainLength, opts.Now.SwitchCertChain)
}

// Common function to verify the certificate chain for both GPU and Switch devices.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L143
var defaultVerifyCertificateChain = func(trustedRoots *x509.CertPool, certChain []*x509.Certificate, expectedCertChainLength int, now time.Time, keyUsages ...x509.ExtKeyUsage) error {
	if len(certChain) == 0 {
		return ErrNoCertificateChain
	}

	if len(certChain) != expectedCertChainLength {
		return ErrIncorrectNumberOfCertificates
	}
	leafCert := certChain[0]
	intermediatePool := x509.NewCertPool()

	if len(certChain) >= minCertChainLengthForIntermediate {
		for _, cert := range certChain[1 : len(certChain)-1] {
			intermediatePool.AddCert(cert)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         trustedRoots,
		Intermediates: intermediatePool,
		CurrentTime:   now,
	}
	if len(keyUsages) > 0 {
		opts.KeyUsages = keyUsages
	}
	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("verifying certificate chain: %w", err)
	}
	return nil
}

// defaultVerifyAttestationReportSignature verifies the signature of the attestation report.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L493
var defaultVerifyAttestationReportSignature = func(attestationReport []byte, leafCertificate *x509.Certificate, mode verificationMode) error {
	dataToVerify := attestationReport[:len(attestationReport)-signatureLength]

	reportProto, err := abi.RawAttestationReportToProto(attestationReport, abi.AttestationType(mode))
	if err != nil {
		return err
	}

	signature := reportProto.GetSpdmMeasurementResponse().GetSignature()

	if err := verifySignature(leafCertificate, dataToVerify, signature); err != nil {
		return fmt.Errorf("verifying attestation report signature: %w", err)
	}
	return nil
}

// verifySignature verifies the signature of the data using the ECDSA algorithm.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/attestation/__init__.py#L111
func verifySignature(cert *x509.Certificate, dataToVerify, signature []byte) error {
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrInvalidPublicKey
	}

	if len(signature) != signatureLength {
		return fmt.Errorf("invalid signature length: %d, expected %d", len(signature), signatureLength)
	}

	digest := sha512.Sum384(dataToVerify)
	r := new(big.Int).SetBytes(signature[:signatureLength/2])
	s := new(big.Int).SetBytes(signature[signatureLength/2:])

	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return ErrSignatureVerificationFailed
	}
	return nil
}

// defaultVerifyCertificateChainWithOCSP verifies OCSP Status of the certificate chain
// It fetches OCSP responses for each certificate in the chain (except the root)
// and checks their status. It returns the final OcspState and an error if any.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L223
var defaultVerifyCertificateChainWithOCSP = func(ctx context.Context, certChain []*x509.Certificate, trustedRoots *x509.CertPool, opts Options, mode verificationMode, now time.Time) (*pb.OcspState, error) {
	if opts.DisableOCSPCheck {
		return nil, nil
	}
	startIndex := 0

	if mode == verificationModeGPU || mode == verificationModeSwitch {
		startIndex = 1
	}

	finalOcspState := &pb.OcspState{
		OcspStatus: pb.OcspStatus_OCSP_STATUS_GOOD,
	}

	// We iterate until len(certChain) - 1 because the last certificate is the root and we don't need to check it.
	for i := startIndex; i < len(certChain)-1; i++ {
		targetCert := certChain[i]
		issuerCert := certChain[i+1]

		ocspResponse, err := opts.OcspClient.FetchOCSPResponse(ctx, targetCert, issuerCert)
		if err != nil {
			return nil, fmt.Errorf("fetching OCSP response: %w", err)
		}

		if ocspResponse.Certificate == nil {
			return nil, fmt.Errorf("for cert (SN: %s): %w", targetCert.SerialNumber, ErrOCSPMissingResponderCert)
		}

		ocspResponderChain := append([]*x509.Certificate{ocspResponse.Certificate}, certChain[i:]...)
		if err := opts.verifyCertificateChain(trustedRoots, ocspResponderChain, len(ocspResponderChain), now, x509.ExtKeyUsageOCSPSigning); err != nil {
			return nil, fmt.Errorf("verifying OCSP responder's certificate chain: %w", err)
		}

		if err := opts.checkOCSPResponseSignature(ocspResponse.Certificate, ocspResponse.SignatureAlgorithm, ocspResponse.TBSResponseData, ocspResponse.Signature); err != nil {
			return nil, fmt.Errorf("verifying OCSP signature: %w", err)
		}

		switch ocspResponse.Status {
		case ocsp.Good:
			continue
		case ocsp.Unknown:
			finalOcspState.OcspStatus = pb.OcspStatus_OCSP_STATUS_UNKNOWN
			return finalOcspState, fmt.Errorf("for cert (SN: %s): %w", targetCert.SerialNumber, ErrOCSPUnknownStatus)
		case ocsp.Revoked:
			finalOcspState.OcspStatus = pb.OcspStatus_OCSP_STATUS_REVOKED
			finalOcspState.OcspRevocationReason = ocspRevocationReasonToString(ocspResponse.RevocationReason)
			if ocspResponse.RevocationReason == ocsp.CertificateHold && opts.AllowOCSPCertHold && mode == verificationModeRIM {
				continue
			}
			return finalOcspState, fmt.Errorf("%w: for cert (SN: %s), reason: %s", ErrOCSPRevoked, targetCert.SerialNumber, finalOcspState.OcspRevocationReason)
		default:
			return nil, fmt.Errorf("%w (%d) for cert (SN: %s)", ErrInvalidOCSPStatus, ocspResponse.Status, targetCert.SerialNumber)
		}
	}
	return finalOcspState, nil
}

// defaultVerifyRIM supports RIM verification for the GPU driver, GPU VBIOS, and Switch VBIOS.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/rim/__init__.py#L291
var defaultVerifyRIM = func(ctx context.Context, opts Options, rimData Evaluator, version string) (*pb.RimState, error) {
	finalRimState := &pb.RimState{}
	// 1. Validate the RIM Schema.
	if err := rimData.ValidateSchema(opts.rimSchemaPath); err != nil {
		return finalRimState, fmt.Errorf("%w: %v", ErrRimVerificationFailed, err)
	}
	finalRimState.SchemaValidated = true

	// 2. Validate the RIM Version.
	finalRimState.VersionMatched = (strings.EqualFold(version, rimData.ColloquialVersion()))

	// 3. Validate the RIM Certificate Chain.
	rimCertChain := rimData.CertificateChain()
	if err := opts.verifyCertificateChain(cert.RimRootCertPool, rimCertChain, len(rimCertChain), opts.Now.RIMCertChain); err != nil {
		return finalRimState, fmt.Errorf("%w: could not verify certificate chain: %v", ErrRimVerificationFailed, err)
	}

	// 4. Verify OCSP Status of the RIM Certificate Chain.
	rimOcspState, err := opts.verifyCertificateChainWithOCSP(ctx, rimCertChain, cert.RimRootCertPool, opts, verificationModeRIM, opts.Now.RIMOCSPCertChain)
	if err != nil {
		if rimOcspState != nil {
			finalRimState.CertChainOcsp = rimOcspState
		}
		return finalRimState, fmt.Errorf("%w: could not verify OCSP status: %v", ErrRimVerificationFailed, err)
	}
	finalRimState.CertChainOcsp = rimOcspState

	// 5. Verify the RIM Signature.
	err = rimData.VerifyXMLSignature(opts.Now.RIMCertChain)
	if err != nil {
		return finalRimState, fmt.Errorf("%w: %v", ErrRimVerificationFailed, err)
	}

	finalRimState.SignatureVerified = true
	return finalRimState, nil
}

// revocationReasonMap maps OCSP revocation reason codes to human-readable strings.
var revocationReasonMap = map[int]string{
	ocsp.Unspecified:          "Unspecified",
	ocsp.KeyCompromise:        "KeyCompromise",
	ocsp.CACompromise:         "CACompromise",
	ocsp.AffiliationChanged:   "AffiliationChanged",
	ocsp.Superseded:           "Superseded",
	ocsp.CessationOfOperation: "CessationOfOperation",
	ocsp.CertificateHold:      "CertificateHold",
}

// Helper function to convert OCSP revocation reason to string.
func ocspRevocationReasonToString(reason int) string {
	if reasonStr, ok := revocationReasonMap[reason]; ok {
		return reasonStr
	}
	return fmt.Sprintf("Unknown (%d)", reason)
}

var defaultCheckOCSPResponseSignature = func(cert *x509.Certificate, sigAlgo x509.SignatureAlgorithm, tbsData, sig []byte) error {
	return cert.CheckSignature(sigAlgo, tbsData, sig)
}

// ParsePEMCertificateChain parses a PEM encoded byte slice into a chain of X.509 certificates.
func ParsePEMCertificateChain(data []byte) ([]*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, ErrNoCertificateChain
	}

	var certs []*x509.Certificate

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)

		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing X509Certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, ErrNoCertificateChain
	}
	return certs, nil

}

// FWID is the Go representation of a single FWID structure.
type FWID struct {
	HashAlg asn1.ObjectIdentifier
	Digest  []byte
}

// OperationalFlags is the Go representation of the OperationalFlags structure.
type OperationalFlags struct {
	BitString asn1.BitString
}

// DiceTCBInfo is the Go representation of the entire TcbInfo ASN.1 SEQUENCE.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/__init__.py#L224
type DiceTCBInfo struct {
	Vendor     string           `asn1:"optional,implicit,tag:0,utf8"`
	Model      string           `asn1:"optional,implicit,tag:1,utf8"`
	Version    string           `asn1:"optional,implicit,tag:2,utf8"`
	SVN        int              `asn1:"optional,implicit,tag:3"`
	Layer      int              `asn1:"optional,implicit,tag:4"`
	Index      int              `asn1:"optional,implicit,tag:5"`
	FWIDs      []FWID           `asn1:"optional,implicit,tag:6"`
	Flags      OperationalFlags `asn1:"optional,implicit,tag:7"`
	VendorInfo []byte           `asn1:"optional,implicit,tag:8"`
	Type       []byte           `asn1:"optional,implicit,tag:9"`
}

// extractGPUFWID extracts the GPU FWID from the certificate.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L81
// extractGPUFWID finds the right extension and delegates to the correct parser.
// This version has a cleaner control flow by processing the FWID as soon as it's found.
func extractGPUFWID(cert *x509.Certificate, arch pb.GpuArchitectureType) (string, error) {
	tcgDiceFWIDOIDs := []string{"2.23.133.5.4.1", "2.23.133.5.4.1.1"}

	for _, ext := range cert.Extensions {
		for _, oid := range tcgDiceFWIDOIDs {
			if ext.Id.String() == oid {
				switch arch {
				case pb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER:
					return extractHopperFWID(ext.Value)
				case pb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL:
					return extractBlackwellFWID(ext.Value)
				default:
					return "", fmt.Errorf("unsupported GPU architecture: %s", arch)
				}
			}
		}
	}
	return "", ErrNoFwidFound
}

// extractHopperFWID extracts the FWID for Hopper architecture.
func extractHopperFWID(rawExtensionValue []byte) (string, error) {
	return extractTrailingFWID(rawExtensionValue)
}

// extractBlackwellFWID extracts the FWID for Blackwell architecture.
func extractBlackwellFWID(rawExtensionValue []byte) (string, error) {
	var tcbInfo DiceTCBInfo
	rest, err := asn1.Unmarshal(rawExtensionValue, &tcbInfo)
	if err != nil {
		return "", fmt.Errorf("failed to parse DiceTCBInfo ASN.1 structure: %w", err)
	}
	if len(rest) > 0 {
		return "", ErrTrailingData
	}

	if len(tcbInfo.FWIDs) == 0 {
		return "", ErrNoFwidFound
	}
	return hex.EncodeToString(tcbInfo.FWIDs[0].Digest), nil
}

// extractSwitchFWID extracts the Switch FWID from the certificate.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/nvswitch_admin_utils.py#L79
func extractSwitchFWID(cert *x509.Certificate) (string, error) {
	tcgDiceFwidOid := "2.23.133.5.4.1"

	for _, ext := range cert.Extensions {
		if ext.Id.String() == tcgDiceFwidOid {
			return extractTrailingFWID(ext.Value)
		}
	}
	return "", ErrNoFwidFound
}

func extractTrailingFWID(extensionValue []byte) (string, error) {
	const expectedLength = 48
	if len(extensionValue) < expectedLength {
		return "", fmt.Errorf("extension value is too short: expected at least %d bytes, got %d", expectedLength, len(extensionValue))
	}

	// Slice the last 48 bytes from the raw extension data.
	fwidBytes := extensionValue[len(extensionValue)-expectedLength:]
	return hex.EncodeToString(fwidBytes), nil
}
