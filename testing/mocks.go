/*
Package testing provides mock implementations for testing.
*/
package testing

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"
	"unsafe"

	nvmlmock "github.com/NVIDIA/go-nvml/pkg/nvml/mock"
	"github.com/NVIDIA/go-nvml/pkg/nvml"
	nscqmock "github.com/google/go-nvattest-tools/internal/nvnscq/pkg/nscq/mock"
	"github.com/google/go-nvattest-tools/internal/nvnscq/pkg/nscq"
	"github.com/google/go-nvattest-tools/testing/testdata"
	"golang.org/x/crypto/ocsp"
)

const (
	// TestDriverVersion is a test driver version.
	TestDriverVersion = "test_driver_version"
	// TestUUID is a test UUID.
	TestUUID = "test_uuid"
	// TestVBIOSVersion is a test VBIOS version.
	TestVBIOSVersion = "test_vbios_version"
	// TestArchitecture is a test DeviceArchitecture.
	TestArchitecture = nvml.DeviceArchitecture(123)
	// TestGpuAttestationReportSize is a test GPU attestation report size.
	TestGpuAttestationReportSize = 4117
	// TestSwitchAttestationReportSize is a test NVSwitch attestation report size.
	TestSwitchAttestationReportSize = 2172
	// TestAttestationCertChainSize is a test attestation certificate chain size.
	TestAttestationCertChainSize = 4825
	// TestDeviceCount is a test device count.
	TestDeviceCount = 2
)

// NvmlSuccessInitFunc returns nvml.SUCCESS.
func NvmlSuccessInitFunc() nvml.Return {
	return nvml.SUCCESS
}

// NvmlSuccessShutdownFunc returns nvml.SUCCESS.
func NvmlSuccessShutdownFunc() nvml.Return {
	return nvml.SUCCESS
}

// NvmlSuccessSystemGetDriverVersionFunc returns a test driver version and nvml.SUCCESS.
func NvmlSuccessSystemGetDriverVersionFunc() (string, nvml.Return) {
	return TestDriverVersion, nvml.SUCCESS
}

// NvmlSuccessDeviceGetCountFunc returns a device count of 2 and nvml.SUCCESS.
func NvmlSuccessDeviceGetCountFunc() (int, nvml.Return) {
	return TestDeviceCount, nvml.SUCCESS
}

// NvmlSuccessDeviceGetCountNoGpusFunc returns a device count of 0 and nvml.SUCCESS.
func NvmlSuccessDeviceGetCountNoGpusFunc() (int, nvml.Return) {
	return 0, nvml.SUCCESS
}

// NvmlSuccessDeviceGetHandleByIndexFunc returns a default mock GPU device and nvml.SUCCESS.
func NvmlSuccessDeviceGetHandleByIndexFunc(index int) (nvml.Device, nvml.Return) {
	return DefaultMockGpuDevice(), nvml.SUCCESS
}

// NvmlSuccessGetUUIDFunc returns a test UUID and nvml.SUCCESS.
func NvmlSuccessGetUUIDFunc() (string, nvml.Return) {
	return TestUUID, nvml.SUCCESS
}

// NvmlSuccessGetVbiosVersionFunc returns a test VBIOS version and nvml.SUCCESS.
func NvmlSuccessGetVbiosVersionFunc() (string, nvml.Return) {
	return TestVBIOSVersion, nvml.SUCCESS
}

// NvmlSuccessGetArchitectureFunc returns a test DeviceArchitecture and nvml.SUCCESS.
func NvmlSuccessGetArchitectureFunc() (nvml.DeviceArchitecture, nvml.Return) {
	return TestArchitecture, nvml.SUCCESS
}

// NvmlSuccessGetConfComputeGpuAttestationReportFunc returns a test ConfComputeGpuAttestationReport with the test nonce and nvml.SUCCESS.
func NvmlSuccessGetConfComputeGpuAttestationReportFunc(report *nvml.ConfComputeGpuAttestationReport) nvml.Return {
	report.Nonce = testdata.Nonce
	report.AttestationReportSize = TestGpuAttestationReportSize
	report.AttestationReport = *(*[8192]uint8)(unsafe.Pointer(&testdata.RawGpuAttestationReportTestData.RawAttestationReport[0]))
	return nvml.SUCCESS
}

// NvmlSuccessGetConfComputeGpuCertificateFunc returns a test ConfComputeGpuCertificate and nvml.SUCCESS.
func NvmlSuccessGetConfComputeGpuCertificateFunc() (nvml.ConfComputeGpuCertificate, nvml.Return) {
	return nvml.ConfComputeGpuCertificate{
		AttestationCertChainSize: TestAttestationCertChainSize,
		AttestationCertChain:     *(*[5120]uint8)(unsafe.Pointer(&testdata.GpuAttestationCertificateChain[0])),
	}, nvml.SUCCESS
}

// NvmlErrorInitFunc returns nvml.ERROR_LIBRARY_NOT_FOUND.
func NvmlErrorInitFunc() nvml.Return {
	return nvml.ERROR_LIBRARY_NOT_FOUND
}

// NvmlErrorShutdownFunc returns nvml.ERROR_UNKNOWN.
func NvmlErrorShutdownFunc() nvml.Return {
	return nvml.ERROR_UNKNOWN
}

// NvmlErrorSystemGetDriverVersionFunc returns an empty string and nvml.ERROR_UNKNOWN.
func NvmlErrorSystemGetDriverVersionFunc() (string, nvml.Return) {
	return "", nvml.ERROR_UNKNOWN
}

// NvmlErrorDeviceGetCountFunc returns a device count of 0 and nvml.ERROR_UNKNOWN.
func NvmlErrorDeviceGetCountFunc() (int, nvml.Return) {
	return 0, nvml.ERROR_UNKNOWN
}

// NvmlErrorDeviceGetHandleByIndexFunc returns nil and nvml.ERROR_UNKNOWN.
func NvmlErrorDeviceGetHandleByIndexFunc(index int) (nvml.Device, nvml.Return) {
	return nil, nvml.ERROR_UNKNOWN
}

// NvmlErrorGetUUIDFunc returns an empty string and nvml.ERROR_UNKNOWN.
func NvmlErrorGetUUIDFunc() (string, nvml.Return) {
	return "", nvml.ERROR_UNKNOWN
}

// NvmlErrorGetVbiosVersionFunc returns an empty string and nvml.ERROR_UNKNOWN.
func NvmlErrorGetVbiosVersionFunc() (string, nvml.Return) {
	return "", nvml.ERROR_UNKNOWN
}

// NvmlErrorGetArchitectureFunc returns a zero DeviceArchitecture and nvml.ERROR_UNKNOWN.
func NvmlErrorGetArchitectureFunc() (nvml.DeviceArchitecture, nvml.Return) {
	return nvml.DeviceArchitecture(0), nvml.ERROR_UNKNOWN
}

// NvmlErrorGetConfComputeGpuAttestationReportFunc returns nvml.ERROR_UNKNOWN.
func NvmlErrorGetConfComputeGpuAttestationReportFunc(*nvml.ConfComputeGpuAttestationReport) nvml.Return {
	return nvml.ERROR_UNKNOWN
}

// NvmlErrorGetConfComputeGpuCertificateFunc returns an empty ConfComputeGpuCertificate and nvml.ERROR_UNKNOWN.
func NvmlErrorGetConfComputeGpuCertificateFunc() (nvml.ConfComputeGpuCertificate, nvml.Return) {
	return nvml.ConfComputeGpuCertificate{}, nvml.ERROR_UNKNOWN
}

// DefaultMockGpuDevice returns a default mock GPU device for testing.
func DefaultMockGpuDevice() *nvmlmock.Device {
	return &nvmlmock.Device{
		GetUUIDFunc:                            NvmlSuccessGetUUIDFunc,
		GetVbiosVersionFunc:                    NvmlSuccessGetVbiosVersionFunc,
		GetArchitectureFunc:                    NvmlSuccessGetArchitectureFunc,
		GetConfComputeGpuAttestationReportFunc: NvmlSuccessGetConfComputeGpuAttestationReportFunc,
		GetConfComputeGpuCertificateFunc:       NvmlSuccessGetConfComputeGpuCertificateFunc,
	}
}

// DefaultMockGpuInterface returns a default mock GPU interface for testing.
func DefaultMockGpuInterface() *nvmlmock.Interface {
	return &nvmlmock.Interface{
		InitFunc:                   NvmlSuccessInitFunc,
		ShutdownFunc:               NvmlSuccessShutdownFunc,
		SystemGetDriverVersionFunc: NvmlSuccessSystemGetDriverVersionFunc,
		DeviceGetCountFunc:         NvmlSuccessDeviceGetCountFunc,
		DeviceGetHandleByIndexFunc: NvmlSuccessDeviceGetHandleByIndexFunc,
	}
}

// NscqSuccessInitFunc returns nscq.Success.
func NscqSuccessInitFunc() nscq.Return {
	return nscq.Success
}

// NscqSuccessShutdownFunc returns nscq.Success.
func NscqSuccessShutdownFunc() nscq.Return {
	return nscq.Success
}

// NscqSuccessSessionCreateFunc returns a default mock NSCQ session and nscq.Success.
func NscqSuccessSessionCreateFunc(flags uint32) (*nscq.Session, nscq.Return) {
	return &nscq.Session{}, nscq.Success
}

// NscqSuccessSessionDestroyFunc returns nscq.Success.
func NscqSuccessSessionDestroyFunc(session *nscq.Session) nscq.Return {
	return nscq.Success
}

// NscqSuccessSwitchPCIEModeFunc returns 0 and nscq.Success.
func NscqSuccessSwitchPCIEModeFunc(session *nscq.Session, uuid string) (int8, nscq.Return) {
	return 0, nscq.Success
}

// NscqSuccessSwitchDeviceUUIDsFunc returns a slice containing the test UUID and nscq.Success.
func NscqSuccessSwitchDeviceUUIDsFunc(session *nscq.Session) ([]string, nscq.Return) {
	return []string{TestUUID}, nscq.Success
}

// NscqSuccessSwitchArchitectureFunc returns 2 and nscq.Success.
func NscqSuccessSwitchArchitectureFunc(session *nscq.Session) (int8, nscq.Return) {
	return 2, nscq.Success
}

// NscqSuccessSwitchAttestationReportFunc returns a slice containing the test attestation report and nscq.Success.
func NscqSuccessSwitchAttestationReportFunc(session *nscq.Session, nonce [32]uint8, uuid string) ([]uint8, nscq.Return) {
	return testdata.RawSwitchAttestationReportTestData.RawAttestationReport[:TestSwitchAttestationReportSize], nscq.Success
}

// NscqSuccessSwitchAttestationCertificateChainFunc returns a slice containing the test attestation certificate chain and nscq.Success.
func NscqSuccessSwitchAttestationCertificateChainFunc(session *nscq.Session, uuid string) ([]uint8, nscq.Return) {
	return testdata.SwitchAttestationCertificateChain[:TestAttestationCertChainSize], nscq.Success
}

// DefaultMockSwitchInterface returns a default mock Switch interface for testing.
func DefaultMockSwitchInterface() *nscqmock.Interface {
	return &nscqmock.Interface{
		InitFunc:                              NscqSuccessInitFunc,
		ShutdownFunc:                          NscqSuccessShutdownFunc,
		SessionCreateFunc:                     NscqSuccessSessionCreateFunc,
		SessionDestroyFunc:                    NscqSuccessSessionDestroyFunc,
		SwitchPCIEModeFunc:                    NscqSuccessSwitchPCIEModeFunc,
		SwitchDeviceUUIDsFunc:                 NscqSuccessSwitchDeviceUUIDsFunc,
		SwitchArchitectureFunc:                NscqSuccessSwitchArchitectureFunc,
		SwitchAttestationReportFunc:           NscqSuccessSwitchAttestationReportFunc,
		SwitchAttestationCertificateChainFunc: NscqSuccessSwitchAttestationCertificateChainFunc,
	}
}

// MockOcspClient implements the ocspClient interface to simulate OCSP responses
// without making real network calls.
type MockOcspClient struct {
	// ResponsesBySerial provides specific responses keyed by the target cert's serial number.
	// This is prioritized over ResponsesToReturn.
	ResponsesBySerial map[string]*ocsp.Response
	// A slice of responses to return in order for each call.
	ResponsesToReturn []*ocsp.Response
	// An error to return immediately, used for testing network failures.
	ErrToReturn error
	// callCount tracks the number of times FetchOCSPResponse is called, allowing the
	// mock to return a different response for each certificate in the chain.
	callCount int
}

// FetchOCSPResponse fulfills the ocspClient interface for the mock.
func (m *MockOcspClient) FetchOCSPResponse(ctx context.Context, targetCert, issuerCert *x509.Certificate) (*ocsp.Response, error) {
	if err := targetCert.CheckSignatureFrom(issuerCert); err != nil {
		return nil, fmt.Errorf("mock validation failed: provided issuer (SN: %s) is not the issuer of target (SN: %s): %w", issuerCert.SerialNumber, targetCert.SerialNumber, err)
	}

	if m.ErrToReturn != nil {
		return nil, m.ErrToReturn
	}
	// Prioritize the map-based lookup.
	if m.ResponsesBySerial != nil {
		targetSN := targetCert.SerialNumber.String()
		if resp, ok := m.ResponsesBySerial[targetSN]; ok {
			return resp, nil
		}
		return nil, fmt.Errorf("mock ocsp client: no response found for serial number %s", targetSN)
	}

	if m.callCount >= len(m.ResponsesToReturn) {
		return nil, fmt.Errorf("mock received more calls than expected responses")
	}
	// Return the next response in the configured sequence.
	response := m.ResponsesToReturn[m.callCount]
	m.callCount++
	return response, nil
}

// CreateMockOcspResponse is a test helper to build an OCSP response object.
func CreateMockOcspResponse(status int, reason int, responderCert *x509.Certificate) *ocsp.Response {
	return &ocsp.Response{Status: status, RevocationReason: reason, Certificate: responderCert}
}

// CreateMockOcspResponses is a test helper to build a slice of OCSP response objects.
// It creates a response for each certificate in the chain, except the root.
// The first response is created with the given status and reason, and the rest are 'Good'
// (each signed by their respective issuer).
func CreateMockOcspResponses(testChain []*x509.Certificate, firstStatus int, firstReason int) []*ocsp.Response {
	var responses []*ocsp.Response

	if len(testChain) < 2 {
		return responses
	}

	responses = append(responses, CreateMockOcspResponse(firstStatus, firstReason, testChain[1]))

	for i := 1; i < len(testChain)-1; i++ {
		issuerForThisCert := testChain[i+1]
		responses = append(responses, CreateMockOcspResponse(ocsp.Good, 0, issuerForThisCert))
	}

	return responses
}

// MockRimData is a mock implementation of the Evaluator interface for testing.
type MockRimData struct {
	MockSchemaErr error
	MockSigErr    error
	MockVersion   string
	MockCertChain []*x509.Certificate
}

// ValidateSchema provides a mock implementation of the ValidateSchema function for RIM data.
func (m *MockRimData) ValidateSchema(SchemaPath string) error {
	return m.MockSchemaErr
}

// VerifyXMLSignature provides a mock implementation of the VerifyXMLSignature function for RIM data.
func (m *MockRimData) VerifyXMLSignature(now time.Time) error {
	return m.MockSigErr
}

// ColloquialVersion provides a mock implementation of the GetColloquialVersion function for RIM data.
func (m *MockRimData) ColloquialVersion() string {
	return m.MockVersion
}

// CertificateChain provides a mock implementation of the GetCertificateChain function for RIM data.
func (m *MockRimData) CertificateChain() []*x509.Certificate {
	return m.MockCertChain
}

// MockRimClient implements the rim.Client interface to simulate fetching RIM documents.
type MockRimClient struct {
	// ContentToReturn is the byte slice to return when FetchRIM is called.
	ContentToReturn []byte
	// ErrToReturn is an error to return from FetchRIM.
	ErrToReturn error
	// FetchRIMFunc allows custom logic for FetchRIM, for example, returning different
	// content based on rimID.
	FetchRIMFunc func(ctx context.Context, rimID string) ([]byte, error)

	// ListToReturn is the string slice to return when ListRIMs is called.
	ListToReturn []string
	// ListErrToReturn is an error to return from ListRIMs.
	ListErrToReturn error
}

// FetchRIM mock.
func (m *MockRimClient) FetchRIM(ctx context.Context, rimID string) ([]byte, error) {
	if m.FetchRIMFunc != nil {
		return m.FetchRIMFunc(ctx, rimID)
	}
	if m.ErrToReturn != nil {
		return nil, m.ErrToReturn
	}
	return m.ContentToReturn, nil
}

// ListRIMs mock.
func (m *MockRimClient) ListRIMs(ctx context.Context) ([]string, error) {
	if m.ListErrToReturn != nil {
		return nil, m.ListErrToReturn
	}
	return m.ListToReturn, nil
}
