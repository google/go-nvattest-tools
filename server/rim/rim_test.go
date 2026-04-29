package rim

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	etree "github.com/beevik/etree"
	testdata "github.com/google/go-nvattest-tools/testing/testdata"
	testHelper "github.com/google/go-nvattest-tools/testing"
)

const hashFunctionNamespaceURI = "http://www.w3.org/2001/04/xmlenc#sha384"

// mockRoundTripper is a helper to mock the RoundTrip method of http.RoundTripper.
type mockRoundTripper struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

// RoundTrip is a mock implementation of the RoundTrip method of http.RoundTripper.
func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.RoundTripFunc == nil {
		return nil, fmt.Errorf("RoundTripFunc is not implemented")
	}
	return m.RoundTripFunc(req)
}

// mockReader is a helper to simulate read errors from io.ReadAll.
type mockReader struct {
	err error
}

// Read is a mock implementation of the Read method of io.Reader.
func (m *mockReader) Read(p []byte) (n int, err error) {
	return 0, m.err
}

// TestNewDefaultNvidiaClient tests the NewDefaultNvClient function responsible for creating a new DefaultNvClient instance.
func TestNewDefaultNvidiaClient(t *testing.T) {
	// Defines a custom client to avoid using the default http client.
	customClient := &http.Client{Transport: &mockRoundTripper{
		// RoundTripFunc: nil is fine here, as we only need the Transport pointer to be unique.
		// cmp.Diff will ignore this field directly.
		RoundTripFunc: nil,
	}}

	tests := []struct {
		name       string
		desc       string
		httpClient *http.Client
		serviceKey string
		wantClient *DefaultNvidiaClient
	}{
		{
			name:       "with_http_client_and_service_key_provided",
			desc:       "Test with both http client and service key provided, should return a client with both values.",
			httpClient: customClient,
			serviceKey: "test-service-key",
			wantClient: &DefaultNvidiaClient{httpClient: customClient, serviceKey: "test-service-key"},
		},
		{
			name:       "with_only_service_key_provided",
			desc:       "Test with only service key provided, should return a client with the service key and default http client.",
			httpClient: nil,
			serviceKey: "test-service-key",
			wantClient: &DefaultNvidiaClient{httpClient: http.DefaultClient, serviceKey: "test-service-key"},
		},
		{
			name:       "with_only_http_client_provided",
			desc:       "Test with only http client provided, should return a client with the http client and empty service key.",
			httpClient: customClient,
			wantClient: &DefaultNvidiaClient{httpClient: customClient, serviceKey: ""},
		},
		{
			name:       "with_no_http_client_or_service_key_provided",
			desc:       "Test with no http client or service key provided, should return a client with default http client and empty service key.",
			httpClient: nil,
			wantClient: &DefaultNvidiaClient{httpClient: http.DefaultClient, serviceKey: ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := NewDefaultNvidiaClient(tc.httpClient, tc.serviceKey)
			if diff := cmp.Diff(tc.wantClient, client, cmp.AllowUnexported(DefaultNvidiaClient{}, mockRoundTripper{})); diff != "" {
				t.Errorf("NewDefaultNvClient() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestFetchRIMSuccess tests the FetchRIM function when the request is successful.
func TestFetchRIMSuccess(t *testing.T) {
	ctx := t.Context()
	rimContent := []byte("This is a test RIM content.")
	encodedRIMContent := base64.StdEncoding.EncodeToString(rimContent)
	validRespBody, err := json.Marshal(rimResponse{RIM: encodedRIMContent})
	if err != nil {
		t.Fatalf("Failed to marshal RIM API response: %v", err)
	}

	tests := []struct {
		desc           string
		name           string
		fileID         string
		serviceKey     string
		roundTripFn    func(req *http.Request) (*http.Response, error)
		wantRIMContent []byte
	}{
		{
			desc:           "successful RIM request",
			name:           "valid_request",
			fileID:         "test-rim-file-id",
			roundTripFn:    newSuccessRoundTripper(t, validRespBody, ""),
			wantRIMContent: rimContent,
		},
		{
			desc:           "successful RIM request with service key provided",
			name:           "valid_request_with_service_key",
			fileID:         "test-rim-file-id",
			serviceKey:     "test-service-key",
			roundTripFn:    newSuccessRoundTripper(t, validRespBody, "test-service-key"),
			wantRIMContent: rimContent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Log(tc.desc)
			mockHTTPClient := &http.Client{Transport: &mockRoundTripper{RoundTripFunc: tc.roundTripFn}}
			client := &DefaultNvidiaClient{httpClient: mockHTTPClient, serviceKey: tc.serviceKey}

			rimContent, err := client.FetchRIM(ctx, tc.fileID)
			if err != nil {
				t.Fatalf("FetchRIM returned an unexpected error: %v", err)
			}
			if !bytes.Equal(rimContent, tc.wantRIMContent) {
				t.Errorf("FetchRIM() returned RIM content:\n  got: %s\n want: %s", rimContent, tc.wantRIMContent)
			}
		})
	}
}

// TestFetchRIMFailure tests the FetchRIM function when the request fails.
func TestFetchRIMFailure(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		desc        string
		name        string
		fileID      string
		serviceKey  string
		roundTripFn func(req *http.Request) (*http.Response, error)
		wantErr     string
	}{
		{
			desc:        "http client returns network error",
			name:        "network_error",
			fileID:      "test-rim-file-id",
			roundTripFn: newErrorRoundTripper(errors.New("simulated network error")),
			wantErr:     "simulated network error",
		},
		{
			desc:        "error reading http response body",
			name:        "error_reading_body",
			fileID:      "test-rim-file-id",
			roundTripFn: newResponseRoundTripper(http.StatusOK, &mockReader{err: fmt.Errorf("simulated read error")}),
			wantErr:     "simulated read error",
		},
		{
			desc:        "Invalid JSON response",
			name:        "invalid_json",
			fileID:      "test-rim-file-id",
			roundTripFn: newResponseRoundTripper(http.StatusOK, bytes.NewReader([]byte(`{"rim": 12345}`))),
			wantErr:     "unmarshalling JSON response",
		},
		{
			desc:        "Invalid base64 response",
			name:        "invalid_base64",
			fileID:      "test-rim-file-id",
			roundTripFn: newResponseRoundTripper(http.StatusOK, bytes.NewReader([]byte(`{"rim": "invalid base64 string"}`))),
			wantErr:     "decoding base64 string",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockHTTPClient := &http.Client{Transport: &mockRoundTripper{RoundTripFunc: tc.roundTripFn}}
			client := &DefaultNvidiaClient{httpClient: mockHTTPClient, serviceKey: tc.serviceKey}

			_, err := client.FetchRIM(ctx, tc.fileID)
			t.Logf("FetchRIM returned error: %v", err)
			if err == nil {
				t.Fatalf("FetchRIM expected error, but got nil, want error: %v", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("FetchRIM error: got %v, want error to contain %v", err, tc.wantErr)
			}
		})
	}
}

// --- Mock HTTP RoundTripper Factories ---

// newSuccessRoundTripper creates a roundTripFn for successful API calls.
// It checks the request method, URL, and optionally the service key header.
func newSuccessRoundTripper(t *testing.T, respBody []byte, wantServiceKey string) func(req *http.Request) (*http.Response, error) {
	t.Helper()
	return func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			return nil, fmt.Errorf("unexpected HTTP method: got %s, want %s", req.Method, http.MethodGet)
		}
		if !strings.Contains(req.URL.String(), "test-rim-file-id") {
			return nil, fmt.Errorf("URL does not contain expected fileID 'test-rim-file-id': got %s", req.URL.String())
		}
		if wantServiceKey != "" {
			wantHeader := fmt.Sprintf(serviceKeyValueFormat, wantServiceKey)
			if gotHeader := req.Header.Get(serviceKeyHeader); gotHeader != wantHeader {
				return nil, fmt.Errorf("unexpected Authorization header: got %q, want %q", gotHeader, wantHeader)
			}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(respBody)),
		}, nil
	}
}

// newErrorRoundTripper creates a roundTripFn that simply returns a specified error.
func newErrorRoundTripper(err error) func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		return nil, err
	}
}

// newResponseRoundTripper creates a roundTripFn that returns a response with a given status and body.
func newResponseRoundTripper(statusCode int, body io.Reader) func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(body),
		}, nil
	}
}

func TestParse(t *testing.T) {

	testCases := []struct {
		name       string
		rimBytes   func() ([]byte, error)
		wantPass   bool
		wantRimErr error
	}{
		{
			name: "successfully_parsed_valid_rim",
			rimBytes: func() ([]byte, error) {
				return testdata.ReadXMLFile("rim/success_valid_rim.xml")
			},
			wantPass: true,
		},
		{
			name: "failure_invalid_rim_xml",
			rimBytes: func() ([]byte, error) {
				return []byte("<root><unclosed>"), nil
			},
			wantPass:   false,
			wantRimErr: etree.ErrXML,
		},
		{
			name: "failure_not_xml",
			rimBytes: func() ([]byte, error) {
				return []byte("this is not a valid XML"), nil
			},
			wantPass:   false,
			wantRimErr: ErrRootElementNil,
		},
		{
			name: "failure_from_extract_colloquial_version_helper",
			rimBytes: func() ([]byte, error) {
				return testdata.ReadXMLFile("rim/failure_missing_colloquial_version.xml")
			},
			wantPass:   false,
			wantRimErr: ErrElementNotFound,
		},
		{
			name: "failure_from_extract_certificate_chain_helper",
			rimBytes: func() ([]byte, error) {
				return testdata.ReadXMLFile("rim/failure_missing_x509_data.xml")
			},
			wantPass:   false,
			wantRimErr: ErrElementNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rimBytes, err := tc.rimBytes()
			if err != nil {
				t.Fatalf("Failed to prepare test data: %v", err)
			}

			parsedRIM, err := Parse(rimBytes)

			if tc.wantPass {
				if err != nil {
					t.Fatalf("Parse() returned an unexpected error: %v", err)
				}
				if parsedRIM == nil {
					t.Fatalf("Parse() returned a nil result, want non-nil")
				}
			} else {
				if err == nil {
					t.Fatalf("Parse() was expected to return an error, but got nil")
				}
				if tc.wantRimErr != nil && !errors.Is(err, tc.wantRimErr) {
					t.Errorf("Parse() returned error '%v', want error that is or wraps '%v'", err, tc.wantRimErr)
				}
			}
		})
	}
}

func TestExtractColloquialVersion(t *testing.T) {
	testCases := []struct {
		name                  string
		rimXMLFile            string
		wantColloquialVersion string
		wantErr               error
	}{
		{
			name:                  "success_valid_collaquial_version",
			rimXMLFile:            "rim/success_valid_rim.xml",
			wantColloquialVersion: "96.00.6D.00.29",
			wantErr:               nil,
		},
		{
			name:                  "failure_missing_colloquial_version",
			rimXMLFile:            "rim/failure_missing_colloquial_version.xml",
			wantColloquialVersion: "",
			wantErr:               ErrElementNotFound,
		},
		{
			name:                  "failure_missing_meta",
			rimXMLFile:            "rim/failure_missing_meta.xml",
			wantColloquialVersion: "",
			wantErr:               ErrElementNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			root := testHelper.ParseXML(t, tc.rimXMLFile)
			gotVersion, err := extractColloquialVersion(root)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("extractColloquialVersion() returned error '%v', want error that is or wraps '%v'", err, tc.wantErr)
			}
			if gotVersion != tc.wantColloquialVersion {
				t.Errorf("extractColloquialVersion() returned version '%v', want version '%v'", gotVersion, tc.wantColloquialVersion)
			}

		})
	}

}

func TestExtractCertificateChain(t *testing.T) {
	testCases := []struct {
		name         string
		rimXMLFile   string
		wantChainLen int
		wantPass     bool
		wantErr      error
		wantErrMsg   string
	}{
		{
			name:         "success_valid_certificate_chain",
			rimXMLFile:   "rim/success_valid_rim.xml",
			wantChainLen: 4,
			wantPass:     true,
			wantErr:      nil,
		},
		{
			name:         "failure_missing_x509_data",
			rimXMLFile:   "rim/failure_missing_x509_data.xml",
			wantChainLen: 0,
			wantErr:      ErrElementNotFound,
		},
		{
			name:         "failure_missing_x509_certificate",
			rimXMLFile:   "rim/failure_missing_x509_certificate.xml",
			wantChainLen: 0,
			wantErr:      ErrElementNotFound,
		},
		{
			name:         "failure_invalid_certificate_bytes",
			rimXMLFile:   "rim/failure_invalid_cert_bytes.xml",
			wantChainLen: 0,
			wantErrMsg:   "parsing X509Certificate",
		},
		{
			name:         "failure_invalid_pem_data",
			rimXMLFile:   "rim/failure_invalid_pem_data.xml",
			wantChainLen: 0,
			wantErrMsg:   "Failed to decode PEM data",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			root := testHelper.ParseXML(t, tc.rimXMLFile)
			gotChain, err := extractCertificateChain(root)
			if tc.wantPass {
				if err != nil {
					t.Fatalf("extractCertificateChain() returned an unexpected error: %v", err)
				}
				if gotChain == nil {
					t.Fatalf("extractCertificateChain() returned a nil result, want non-nil")
				}
				if len(gotChain) != tc.wantChainLen {
					t.Errorf("extractCertificateChain() returned chain of length %d, want %d", len(gotChain), tc.wantChainLen)
				}
			} else {
				if err == nil {
					t.Fatalf("extractCertificateChain() was expected to return an error, but got nil")
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("extractCertificateChain() returned error '%v', want error that is or wraps '%v'", err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("extractCertificateChain() returned error '%v', want error to contain '%v'", err, tc.wantErr)
				}
			}
		})
	}
}

func TestMeasurementsSuccess(t *testing.T) {
	const driverRimName = "driver"
	const vbiosRimName = "vbios"

	testCases := []struct {
		name             string
		rimXMLFile       string
		rimNameInput     string
		wantMeasurements []GoldenMeasurement
	}{
		{
			name:         "single_measurement",
			rimXMLFile:   "rim/success_payload_single_measurement.xml",
			rimNameInput: driverRimName,
			wantMeasurements: []GoldenMeasurement{
				{
					Component:    driverRimName,
					Values:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
					Name:         "Measurement_0",
					Index:        0,
					Size:         48,
					Alternatives: 1,
					Active:       true,
				},
			},
		},
		{
			name:         "multiple_measurements",
			rimXMLFile:   "rim/success_payload_multiple_measurements.xml",
			rimNameInput: driverRimName,
			wantMeasurements: []GoldenMeasurement{
				{Component: driverRimName, Values: []string{"hash0"}, Name: "Meas_0", Index: 0, Size: 10, Alternatives: 1, Active: true},
				{Component: driverRimName, Values: []string{"hash1"}, Name: "Meas_1", Index: 1, Size: 20, Alternatives: 1, Active: false},
			},
		},
		{
			name:         "multiple_alternatives",
			rimXMLFile:   "rim/success_payload_multiple_alternatives.xml",
			rimNameInput: vbiosRimName,
			wantMeasurements: []GoldenMeasurement{
				{
					Component:    vbiosRimName,
					Values:       []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
					Name:         "Measurement_0",
					Index:        0,
					Size:         48,
					Alternatives: 1,
					Active:       true,
				},
				{
					Component: vbiosRimName,
					Values: []string{
						"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
						"758af96044c700f98a85347be27124d51c05b8784ba216b629b9aaab6d538c759aed9922a133e4ac473564d359b271d5",
						"7df046f26d0536f3a0b06d288ce6e5c659cad7a9c45cbd3a82c5df248755e4ddeff5871045acc6366ccab178b0d6568e",
						"cb09606fa5c052f0bc4cfa86dbeb4e3e70500bfbeeb7193256ac24ed4464a607366df16a3547b7c17ebd741eb43f1adf",
					},
					Name:         "Measurement_12",
					Index:        12,
					Size:         48,
					Alternatives: 4,
					Active:       true,
				},
			},
		},
	}

	goldentMeasurementSorter := cmpopts.SortSlices(func(a, b GoldenMeasurement) bool { return a.Index < b.Index })

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := &Data{
				root: testHelper.ParseXML(t, tc.rimXMLFile),
			}
			gotMeasurements, err := data.Measurements(tc.rimNameInput, hashFunctionNamespaceURI)
			if err != nil {
				t.Fatalf("Measurements() returned an unexpected error: %v", err)
			}
			if gotMeasurements == nil {
				t.Fatalf("Measurements() returned a nil result, want non-nil")
			}
			if diff := cmp.Diff(tc.wantMeasurements, gotMeasurements, goldentMeasurementSorter); diff != "" {
				t.Errorf("Measurements() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMeasurementsFailure(t *testing.T) {
	const driverRimName = "driver"

	testCases := []struct {
		name         string
		rimXMLFile   string
		rimNameInput string
		wantErr      error
		wantErrMsg   string
	}{
		{
			name:         "no_payload_element",
			rimXMLFile:   "rim/failure_no_payload.xml",
			rimNameInput: driverRimName,
			wantErr:      ErrElementNotFound,
		},
		{
			name:         "empty_payload",
			rimXMLFile:   "rim/failure_empty_payload.xml",
			rimNameInput: driverRimName,
			wantErr:      ErrNoGoldenMeasurements,
		},
		{
			name:         "missing_index_attribute",
			rimXMLFile:   "rim/failure_missing_index.xml",
			rimNameInput: driverRimName,
			wantErr:      ErrElementNotFound,
		},
		{
			name:         "invalid_index_attribute",
			rimXMLFile:   "rim/failure_invalid_index.xml",
			rimNameInput: driverRimName,
			wantErrMsg:   "parsing index attribute in Payload tag",
		},
		{
			name:         "missing_alternatives_attribute",
			rimXMLFile:   "rim/failure_missing_alternatives.xml",
			rimNameInput: driverRimName,
			wantErr:      ErrElementNotFound,
		},
		{
			name:         "invalid_alternatives_attribute",
			rimXMLFile:   "rim/failure_invalid_alternatives.xml",
			rimNameInput: driverRimName,
			wantErrMsg:   "attribute 'alternatives' has invalid integer value",
		},
		{
			name:         "missing_size_attribute",
			rimXMLFile:   "rim/failure_missing_size.xml",
			rimNameInput: driverRimName,
			wantErr:      ErrElementNotFound,
		},
		{
			name:         "invalid_size_attribute",
			rimXMLFile:   "rim/failure_invalid_size.xml",
			rimNameInput: driverRimName,
			wantErrMsg:   "attribute 'size' has invalid integer value",
		},
		{
			name:         "missing_hash_attribute",
			rimXMLFile:   "rim/failure_missing_hash.xml",
			rimNameInput: driverRimName,
			wantErrMsg:   "attribute \"Hash0\" with namespace",
		},
		{
			name:         "duplicate_index",
			rimXMLFile:   "rim/failure_duplicate_index.xml",
			rimNameInput: driverRimName,
			wantErrMsg:   "invalid measurement index: multiple measurements have the same index",
		},
		{
			name:         "hash_attribute_has_empty_namespace",
			rimXMLFile:   "rim/failure_hash_empty_namespace.xml",
			rimNameInput: driverRimName,
			wantErrMsg:   "attribute \"Hash0\" with namespace",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := &Data{
				root: testHelper.ParseXML(t, tc.rimXMLFile),
			}
			_, err := data.Measurements(tc.rimNameInput, hashFunctionNamespaceURI)
			if err == nil {
				t.Fatalf("Measurements() was expected to return an error, but got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("Measurements() returned error '%v', want error that is or wraps '%v'", err, tc.wantErr)
			}
			if tc.wantErrMsg != "" && !strings.Contains(err.Error(), tc.wantErrMsg) {
				t.Errorf("Measurements() returned error '%v', want error to contain '%v'", err, tc.wantErrMsg)
			}
		})
	}
}

func TestValidateSchema(t *testing.T) {
	testCases := []struct {
		name           string
		getRoot        func(t *testing.T) *etree.Element
		schemaContent  []byte
		useDefaultPath bool
		useInvalidPath bool
		wantErr        error
		wantErrMsg     string
	}{
		{
			name: "success_valid_schema",
			getRoot: func(t *testing.T) *etree.Element {
				return testHelper.ParseXML(t, "rim/success_valid_rim.xml")
			},
			schemaContent: DefaultSchema,
			wantErr:       nil,
		},
		{
			name: "failure_schema_cannot_be_parsed",
			getRoot: func(t *testing.T) *etree.Element {
				return testHelper.ParseXML(t, "rim/success_valid_rim.xml")
			},
			schemaContent: []byte("this is not a valid schema"),
			wantErr:       nil,
			wantErrMsg:    "RIM Schema validation failed: could not parse schema file",
		},
		{
			name: "failure_from_libxml2_parseString",
			getRoot: func(t *testing.T) *etree.Element {
				doc := etree.NewDocument()
				invalidElement := etree.NewElement("")
				doc.SetRoot(invalidElement)
				return doc.Root()
			},
			schemaContent: DefaultSchema,
			wantErr:       nil,
			wantErrMsg:    "RIM Schema validation failed: could not parse document",
		},
		{
			name: "Failure_schema_validation",
			getRoot: func(t *testing.T) *etree.Element {
				root := testHelper.ParseXML(t, "rim/success_valid_rim.xml")
				root.RemoveAttr("tagId")
				return root
			},
			schemaContent: DefaultSchema,
			wantErr:       ErrRimSchemaValidationFailed,
		},
		{
			name: "success_with_empty_schema_path_uses_default_schema",
			getRoot: func(t *testing.T) *etree.Element {
				return testHelper.ParseXML(t, "rim/success_valid_rim.xml")
			},
			useDefaultPath: true,
			wantErr:        nil,
		},
		{
			name: "failure_with_invalid_schema_path",
			getRoot: func(t *testing.T) *etree.Element {
				return testHelper.ParseXML(t, "rim/success_valid_rim.xml")
			},
			useInvalidPath: true,
			wantErr:        nil,
			wantErrMsg:     "could not read schema file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var tempSchemaPath string
			tempDir := t.TempDir()
			switch {
			case tc.useDefaultPath:
				tempSchemaPath = ""
			case tc.useInvalidPath:
				tempSchemaPath = filepath.Join(tempDir, "invalid_schema.xsd")
			default:
				tempSchemaPath = filepath.Join(tempDir, "schema.xsd")
				if err := os.WriteFile(tempSchemaPath, tc.schemaContent, 0644); err != nil {
					t.Fatalf("Failed to write schema file: %v", err)
				}
			}
			dataToValidate := &Data{
				root: tc.getRoot(t),
			}
			err := dataToValidate.ValidateSchema(tempSchemaPath)
			if err != nil {
				if tc.wantErr == nil && tc.wantErrMsg == "" {
					t.Fatalf("ValidateSchema() got unexpected error: %v", err)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("ValidateSchema() returned error '%v', want error that is or wraps '%v'", err, tc.wantErr)
				}
				if tc.wantErrMsg != "" && !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("ValidateSchema() returned error '%v', want error to contain '%v'", err, tc.wantErrMsg)
				}
			} else if tc.wantErr != nil || tc.wantErrMsg != "" {
				t.Fatal("ValidateSchema() returned nil, but expected an error")
			}
		})
	}
}

func TestVerifyXMLSignature(t *testing.T) {
	wrongRootCertPEM := []byte(`-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----`)
	badFormatPEM := []byte("this is not a valid pem block")
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not a valid DER-encoded certificate"),
	}
	validXMLTime, err := time.Parse(time.RFC3339, "2025-09-21T00:00:00Z")
	if err != nil {
		t.Fatalf("Failed to parse validXMLTime: %v", err)
	}
	badCertDataPEM := pem.EncodeToMemory(block)
	testCases := []struct {
		name       string
		rootCert   []byte
		getRoot    func(t *testing.T) *etree.Element
		wantErr    error
		wantErrMsg string
	}{
		{
			name: "success_valid_signature",
			rootCert: testdata.TestValidRootCert,
			getRoot: func(t *testing.T) *etree.Element {
				return testHelper.ParseXML(t, "rim/valid_signed_xml.xml")
			},
			wantErr: nil,
		},
		{
			name:     "failure_bad_root_cert_pem_format",
			rootCert: badFormatPEM,
			getRoot: func(t *testing.T) *etree.Element {
				return testHelper.ParseXML(t, "rim/valid_signed_xml.xml")
			},
			wantErr:    ErrRimSignatureVerificationFailed,
			wantErrMsg: "could not decode root certificate",
		},
		{
			name:     "failure_bad_root_cert_data",
			rootCert: badCertDataPEM,
			getRoot: func(t *testing.T) *etree.Element {
				return testHelper.ParseXML(t, "rim/valid_signed_xml.xml")
			},
			wantErr:    ErrRimSignatureVerificationFailed,
			wantErrMsg: "could not parse root certificate",
		},
		{
			name:     "failure_wrong_root_certificate",
			rootCert: wrongRootCertPEM,
			getRoot: func(t *testing.T) *etree.Element {
				return testHelper.ParseXML(t, "rim/valid_signed_xml.xml")
			},
			wantErr: ErrRimSignatureVerificationFailed,
		},
		{
			name: "failure_tampered_xml_invalid_signature",
			getRoot: func(t *testing.T) *etree.Element {
				root := testHelper.ParseXML(t, "rim/valid_signed_xml.xml")
				root.RemoveAttr("tagId")
				return root
			},
			wantErr: ErrRimSignatureVerificationFailed,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := &Data{
				root: tc.getRoot(t),
			}

			originalRoot := data.root
			err := data.verifyXMLSignatureWithRootCert(tc.rootCert, validXMLTime)
			if err != nil && tc.wantErr == nil && tc.wantErrMsg == "" {
				t.Fatalf("VerifyXMLSignatureWithRootCert() got unexpected error: %v", err)
			}
			if err == nil && (tc.wantErr != nil || tc.wantErrMsg != "") {
				t.Fatal("VerifyXMLSignatureWithRootCert() got nil error; want non-nil error")
			}
			if err != nil {
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("VerifyXMLSignatureWithRootCert() error = %v; want to wrap %v", err, tc.wantErr)
				}
				if tc.wantErrMsg != "" && !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("VerifyXMLSignatureWithRootCert() error = %v; want to contain %q", err, tc.wantErrMsg)
				}
			}
			if err == nil {
				if data.root == originalRoot {
					t.Fatal("VerifyXMLSignatureWithRootCert() did not update the root element")
				}
			}
		})
	}
}

func TestListRIMs(t *testing.T) {
	ctx := t.Context()
	rimIDsList := []string{"test-rim-file-id1", "test-rim-file-id2", "test-rim-file-id3"}
	validRespBody, err := json.Marshal(rimIDsResponse{IDs: rimIDsList})
	if err != nil {
		t.Fatalf("Failed to marshal RIM API response: %v", err)
	}
	defaultRoundTripFn := func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			return nil, fmt.Errorf("unexpected HTTP method: got %s, want %s", req.Method, http.MethodGet)
		}
		if got := req.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("unexpected Accept header: got %q, want %q", got, "application/json")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(validRespBody)),
		}, nil
	}

	tests := []struct {
		name        string
		serviceKey  string
		roundTripFn func(req *http.Request) (*http.Response, error)
		wantRIMIDs  []string
		wantErr     string
	}{
		{
			name:        "valid_request",
			roundTripFn: defaultRoundTripFn,
			wantRIMIDs:  rimIDsList,
		},
		{
			name:        "valid_request_with_service_key",
			roundTripFn: defaultRoundTripFn,
			serviceKey:  "test-service-key",
			wantRIMIDs:  rimIDsList,
		},
		{
			name:        "network_error",
			roundTripFn: newErrorRoundTripper(errors.New("simulated network error")),
			wantErr:     "simulated network error",
		},
		{
			name:        "error_reading_body",
			roundTripFn: newResponseRoundTripper(http.StatusOK, &mockReader{err: fmt.Errorf("simulated read error")}),
			wantErr:     "simulated read error",
		},
		{
			name:        "invalid_json",
			roundTripFn: newResponseRoundTripper(http.StatusOK, bytes.NewReader([]byte(`{"ids": ""}`))),
			wantErr:     "unmarshalling JSON response",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockHTTPClient := &http.Client{Transport: &mockRoundTripper{RoundTripFunc: tc.roundTripFn}}
			client := &DefaultNvidiaClient{httpClient: mockHTTPClient, serviceKey: tc.serviceKey}

			rimIDs, err := client.ListRIMs(ctx)
			if err == nil && !cmp.Equal(rimIDs, tc.wantRIMIDs) {
				t.Errorf("ListRIMs() returned RIM IDs:\n  got: %s\n want: %s", rimIDs, tc.wantRIMIDs)
			}
			if err != nil && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ListRIMs() returned error '%v', want error to contain '%v'", err, tc.wantErr)
			}
		})
	}
}
