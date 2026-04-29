package ocsp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/ocsp"
)

// Helper function to create a test certificate.
func newTestCertificate(t *testing.T) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	return cert, cert, privateKey
}

// Helper function to create a valid OCSP response.
func newValidOCSPResponse(t *testing.T, issuerCert, targetCert *x509.Certificate, key *rsa.PrivateKey) *ocsp.Response {
	t.Helper()
	now := time.Now().Truncate(time.Minute)
	respTemplate := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: targetCert.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(24 * time.Hour),
	}
	respBytes, err := ocsp.CreateResponse(issuerCert, targetCert, respTemplate, key)
	if err != nil {
		t.Fatalf("Failed to create OCSP response: %v", err)
	}
	resp, err := ocsp.ParseResponse(respBytes, issuerCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}
	return resp
}

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

// TestNewDefaultNvidiaClient tests the NewDefaultNvidiaClient function responsible for creating a new DefaultNvidiaClient instance.
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
				t.Errorf("%s\nNewDefaultNvidiaClient() returned unexpected diff (-want +got):\n%s", tc.desc, diff)
			}
		})
	}
}

// TestFetchOCSPResponseSuccess tests the FetchOCSPResponse function for successful scenarios.
func TestFetchOCSPResponseSuccess(t *testing.T) {
	ctx := t.Context()
	targetCert, issuerCert, key := newTestCertificate(t)
	validOCSPResponse := newValidOCSPResponse(t, issuerCert, targetCert, key)

	tests := []struct {
		name        string
		desc        string
		roundTripFn func(req *http.Request) (*http.Response, error)
		serviceKey  string
	}{
		{
			name: "valid_request",
			desc: "successful request with no service key",
			roundTripFn: func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodPost {
					return nil, fmt.Errorf("unexpected HTTP method: %s", req.Method)
				}
				if req.Header.Get("Content-Type") != "application/ocsp-request" {
					return nil, fmt.Errorf("unexpected Content-Type header: %s", req.Header.Get("Content-Type"))
				}
				respBody := validOCSPResponse.Raw
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(respBody)),
				}, nil
			},
			serviceKey: "",
		},
		{
			name: "valid_request_with_service_key",
			desc: "successful request with a service key",
			roundTripFn: func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodPost {
					return nil, fmt.Errorf("unexpected HTTP method: %s", req.Method)
				}
				if req.Header.Get("Content-Type") != "application/ocsp-request" {
					return nil, fmt.Errorf("unexpected Content-Type header: %s", req.Header.Get("Content-Type"))
				}
				if req.Header.Get(serviceKeyHeader) != fmt.Sprintf(serviceKeyValueFormat, "test-service-key") {
					return nil, fmt.Errorf("unexpected Authorization header: %s", req.Header.Get(serviceKeyHeader))
				}
				respBody := validOCSPResponse.Raw
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(respBody)),
				}, nil
			},
			serviceKey: "test-service-key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockHTTPClient := &http.Client{Transport: &mockRoundTripper{RoundTripFunc: tc.roundTripFn}}
			client := &DefaultNvidiaClient{httpClient: mockHTTPClient, serviceKey: tc.serviceKey}
			resp, err := client.FetchOCSPResponse(ctx, targetCert, issuerCert)
			if err != nil {
				t.Fatalf("%s\nFetchOCSPResponse() unexpected error: %v", tc.desc, err)
			}
			if resp == nil {
				t.Fatalf("%s\nFetchOCSPResponse() expected a response but got nil", tc.desc)
			}

			if got, want := resp.Status, validOCSPResponse.Status; got != want {
				t.Errorf("%s\nresp.Status = %v, want %v", tc.desc, got, want)
			}

			if resp.SerialNumber.Cmp(validOCSPResponse.SerialNumber) != 0 {
				t.Errorf("%s\nresp.SerialNumber = %v, want %v", tc.desc, resp.SerialNumber, validOCSPResponse.SerialNumber)
			}
		})
	}
}

// TestFetchOCSPResponseFailure tests the FetchOCSPResponse function for failure scenarios.
func TestFetchOCSPResponseFailure(t *testing.T) {
	ctx := t.Context()
	targetCert, issuerCert, _ := newTestCertificate(t)

	tests := []struct {
		name        string
		desc        string
		targetCert  *x509.Certificate
		issuerCert  *x509.Certificate
		roundTripFn func(req *http.Request) (*http.Response, error)
		wantOCSPErr error
	}{
		{
			name: "nil_target_cert",
			desc: "target certificate is nil",
			roundTripFn: func(req *http.Request) (*http.Response, error) {
				return nil, nil
			},
			wantOCSPErr: errNilCertificates,
			targetCert:  nil,
			issuerCert:  issuerCert,
		},
		{
			name: "nil_issuer_cert",
			desc: "issuer certificate is nil",
			roundTripFn: func(req *http.Request) (*http.Response, error) {
				return nil, nil
			},
			wantOCSPErr: errNilCertificates,
			targetCert:  targetCert,
			issuerCert:  nil,
		},
		{
			name: "network_error",
			desc: "http client returns network error",
			roundTripFn: func(req *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("simulated network error")
			},
			targetCert: targetCert,
			issuerCert: issuerCert,
		},
		{
			name: "empty_ocsp_response",
			desc: "OCSP response body is empty",
			roundTripFn: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			},
			wantOCSPErr: errOCSPParse,
			targetCert:  targetCert,
			issuerCert:  issuerCert,
		},
		{
			name: "invalid_ocsp_response",
			desc: "OCSP response body is invalid",
			roundTripFn: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte("invalid OCSP response"))),
				}, nil
			},
			wantOCSPErr: errOCSPParse,
			targetCert:  targetCert,
			issuerCert:  issuerCert,
		},
		{
			name: "error_reading_body",
			desc: "Error while reading http response body",
			roundTripFn: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(&mockReader{err: errors.New("simulated read error")}),
				}, nil
			},
			targetCert: targetCert,
			issuerCert: issuerCert,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockHTTPClient := &http.Client{Transport: &mockRoundTripper{RoundTripFunc: tc.roundTripFn}}
			client := &DefaultNvidiaClient{httpClient: mockHTTPClient}
			_, err := client.FetchOCSPResponse(ctx, tc.targetCert, tc.issuerCert)
			if err == nil {
				t.Errorf("%s\nFetchOCSPResponse() expected an error but got nil, want %v", tc.desc, tc.wantOCSPErr)
				return
			}
			if tc.wantOCSPErr != nil && !errors.Is(err, tc.wantOCSPErr) {
				t.Errorf("%s\nFetchOCSPResponse() error: got %v (type %T), want error that is or wraps %v (type %T)", tc.desc, err, err, tc.wantOCSPErr, tc.wantOCSPErr)
			}
		})
	}
}
