// Package ocsp provides functionality for working with OCSP (Online Certificate Status Protocol) responses.
package ocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

// Define sentinel error values.
var (
	errOCSPParse       = errors.New("ocsp: parse ocsp response")
	errNilCertificates = errors.New("ocsp: target and issuer certificates cannot be nil")
)

const (
	// nvidiaOCSPServiceURL is the default URL for Nvidia's OCSP service.
	nvidiaOCSPServiceURL = "https://ocsp.ndis.nvidia.com/"
	// serviceKeyHeader is the header name for authorization with a service key.
	serviceKeyHeader = "Authorization"
	// serviceKeyValueFormat is the format string for the service key value in the Authorization header.
	serviceKeyValueFormat = "Bearer %s" // Assuming "Bearer" token type
)

// Client defines a generic interface for fetching OCSP responses.
type Client interface {
	// FetchOCSPResponse returns the OCSP response.
	FetchOCSPResponse(ctx context.Context, targetCert, issuerCert *x509.Certificate) (*ocsp.Response, error)
}

// DefaultNvidiaClient implements Client by calling a public OCSP responder via HTTP.
type DefaultNvidiaClient struct {
	httpClient *http.Client
	serviceKey string // For Authorization header
}

// NewDefaultNvidiaClient creates a new client for Nvidia's OCSP service.
func NewDefaultNvidiaClient(httpClient *http.Client, serviceKey string) Client {
	if httpClient != nil {
		// Use the provided http client. This is mainly for mock testing purposes.
		return &DefaultNvidiaClient{httpClient: httpClient, serviceKey: serviceKey}
	}
	// Provide a default http client if none is provided.
	return &DefaultNvidiaClient{httpClient: http.DefaultClient, serviceKey: serviceKey}
}

// FetchOCSPResponse returns the OCSP response for the given certificate.
// Reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L341
func (c *DefaultNvidiaClient) FetchOCSPResponse(ctx context.Context, targetCert, issuerCert *x509.Certificate) (*ocsp.Response, error) {

	if targetCert == nil || issuerCert == nil {
		return nil, errNilCertificates
	}

	// The NVIDIA OCSP service expects requests to use the SHA384 hash, so it is hardcoded here
	// to align with the canonical nvtrust reference implementation.
	// Reference: https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L255
	requestBytes, err := ocsp.CreateRequest(targetCert, issuerCert, &ocsp.RequestOptions{Hash: crypto.SHA384})
	if err != nil {
		return nil, fmt.Errorf("ocsp: creating request for cert SN %s, issuer SN %s: %w", targetCert.SerialNumber, issuerCert.SerialNumber, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nvidiaOCSPServiceURL, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, fmt.Errorf("ocsp: creating %s request for URL %s: %w", http.MethodPost, nvidiaOCSPServiceURL, err)
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	if c.serviceKey != "" {
		req.Header.Set(serviceKeyHeader, fmt.Sprintf(serviceKeyValueFormat, c.serviceKey))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ocsp: sending POST request to %s: %w", req.URL, err)
	}
	defer resp.Body.Close()

	ocspResponseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ocsp: reading response body: %w", err)
	}

	// Parse OCSP response.
	ocspResp, err := ocsp.ParseResponseForCert(ocspResponseBytes, targetCert, issuerCert)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, errOCSPParse)
	}

	return ocspResp, nil
}
