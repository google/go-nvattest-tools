// Package rim provides a client for fetching RIMs (Reference Integrity Manifests) from Nvidia's RIM service.
package rim

import (
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/google/go-nvattest-tools/server/cert"
	"github.com/lestrrat-go/libxml2"
	"github.com/lestrrat-go/libxml2/xsd"
	"github.com/russellhaering/goxmldsig"
)

var (
	// DefaultSchema is the default XSD schema for RIM Verification.
	//
	//go:embed valid_schema.xsd
	DefaultSchema []byte
	// ErrRootElementNil is returned when the root element of the XML is nil.
	ErrRootElementNil = errors.New("xml root element is nil")
	// ErrElementNotFound is returned when an element is not found in the XML.
	ErrElementNotFound = errors.New("element not found")
	// ErrNoGoldenMeasurements is returned when no golden measurements are found in the RIM.
	ErrNoGoldenMeasurements = errors.New("no golden measurements found in RIM")
	// ErrRimSchemaValidationFailed is returned when the RIM Schema validation fails.
	ErrRimSchemaValidationFailed = errors.New("RIM Schema validation failed")
	// ErrRimSignatureVerificationFailed is returned when the signature verification fails.
	ErrRimSignatureVerificationFailed = errors.New("RIM signature verification failed")
)

const (
	// nvidiaRIMServiceURL is the default URL for Nvidia's RIM service.
	nvidiaRIMServiceURL = "https://rim.attestation.nvidia.com/v1/rim/"
	// serviceKeyHeader is the header name for authorization with a service key.
	serviceKeyHeader = "Authorization"
	// serviceKeyValueFormat is the format string for the service key value in the Authorization header.
	serviceKeyValueFormat = "Bearer %s" // Assuming "Bearer" token type
)

// Client is the interface for a client that fetches RIMs (Reference Integrity Manifests).
type Client interface {
	// ListRIMs lists the available RIMs (Reference Integrity Manifests).
	ListRIMs(ctx context.Context) ([]string, error)
	// FetchRIM fetches the RIM (Reference Integrity Manifest) with the given ID.
	FetchRIM(ctx context.Context, rimID string) (rimContent []byte, err error)
}

// DefaultNvidiaClient implements Client by calling Nvidia's public RIM service via HTTP.
type DefaultNvidiaClient struct {
	httpClient *http.Client
	serviceKey string
}

// NewDefaultNvidiaClient creates a new client for Nvidia's RIM service.
func NewDefaultNvidiaClient(httpClient *http.Client, serviceKey string) Client {
	if httpClient != nil {
		// Use the provided http client. This is mainly for mock testing purposes.
		return &DefaultNvidiaClient{httpClient: httpClient, serviceKey: serviceKey}
	}
	// Provide a default http client if none is provided.
	return &DefaultNvidiaClient{httpClient: http.DefaultClient, serviceKey: serviceKey}
}

// rimIDsResponse is the response from the Nvidia RIM server for listing RIMs.
type rimIDsResponse struct {
	RequestID   string   `json:"request_id"`
	LastUpdated string   `json:"last_updated"`
	IDs         []string `json:"ids"`
}

type rimResponse struct {
	// rimResponse definition as per Nvidia's RIM service API: https://docs.api.nvidia.com/attestation/reference/get_rim_v1_rim___id__get
	RequestID   string `json:"request_id"`
	LastUpdated string `json:"last_updated"`
	RIM         string `json:"rim"`
	ID          string `json:"id"`
	RimFormat   string `json:"rim_format"`
}

// ListRIMs lists all the Nvidia RIM (Reference Integrity Manifests) IDs.
func (c *DefaultNvidiaClient) ListRIMs(ctx context.Context) ([]string, error) {
	rimIDsURL, err := url.JoinPath(nvidiaRIMServiceURL, "ids")
	if err != nil {
		return nil, fmt.Errorf("constructing RIM URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rimIDsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating %s request for URL %s: %w", http.MethodGet, rimIDsURL, err)
	}

	req.Header.Set("Accept", "application/json")

	if c.serviceKey != "" {
		req.Header.Set(serviceKeyHeader, fmt.Sprintf(serviceKeyValueFormat, c.serviceKey))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending GET request to %s: %w", rimIDsURL, err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var rimIDsResp rimIDsResponse
	if err := json.Unmarshal(bodyBytes, &rimIDsResp); err != nil {
		return nil, fmt.Errorf("unmarshalling JSON response: %w", err)
	}
	return rimIDsResp.IDs, nil
}

// FetchRIM is the default implementation for the FetchRIM function of Client Interface.
// Reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L392
func (c *DefaultNvidiaClient) FetchRIM(ctx context.Context, rimID string) (rimContent []byte, err error) {
	rimURL, err := url.JoinPath(nvidiaRIMServiceURL, rimID)
	if err != nil {
		return nil, fmt.Errorf("constructing RIM URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rimURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating %s request for URL %s: %w", http.MethodGet, rimURL, err)
	}

	req.Header.Set("Content-Type", "application/json")

	if c.serviceKey != "" {
		req.Header.Set(serviceKeyHeader, fmt.Sprintf(serviceKeyValueFormat, c.serviceKey))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending GET request to %s: %w", rimURL, err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Unmarshal the JSON response into the struct that holds the "rim" key
	var rimResp rimResponse
	if err := json.Unmarshal(bodyBytes, &rimResp); err != nil {
		return nil, fmt.Errorf("unmarshalling JSON response: %w", err)
	}

	// Check if the "rim" field is present and non-empty
	if rimResp.RIM == "" {
		return nil, fmt.Errorf("response body is empty")
	}

	// Decode the base64 string from the 'RIM' field
	decodedBytes, err := base64.StdEncoding.DecodeString(rimResp.RIM)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 string: %w", err)
	}
	return decodedBytes, nil
}

// Data represents a parsed RIM from Nvidia's RIM service response which is in bytes.
type Data struct {
	root              *etree.Element
	colloquialVersion string
	certificateChain  []*x509.Certificate
}

// GoldenMeasurement is a struct to hold the golden measurement data extracted from RIM.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/8c40874adb53b01608a0e73b153a67c8fbcc1a9f/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/rim/golden_measurement.py#L31.
type GoldenMeasurement struct {
	Component    string
	Values       []string
	Name         string
	Index        int
	Size         int
	Alternatives int
	Active       bool
}

// Parse parses the RIM raw bytes into a Data struct.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/rim/__init__.py#L105
func Parse(rimBytes []byte) (*Data, error) {

	// parse the raw bytes into an etree.Tree
	doc := etree.NewDocument()

	if err := doc.ReadFromBytes(rimBytes); err != nil {
		return nil, fmt.Errorf("parsing RIM bytes: %w", err)
	}

	root := doc.Root()

	if root == nil {
		return nil, fmt.Errorf("%w", ErrRootElementNil)
	}

	colloquialVersion, err := extractColloquialVersion(root)
	if err != nil {
		return nil, err
	}

	certificateChain, err := extractCertificateChain(root)
	if err != nil {
		return nil, err
	}

	return &Data{
		root:              root,
		colloquialVersion: colloquialVersion,
		certificateChain:  certificateChain,
	}, nil
}

// ValidateSchema validates the RIM against the schema.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/rim/__init__.py#L150
func (d *Data) ValidateSchema(schemaPath string) error {
	var schemaBytes []byte
	var err error

	if schemaPath != "" {
		schemaBytes, err = os.ReadFile(schemaPath)
		if err != nil {
			return fmt.Errorf("%w: could not read schema file: %v", ErrRimSchemaValidationFailed, err)
		}
	} else {
		schemaBytes = DefaultSchema
	}
	schema, err := xsd.Parse(schemaBytes)
	if err != nil {
		return fmt.Errorf("%w: could not parse schema file: %v", ErrRimSchemaValidationFailed, err)
	}
	defer schema.Free()

	docForWrite := etree.NewDocument()
	docForWrite.SetRoot(d.root)
	xmlString, err := docForWrite.WriteToString()
	if err != nil {
		return fmt.Errorf("%w: could not write document to string: %v", ErrRimSchemaValidationFailed, err)
	}

	docToValidate, err := libxml2.ParseString(xmlString)
	if err != nil {
		return fmt.Errorf("%w: could not parse document: %v", ErrRimSchemaValidationFailed, err)
	}
	defer docToValidate.Free()

	if err := schema.Validate(docToValidate); err != nil {
		return fmt.Errorf("%w: %v", ErrRimSchemaValidationFailed, err.Error())
	}
	return nil

}

// VerifyXMLSignature verifies the signature of the XML.
func (d *Data) VerifyXMLSignature(now time.Time) error {
	return d.verifyXMLSignatureWithRootCert(cert.RimRootCertPEM, now)
}

// VerifyXMLSignatureWithRootCert verifies the signature of the XML using the root certificate.
// After successful validation, it replaces the document's root element with the validated element.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/attestation_sdk/src/nv_attestation_sdk/verifiers/nv_switch_verifier/rim/__init__.py#L262
func (d *Data) verifyXMLSignatureWithRootCert(rootCertPEM []byte, now time.Time) error {
	pemBlock, _ := pem.Decode(rootCertPEM)
	if pemBlock == nil {
		return fmt.Errorf("%w: could not decode root certificate", ErrRimSignatureVerificationFailed)
	}
	parsedRootCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("%w: could not parse root certificate %v", ErrRimSignatureVerificationFailed, err)
	}

	certStore := &dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{parsedRootCert},
	}

	validationContext := dsig.NewDefaultValidationContext(certStore)
	// Override the clock to use a fake clock set to the given time for verifying the signature.
	validationContext.Clock = dsig.NewFakeClockAt(now)
	doc := etree.NewDocument()
	doc.SetRoot(d.root)
	validatedElement, err := validationContext.Validate(d.root)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRimSignatureVerificationFailed, err)
	}
	doc.SetRoot(validatedElement)
	d.root = doc.Root()
	return nil
}

// Measurements returns the golden measurements from the RIM.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/rim/__init__.py#L345
func (d *Data) Measurements(rimName, hashFunctionNamespace string) ([]GoldenMeasurement, error) {
	payload := d.root.FindElement("Payload")
	if payload == nil {
		return nil, fmt.Errorf("%w", ErrElementNotFound)
	}

	measurementsMap := make(map[int]GoldenMeasurement)

	for _, child := range payload.ChildElements() {
		activeStr := child.SelectAttrValue("active", "false")
		active, _ := strconv.ParseBool(activeStr)

		indexStr := child.SelectAttrValue("index", "")
		if indexStr == "" {
			return nil, fmt.Errorf("%w - index attribute in Payload tag", ErrElementNotFound)
		}

		index, err := strconv.Atoi(indexStr)
		if err != nil {
			return nil, fmt.Errorf("parsing index attribute in Payload tag: %w", err)
		}

		if _, exists := measurementsMap[index]; exists {
			return nil, fmt.Errorf("invalid measurement index: multiple measurements have the same index %d", index)
		}

		alternativesStr := child.SelectAttrValue("alternatives", "")
		if alternativesStr == "" {
			return nil, fmt.Errorf("%w - alternatives attribute in Payload tag", ErrElementNotFound)
		}

		alternatives, err := strconv.Atoi(alternativesStr)
		if err != nil {
			return nil, fmt.Errorf("attribute 'alternatives' has invalid integer value '%s' for index %d", alternativesStr, index)
		}

		sizeStr := child.SelectAttrValue("size", "")
		if sizeStr == "" {
			return nil, fmt.Errorf("%w - size attribute in Payload tag", ErrElementNotFound)
		}

		size, err := strconv.Atoi(sizeStr)
		if err != nil {
			return nil, fmt.Errorf("attribute 'size' has invalid integer value '%s' for index %d", sizeStr, index)
		}
		attrValues := make(map[string]string)
		for _, attr := range child.Attr {
			if attr.NamespaceURI() == hashFunctionNamespace && strings.HasPrefix(attr.Key, "Hash") {
				attrValues[attr.Key] = attr.Value
			}
		}

		measurementValues := make([]string, 0, alternatives)

		for i := 0; i < alternatives; i++ {
			key := "Hash" + strconv.Itoa(i)
			value, found := attrValues[key]

			if !found {
				return nil, fmt.Errorf("attribute %q with namespace %q not found for index %d", key, hashFunctionNamespace, index)
			}
			measurementValues = append(measurementValues, value)

		}

		measurementsMap[index] = GoldenMeasurement{
			Component:    rimName,
			Values:       measurementValues,
			Name:         child.SelectAttrValue("name", ""),
			Index:        index,
			Size:         size,
			Alternatives: alternatives,
			Active:       active,
		}
	}
	if len(measurementsMap) == 0 {
		return nil, fmt.Errorf("%w", ErrNoGoldenMeasurements)
	}

	finalMeasurements := make([]GoldenMeasurement, 0, len(measurementsMap))

	for _, measurement := range measurementsMap {
		finalMeasurements = append(finalMeasurements, measurement)
	}
	return finalMeasurements, nil
}

// extractColloquialVersion extracts the colloquialVersion attribute from the Meta tag.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/rim/__init__.py#L202
func extractColloquialVersion(root *etree.Element) (string, error) {
	meta := root.FindElement("Meta")
	if meta == nil {
		return "", fmt.Errorf("%w - Meta tag", ErrElementNotFound)
	}

	colloquialVersion := meta.SelectAttrValue("colloquialVersion", "")
	if colloquialVersion == "" {
		return "", fmt.Errorf("%w - colloquialVersion attribute in Meta tag", ErrElementNotFound)
	}
	return colloquialVersion, nil
}

// extractCertificateChain extracts the certificate chain from the X509Data tag.
// reference to equivalent nvtrust library logic : https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/rim/__init__.py#L230
func extractCertificateChain(root *etree.Element) ([]*x509.Certificate, error) {
	// Navigate: Signature ->Keyinfo -> X509Data
	x509Data := root.FindElement("Signature/KeyInfo/X509Data")
	if x509Data == nil {
		return nil, fmt.Errorf("%w - Signature/KeyInfo/X509Data", ErrElementNotFound)
	}

	// Find all X509Certificate elements within X509Data
	x509Certificates := x509Data.FindElements("X509Certificate")
	if len(x509Certificates) == 0 {
		return nil, fmt.Errorf("%w - X509Certificate", ErrElementNotFound)
	}

	var certChain []*x509.Certificate
	for _, x509Certificate := range x509Certificates {
		base64Cert := x509Certificate.Text()
		pemData := []byte("-----BEGIN CERTIFICATE-----\n" + base64Cert + "\n-----END CERTIFICATE-----")
		certDer, _ := pem.Decode(pemData)
		if certDer == nil {
			return nil, fmt.Errorf("Failed to decode PEM data")
		}
		cert, err := x509.ParseCertificate(certDer.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing X509Certificate: %w", err)
		}
		certChain = append(certChain, cert)
	}
	return certChain, nil
}

// ColloquialVersion returns the colloquialVersion attribute from the Meta tag.
func (d *Data) ColloquialVersion() string {
	return d.colloquialVersion
}

// CertificateChain returns the certificate chain from the X509Data tag.
func (d *Data) CertificateChain() []*x509.Certificate {
	return d.certificateChain
}
