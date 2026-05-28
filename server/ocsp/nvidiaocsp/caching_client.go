// Package nvidiaocsp provides a client for accessing cached OCSP responses.
package nvidiaocsp

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"

	ocsppb "github.com/google/go-nvattest-tools/proto/nvocsp"
)

// CachingClient is a client that fetches OCSP responses from an in-memory cache.
type CachingClient struct {
	rimOCSPResponses    *ocsppb.OCSPResponses
	deviceOCSPResponses *ocsppb.OCSPResponses
	l4RevokedCerts      map[string]struct{}
}

// NewClient creates a new caching client from a Nvidia OCSPResponses and DeviceL4RevokedCerts proto.
func NewClient(rimOCSPResponses *ocsppb.OCSPResponses, deviceOCSPResponses *ocsppb.OCSPResponses, l4RevokedCerts *ocsppb.DeviceL4RevokedCerts) *CachingClient {
	l4RevokedCertsMap := make(map[string]struct{})
	for _, certInfo := range l4RevokedCerts.GetCrl() {
		key := fmt.Sprintf("%s:%s", certInfo.GetCertSerialNumber(), certInfo.GetIssuerDn())
		l4RevokedCertsMap[key] = struct{}{}
	}
	return &CachingClient{
		rimOCSPResponses:    rimOCSPResponses,
		deviceOCSPResponses: deviceOCSPResponses,
		l4RevokedCerts:      l4RevokedCertsMap,
	}
}

// FetchOCSPResponse fetches the OCSP response for a given target certificate and its issuer.
// It checks RIM, Device L1-L3, and Device L4 caches in order.
// If no match is found, it returns an OCSP response with status ocsp.Unknown.
func (c *CachingClient) FetchOCSPResponse(_ context.Context, targetCert, issuerCert *x509.Certificate) (*ocsp.Response, error) {

	if targetCert == nil || issuerCert == nil {
		return nil, fmt.Errorf("target and issuer certificates cannot be nil")
	}

	targetCertKey := fmt.Sprintf("%s:%s", targetCert.SerialNumber.String(), targetCert.Issuer.String())
	issuerCertKey := fmt.Sprintf("%s:%s", issuerCert.SerialNumber.String(), issuerCert.Issuer.String())

	// Check RIM responses.
	resp, ok, err := c.checkRIMOCSPResponses(targetCertKey, issuerCertKey, issuerCert)
	if ok {
		return resp, err
	}

	// Check Device responses (L1-L4).
	resp, ok, err = c.checkDeviceOCSPResponses(targetCert, issuerCert, targetCertKey, issuerCertKey)
	if ok {
		return resp, err
	}

	// If no response was found in any cache, return Unknown status.
	resp, err = constructFakeOCSPResponse(targetCert, issuerCert, ocsp.Unknown)
	return resp, err
}

// checkRIMOCSPResponses checks if the RIM cache contains a valid OCSP response.
// It returns ok=true if a response was found or a parsing error occurred.
func (c *CachingClient) checkRIMOCSPResponses(targetCertKey, issuerCertKey string, issuerCert *x509.Certificate) (*ocsp.Response, bool, error) {
	targetCertSI, targetOk := c.rimOCSPResponses.GetCertStatusInfo()[targetCertKey]
	_, issuerOk := c.rimOCSPResponses.GetCertStatusInfo()[issuerCertKey]

	if targetCertSI.GetCertIndex() == ocsppb.CertificateLevel_CERTIFICATE_LEVEL_L2 {
		// The OCSP response for the root RIM certificate is not cached.
		// If the target certificate is L2, then the issuer must be the root.
		issuerOk = true
	}

	if targetOk && issuerOk {
		resp, err := ocsp.ParseResponse(targetCertSI.GetRawOcspResponseBytes(), issuerCert)
		return resp, true, err
	}
	return nil, false, nil
}

// checkDeviceOCSPResponses checks if the device cache contains a valid OCSP response,
// or if the certificate is an L4 certificate with a Good or Revoked status.
// It returns ok=true if a response was found/constructed or a parsing error occurred.
func (c *CachingClient) checkDeviceOCSPResponses(targetCert, issuerCert *x509.Certificate, targetCertKey, issuerCertKey string) (*ocsp.Response, bool, error) {
	targetCertSI, targetOk := c.deviceOCSPResponses.GetCertStatusInfo()[targetCertKey]
	issuerCertSI, issuerOk := c.deviceOCSPResponses.GetCertStatusInfo()[issuerCertKey]

	// Check for L1-L3 certificates. Both target and issuer must be in cache for these levels.
	if targetOk && issuerOk {
		level := targetCertSI.GetCertIndex()
		if level == ocsppb.CertificateLevel_CERTIFICATE_LEVEL_L1 ||
			level == ocsppb.CertificateLevel_CERTIFICATE_LEVEL_L2 ||
			level == ocsppb.CertificateLevel_CERTIFICATE_LEVEL_L3 {
			resp, err := ocsp.ParseResponse(targetCertSI.GetRawOcspResponseBytes(), issuerCert)
			return resp, true, err
		}
	}

	// Check for L4 certificates.
	// If the issuer certificate is present in the L1-L3 device certificate cache, then the
	// target certificate is an L4 certificate. Its status depends on the L4 CRL.
	if issuerOk && issuerCertSI.GetCertIndex() == ocsppb.CertificateLevel_CERTIFICATE_LEVEL_L3 {
		if c.checkL4CRL(targetCert) {
			resp, err := constructFakeOCSPResponse(targetCert, issuerCert, ocsp.Revoked)
			return resp, true, err
		}
		resp, err := constructFakeOCSPResponse(targetCert, issuerCert, ocsp.Good)
		return resp, true, err
	}

	return nil, false, nil
}

// checkL4CRL returns true if the target certificate is in the Device L4 CRL.
func (c *CachingClient) checkL4CRL(targetCert *x509.Certificate) bool {
	key := fmt.Sprintf("%s:%s", targetCert.SerialNumber.String(), targetCert.Issuer.String())
	_, found := c.l4RevokedCerts[key]
	return found
}

// constructFakeOCSPResponse creates an unsigned OCSP response with minimal fields and the given status.
func constructFakeOCSPResponse(targetCert, issuerCert *x509.Certificate, status int) (*ocsp.Response, error) {
	resp := &ocsp.Response{
		Status:             status,
		SerialNumber:       targetCert.SerialNumber,
		ThisUpdate:         time.Now(),
		Certificate:        issuerCert,
		Signature:          targetCert.Signature,
		SignatureAlgorithm: targetCert.SignatureAlgorithm,
		TBSResponseData:    targetCert.RawTBSCertificate,
	}
	return resp, nil
}
