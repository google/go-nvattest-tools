// Package cert provides pre-parsed root certificates for NVIDIA attestation.
package cert

import (
	"crypto/x509"
	_ "embed"
)

// DeviceRootCertPEM is the PEM-encoded root certificate for GPU/Switch devices.
//
//go:embed device_root.pem
var DeviceRootCertPEM []byte

// RimRootCertPEM is the PEM-encoded root certificate for RIM files.
//
//go:embed rim_root.pem
var RimRootCertPEM []byte

var (
	// DeviceRootCertPool is a pre-parsed cert pool with the device root certificate.
	DeviceRootCertPool *x509.CertPool
	// RimRootCertPool is a pre-parsed cert pool with the RIM root certificate.
	RimRootCertPool *x509.CertPool
)

func init() {
	// Initialize the pool for GPU/Switch device certificates.
	DeviceRootCertPool = x509.NewCertPool()
	if ok := DeviceRootCertPool.AppendCertsFromPEM(DeviceRootCertPEM); !ok {
		panic("cert: failed to parse embedded device_root.pem certificate")
	}

	// Initialize the pool for RIM file certificates.
	RimRootCertPool = x509.NewCertPool()
	if ok := RimRootCertPool.AppendCertsFromPEM(RimRootCertPEM); !ok {
		panic("cert: failed to parse embedded rim_root.pem certificate")
	}
}
