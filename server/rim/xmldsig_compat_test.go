// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
)

// These tests pin the two upstream goxmldsig gaps that NVIDIA RIMs hit
// (see xmldsig_compat.go). Each one fails if validateXMLSignature is replaced
// by a plain dsig.ValidationContext with the RIM root as the only trusted
// certificate, which is what rim.go did with an unpatched goxmldsig.

var compatNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type compatCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newCompatCert(t *testing.T, cn string, isCA bool, parent *compatCA, mod func(*x509.Certificate)) *compatCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             compatNow.Add(-24 * time.Hour),
		NotAfter:              compatNow.Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if mod != nil {
		mod(tmpl)
	}
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &compatCA{key: key, cert: cert}
}

const compatSWID = `<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns0="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="GH100" tagId="t" version="1.0"><ns0:Meta colloquialVersion="1"/><ns0:Payload/></SoftwareIdentity>`

// signCompat signs compatSWID like an NVIDIA RIM: enveloped, C14N 1.1,
// ecdsa-sha384, KeyInfo = chain (leaf first). If p1363 is set the
// SignatureValue is re-encoded from DER to r||s, as NVIDIA does.
func signCompat(t *testing.T, signer crypto.Signer, chain []*x509.Certificate, p1363 bool) *etree.Element {
	t.Helper()
	var raw [][]byte
	for _, c := range chain {
		raw = append(raw, c.Raw)
	}
	ctx, err := dsig.NewSigningContext(signer, raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N11Canonicalizer()
	ctx.Prefix = "ds"
	if err := ctx.SetSignatureMethod(dsig.ECDSASHA384SignatureMethod); err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(compatSWID); err != nil {
		t.Fatal(err)
	}
	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	if p1363 {
		sv := signed.FindElement(".//SignatureValue")
		der, err := base64.StdEncoding.DecodeString(sv.Text())
		if err != nil {
			t.Fatal(err)
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &rs); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 96)
		rs.R.FillBytes(out[:48])
		rs.S.FillBytes(out[48:])
		sv.SetText(base64.StdEncoding.EncodeToString(out))
	}
	// Round-trip through bytes, as RIMs arrive.
	out := etree.NewDocument()
	out.SetRoot(signed)
	b, err := out.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	d := etree.NewDocument()
	if err := d.ReadFromBytes(b); err != nil {
		t.Fatal(err)
	}
	return d.Root()
}

// plainUpstream is how rim.go validated before xmldsig_compat.go existed.
func plainUpstream(el *etree.Element, root *x509.Certificate, now time.Time) error {
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{root}})
	ctx.Clock = dsig.NewFakeClockAt(now)
	_, err := ctx.Validate(el)
	return err
}

// TestXMLSignatureCompat_ECDSAP1363 isolates gap 1: the signer is the
// trusted root itself (so upstream's certificate check passes) and the
// SignatureValue is r||s.
func TestXMLSignatureCompat_ECDSAP1363(t *testing.T) {
	root := newCompatCert(t, "root", true, nil, nil)
	el := signCompat(t, root.key, []*x509.Certificate{root.cert}, true)

	if err := plainUpstream(el, root.cert, compatNow); err == nil {
		t.Log("note: plain upstream goxmldsig now accepts r||s ECDSA signatures (upstream #163 fixed?)")
	} else {
		t.Logf("plain upstream goxmldsig: %v", err)
	}
	if _, err := validateXMLSignature(el, root.cert, compatNow); err != nil {
		t.Fatalf("validateXMLSignature(r||s ECDSA) = %v, want nil", err)
	}
	// DER-encoded signatures keep working (fork fell back to the raw bytes).
	der := signCompat(t, root.key, []*x509.Certificate{root.cert}, false)
	if _, err := validateXMLSignature(der, root.cert, compatNow); err != nil {
		t.Fatalf("validateXMLSignature(DER ECDSA) = %v, want nil", err)
	}
	// The caller's tree is not modified.
	before := elString(t, el)
	_, _ = validateXMLSignature(el, root.cert, compatNow)
	if after := elString(t, el); after != before {
		t.Errorf("validateXMLSignature modified its input")
	}
}

// TestXMLSignatureCompat_CertificateChain isolates gap 2: the signature
// value is DER (so upstream's ECDSA handling is not involved) and the
// signing certificate chains to the root through an intermediate.
func TestXMLSignatureCompat_CertificateChain(t *testing.T) {
	root := newCompatCert(t, "root", true, nil, nil)
	inter := newCompatCert(t, "intermediate", true, root, nil)
	leaf := newCompatCert(t, "leaf", false, inter, nil)
	foreignRoot := newCompatCert(t, "foreign root", true, nil, nil)
	expired := newCompatCert(t, "expired leaf", false, inter, func(c *x509.Certificate) {
		c.NotAfter = compatNow.Add(-time.Hour)
	})

	good := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, inter.cert}, false)
	if err := plainUpstream(good, root.cert, compatNow); err == nil {
		t.Log("note: plain upstream goxmldsig now verifies certificate chains (upstream #192 merged?)")
	} else {
		t.Logf("plain upstream goxmldsig: %v", err)
	}

	tests := []struct {
		name    string
		el      *etree.Element
		root    *x509.Certificate
		wantErr string
	}{
		{name: "leaf+intermediate", el: good, root: root.cert},
		{name: "leaf+intermediate+root", el: signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, inter.cert, root.cert}, true), root: root.cert},
		{name: "r||s and chain together, like NVIDIA", el: signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, inter.cert}, true), root: root.cert},
		{name: "missing intermediate", el: signCompat(t, leaf.key, []*x509.Certificate{leaf.cert}, false), root: root.cert,
			wantErr: "could not verify certificate against trusted certs: x509: certificate signed by unknown authority"},
		{name: "foreign root", el: good, root: foreignRoot.cert,
			wantErr: "could not verify certificate against trusted certs: x509: certificate signed by unknown authority"},
		{name: "expired leaf", el: signCompat(t, expired.key, []*x509.Certificate{expired.cert, inter.cert}, false), root: root.cert,
			wantErr: "could not verify certificate against trusted certs: x509: certificate has expired or is not yet valid"},
		{name: "wrong signer for leaf", el: signCompat(t, inter.key, []*x509.Certificate{leaf.cert, inter.cert}, false), root: root.cert,
			wantErr: "x509: ECDSA verification failure"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateXMLSignature(tc.el, tc.root, compatNow)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateXMLSignature() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.HasPrefix(err.Error(), tc.wantErr) {
				t.Fatalf("validateXMLSignature() = %v, want prefix %q", err, tc.wantErr)
			}
		})
	}
}

func elString(t *testing.T, el *etree.Element) string {
	t.Helper()
	d := etree.NewDocument()
	d.SetRoot(el.Copy())
	s, err := d.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
