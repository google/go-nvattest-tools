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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/google/go-cmp/cmp"
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
	return newCompatCertWithCurve(t, cn, elliptic.P384(), isCA, parent, mod)
}

func newCompatCertWithCurve(t *testing.T, cn string, curve elliptic.Curve, isCA bool, parent *compatCA, mod func(*x509.Certificate)) *compatCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(%s): %v", cn, err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("rand.Int(%s): %v", cn, err)
	}
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
		t.Fatalf("x509.CreateCertificate(%s): %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(%s): %v", cn, err)
	}
	return &compatCA{key: key, cert: cert}
}

const compatSWID = `<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns0="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="GH100" tagId="t" version="1.0"><ns0:Meta colloquialVersion="1"/><ns0:Payload/></SoftwareIdentity>`

// signCompat signs compatSWID like an NVIDIA RIM: enveloped, C14N 1.1,
// ECDSA, KeyInfo = chain (leaf first). If p1363 is set the SignatureValue is
// re-encoded from DER to r||s, as NVIDIA does.
func signCompat(t *testing.T, signer crypto.Signer, chain []*x509.Certificate, p1363 bool) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(compatSWID); err != nil {
		t.Fatalf("ReadFromString(compatSWID): %v", err)
	}
	return signCompatElement(t, doc.Root(), signer, chain, p1363)
}

func signCompatElement(t *testing.T, el *etree.Element, signer crypto.Signer, chain []*x509.Certificate, p1363 bool) *etree.Element {
	t.Helper()
	var raw [][]byte
	for _, c := range chain {
		raw = append(raw, c.Raw)
	}
	ctx, err := dsig.NewSigningContext(signer, raw)
	if err != nil {
		t.Fatalf("dsig.NewSigningContext: %v", err)
	}
	ctx.Canonicalizer = dsig.MakeC14N11Canonicalizer()
	ctx.Prefix = "ds"
	method := dsig.ECDSASHA384SignatureMethod
	if ec, ok := signer.Public().(*ecdsa.PublicKey); ok && ec.Curve == elliptic.P256() {
		method = dsig.ECDSASHA256SignatureMethod
	}
	if err := ctx.SetSignatureMethod(method); err != nil {
		t.Fatalf("SetSignatureMethod(%s): %v", method, err)
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatalf("SignEnveloped: %v", err)
	}
	if p1363 {
		ec, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("p1363 requires ECDSA signer, got %T", signer.Public())
		}
		keySize := (ec.Curve.Params().BitSize + 7) / 8
		sv := signed.SelectElement("Signature").FindElement(".//SignatureValue")
		der, err := base64.StdEncoding.DecodeString(sv.Text())
		if err != nil {
			t.Fatalf("base64.DecodeString(SignatureValue): %v", err)
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &rs); err != nil {
			t.Fatalf("asn1.Unmarshal(SignatureValue): %v", err)
		}
		out := make([]byte, 2*keySize)
		rs.R.FillBytes(out[:keySize])
		rs.S.FillBytes(out[keySize:])
		sv.SetText(base64.StdEncoding.EncodeToString(out))
	}
	// Round-trip through bytes, as RIMs arrive.
	out := etree.NewDocument()
	out.SetRoot(signed)
	b, err := out.WriteToBytes()
	if err != nil {
		t.Fatalf("WriteToBytes: %v", err)
	}
	d := etree.NewDocument()
	if err := d.ReadFromBytes(b); err != nil {
		t.Fatalf("ReadFromBytes: %v", err)
	}
	return d.Root()
}

func assertSignedSWID(t *testing.T, got *etree.Element) {
	t.Helper()
	if got == nil {
		t.Fatal("validateXMLSignature() returned nil element, want SoftwareIdentity")
	}
	if got.Tag != "SoftwareIdentity" {
		t.Errorf("returned root tag = %q, want %q", got.Tag, "SoftwareIdentity")
	}
	if name := got.SelectAttrValue("name", ""); name != "GH100" {
		t.Errorf("returned name attribute = %q, want %q", name, "GH100")
	}
	if got.FindElement(".//Payload") == nil {
		t.Error("returned element missing Payload child")
	}
	if sig := got.FindElement(".//Signature"); sig != nil {
		t.Errorf("returned element still contains Signature element: %v", sig)
	}
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

	t.Run("p1363_r_s", func(t *testing.T) {
		got, err := validateXMLSignature(el, root.cert, compatNow)
		if err != nil {
			t.Fatalf("validateXMLSignature(r||s ECDSA) = %v, want nil", err)
		}
		assertSignedSWID(t, got)
	})

	t.Run("asn1_der", func(t *testing.T) {
		// DER-encoded signatures keep working (fork fell back to the raw bytes).
		der := signCompat(t, root.key, []*x509.Certificate{root.cert}, false)
		got, err := validateXMLSignature(der, root.cert, compatNow)
		if err != nil {
			t.Fatalf("validateXMLSignature(DER ECDSA) = %v, want nil", err)
		}
		assertSignedSWID(t, got)
	})

	t.Run("input_not_mutated", func(t *testing.T) {
		before := elString(t, el)
		if _, err := validateXMLSignature(el, root.cert, compatNow); err != nil {
			t.Fatalf("validateXMLSignature() = %v, want nil", err)
		}
		if diff := cmp.Diff(before, elString(t, el)); diff != "" {
			t.Errorf("validateXMLSignature modified its input (-want +got):\n%s", diff)
		}
	})
}

// TestXMLSignatureCompat_CertificateChain isolates gap 2: the signature
// value is DER (so upstream's ECDSA handling is not involved) and the
// signing certificate chains to the root through an intermediate.
func TestXMLSignatureCompat_CertificateChain(t *testing.T) {
	root := newCompatCert(t, "root", true, nil, nil)
	intermediate := newCompatCert(t, "intermediate", true, root, nil)
	leaf := newCompatCert(t, "leaf", false, intermediate, nil)
	foreignRoot := newCompatCert(t, "foreign root", true, nil, nil)
	expired := newCompatCert(t, "expired leaf", false, intermediate, func(c *x509.Certificate) {
		c.NotAfter = compatNow.Add(-time.Hour)
	})

	p256Root := newCompatCertWithCurve(t, "p256-root", elliptic.P256(), true, nil, nil)
	p256Intermediate := newCompatCertWithCurve(t, "p256-intermediate", elliptic.P256(), true, p256Root, nil)
	p384Leaf := newCompatCertWithCurve(t, "p384-leaf", elliptic.P384(), false, p256Intermediate, nil)

	good := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, false)
	if err := plainUpstream(good, root.cert, compatNow); err == nil {
		t.Log("note: plain upstream goxmldsig now verifies certificate chains (upstream #192 merged?)")
	} else {
		t.Logf("plain upstream goxmldsig: %v", err)
	}

	tamperedPayload := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true)
	tamperedPayload.FindElement(".//Payload").CreateAttr("tampered", "1")

	tests := []struct {
		name    string
		el      *etree.Element
		root    *x509.Certificate
		wantErr string
	}{
		{
			name: "leaf_and_intermediate",
			el:   good,
			root: root.cert,
		},
		{
			name: "leaf_intermediate_and_root",
			el:   signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert, root.cert}, true),
			root: root.cert,
		},
		{
			name: "p1363_with_chain",
			el:   signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true),
			root: root.cert,
		},
		{
			name: "mixed_curve_p256_root_p384_leaf",
			el:   signCompat(t, p384Leaf.key, []*x509.Certificate{p384Leaf.cert, p256Intermediate.cert}, true),
			root: p256Root.cert,
		},
		{
			name:    "tampered_payload_digest_mismatch",
			el:      tamperedPayload,
			root:    root.cert,
			wantErr: "Signature could not be verified",
		},
		{
			name:    "missing_intermediate",
			el:      signCompat(t, leaf.key, []*x509.Certificate{leaf.cert}, false),
			root:    root.cert,
			wantErr: "could not verify certificate against trusted certs: x509: certificate signed by unknown authority",
		},
		{
			name:    "foreign_root",
			el:      good,
			root:    foreignRoot.cert,
			wantErr: "could not verify certificate against trusted certs: x509: certificate signed by unknown authority",
		},
		{
			name:    "expired_leaf",
			el:      signCompat(t, expired.key, []*x509.Certificate{expired.cert, intermediate.cert}, false),
			root:    root.cert,
			wantErr: "could not verify certificate against trusted certs: x509: certificate has expired or is not yet valid",
		},
		{
			name:    "wrong_signer_for_leaf",
			el:      signCompat(t, intermediate.key, []*x509.Certificate{leaf.cert, intermediate.cert}, false),
			root:    root.cert,
			wantErr: "x509: ECDSA verification failure",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateXMLSignature(tc.el, tc.root, compatNow)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateXMLSignature() = %v, want nil", err)
				}
				assertSignedSWID(t, got)
				return
			}
			if err == nil || !strings.HasPrefix(err.Error(), tc.wantErr) {
				t.Fatalf("validateXMLSignature() = %v, want prefix %q", err, tc.wantErr)
			}
		})
	}
}

func TestXMLSignatureCompat_ErrorPaths(t *testing.T) {
	root := newCompatCert(t, "root", true, nil, nil)
	intermediate := newCompatCert(t, "intermediate", true, root, nil)
	leaf := newCompatCert(t, "leaf", false, intermediate, nil)
	foreignRoot := newCompatCert(t, "foreign-root", true, nil, nil)

	noKeyInfo := signCompat(t, root.key, []*x509.Certificate{root.cert}, true)
	ki := noKeyInfo.FindElement(".//KeyInfo")
	ki.Parent().RemoveChild(ki)

	emptyX509Data := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true)
	xd := emptyX509Data.FindElement(".//X509Data")
	for _, c := range xd.ChildElements() {
		xd.RemoveChild(c)
	}

	badBase64Leaf := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true)
	badBase64Leaf.FindElements(".//X509Certificate")[0].SetText("!!!not-base64!!!")

	badDERLeaf := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true)
	badDERLeaf.FindElements(".//X509Certificate")[0].SetText(base64.StdEncoding.EncodeToString([]byte("not-der")))

	badBase64Intermediate := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true)
	badBase64Intermediate.FindElements(".//X509Certificate")[1].SetText("!!!not-base64!!!")

	badDERIntermediate := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true)
	badDERIntermediate.FindElements(".//X509Certificate")[1].SetText(base64.StdEncoding.EncodeToString([]byte("not-der")))

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rsaSerial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("rand.Int(rsa-leaf): %v", err)
	}
	rsaTmpl := &x509.Certificate{
		SerialNumber:          rsaSerial,
		Subject:               pkix.Name{CommonName: "rsa-leaf"},
		NotBefore:             compatNow.Add(-24 * time.Hour),
		NotAfter:              compatNow.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	rsaDER, err := x509.CreateCertificate(rand.Reader, rsaTmpl, intermediate.cert, rsaKey.Public(), intermediate.key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(rsa-leaf): %v", err)
	}
	ecdsaMethodRSALeaf := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true)
	ecdsaMethodRSALeaf.FindElements(".//X509Certificate")[0].SetText(base64.StdEncoding.EncodeToString(rsaDER))

	// Build a document with an #id-referenced signature on the root plus an
	// earlier decoy signature (referencing #payload-1) from a foreign cert.
	idDoc := etree.NewDocument()
	if err := idDoc.ReadFromString(compatSWID); err != nil {
		t.Fatalf("ReadFromString(compatSWID): %v", err)
	}
	idDoc.Root().CreateAttr("ID", "rim-1")
	payloadEl := idDoc.Root().FindElement(".//Payload")
	payloadEl.CreateAttr("ID", "payload-1")
	decoyCtx, err := dsig.NewSigningContext(foreignRoot.key, [][]byte{foreignRoot.cert.Raw})
	if err != nil {
		t.Fatalf("dsig.NewSigningContext(decoy): %v", err)
	}
	decoyCtx.Canonicalizer = dsig.MakeC14N11Canonicalizer()
	decoyCtx.Prefix = "ds"
	if err := decoyCtx.SetSignatureMethod(dsig.ECDSASHA384SignatureMethod); err != nil {
		t.Fatalf("SetSignatureMethod(decoy): %v", err)
	}
	decoySig, err := decoyCtx.ConstructSignature(payloadEl, true)
	if err != nil {
		t.Fatalf("ConstructSignature(decoy): %v", err)
	}
	payloadEl.AddChild(decoySig)
	idRefWithDecoy := signCompatElement(t, idDoc.Root(), leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true)

	commentSplit := signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true)
	sv := commentSplit.FindElement(".//SignatureValue")
	svText := sv.Text()
	sv.SetText("")
	sv.AddChild(etree.NewText(svText[:20]))
	sv.AddChild(etree.NewComment("split"))
	sv.AddChild(etree.NewText(svText[20:]))

	tests := []struct {
		name     string
		el       *etree.Element
		now      time.Time
		wantErr  string
		hasDecoy bool
	}{
		{
			name: "no_keyinfo_valid_root",
			el:   noKeyInfo,
			now:  compatNow,
		},
		{
			name:    "no_keyinfo_expired_root",
			el:      noKeyInfo,
			now:     compatNow.Add(400 * 24 * time.Hour),
			wantErr: "cert is not valid at this time",
		},
		{
			name:    "no_keyinfo_not_yet_valid_root",
			el:      noKeyInfo,
			now:     compatNow.Add(-48 * time.Hour),
			wantErr: "cert is not valid at this time",
		},
		{
			name:    "empty_x509data",
			el:      emptyX509Data,
			now:     compatNow,
			wantErr: "missing X509Certificate within KeyInfo",
		},
		{
			name:    "bad_base64_leaf",
			el:      badBase64Leaf,
			now:     compatNow,
			wantErr: "illegal base64 data at input byte 0",
		},
		{
			name:    "bad_der_leaf",
			el:      badDERLeaf,
			now:     compatNow,
			wantErr: "x509: malformed certificate",
		},
		{
			name:    "bad_base64_intermediate",
			el:      badBase64Intermediate,
			now:     compatNow,
			wantErr: "failed to parse intermediate certificate: illegal base64 data at input byte 0",
		},
		{
			name:    "bad_der_intermediate",
			el:      badDERIntermediate,
			now:     compatNow,
			wantErr: "failed to parse intermediate certificate object: x509: malformed certificate",
		},
		{
			name:    "ecdsa_method_with_rsa_leaf",
			el:      ecdsaMethodRSALeaf,
			now:     compatNow,
			wantErr: "x509: signature algorithm specifies an ECDSA public key, but have public key of type *rsa.PublicKey",
		},
		{
			name:     "id_referenced_with_decoy_signature",
			el:       idRefWithDecoy,
			now:      compatNow,
			hasDecoy: true,
		},
		{
			name: "signature_value_split_by_comment",
			el:   commentSplit,
			now:  compatNow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateXMLSignature(tc.el, root.cert, tc.now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateXMLSignature() = %v, want nil", err)
				}
				if tc.hasDecoy {
					if got == nil || got.Tag != "SoftwareIdentity" || got.SelectAttrValue("ID", "") != "rim-1" {
						t.Errorf("returned element = %v, want SoftwareIdentity with ID=rim-1", got)
					}
					if sig := got.SelectElement("Signature"); sig != nil {
						t.Errorf("returned root still contains outer Signature: %v", sig)
					}
				} else {
					assertSignedSWID(t, got)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("validateXMLSignature() = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestXMLSignatureCompat_ZeroNow(t *testing.T) {
	realNow := time.Now()
	validNow := func(c *x509.Certificate) {
		c.NotBefore = realNow.Add(-24 * time.Hour)
		c.NotAfter = realNow.Add(24 * time.Hour)
	}
	root := newCompatCert(t, "root", true, nil, validNow)
	intermediate := newCompatCert(t, "intermediate", true, root, validNow)
	leaf := newCompatCert(t, "leaf", false, intermediate, validNow)
	expiredLeaf := newCompatCert(t, "expired-leaf", false, intermediate, func(c *x509.Certificate) {
		c.NotBefore = realNow.Add(-48 * time.Hour)
		c.NotAfter = realNow.Add(-24 * time.Hour)
	})

	noKeyInfo := signCompat(t, root.key, []*x509.Certificate{root.cert}, true)
	if ki := noKeyInfo.FindElement(".//KeyInfo"); ki != nil {
		ki.Parent().RemoveChild(ki)
	}

	tests := []struct {
		name          string
		el            *etree.Element
		wantErr       string
		wantErrPrefix string
	}{
		{
			name: "keyinfo_chain",
			el:   signCompat(t, leaf.key, []*x509.Certificate{leaf.cert, intermediate.cert}, true),
		},
		{
			name: "keyinfo_root_signed",
			el:   signCompat(t, root.key, []*x509.Certificate{root.cert}, true),
		},
		{
			name:          "keyinfo_expired",
			el:            signCompat(t, expiredLeaf.key, []*x509.Certificate{expiredLeaf.cert, intermediate.cert}, true),
			wantErrPrefix: "could not verify certificate against trusted certs: x509: certificate has expired or is not yet valid",
		},
		{
			name:    "no_keyinfo",
			el:      noKeyInfo,
			wantErr: "cert is not valid at this time",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateXMLSignature(tc.el, root.cert, time.Time{})
			switch {
			case tc.wantErr != "":
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("validateXMLSignature(zero now) = %v, want %q", err, tc.wantErr)
				}
			case tc.wantErrPrefix != "":
				if err == nil || !strings.HasPrefix(err.Error(), tc.wantErrPrefix) {
					t.Fatalf("validateXMLSignature(zero now) = %v, want prefix %q", err, tc.wantErrPrefix)
				}
			default:
				if err != nil {
					t.Fatalf("validateXMLSignature(zero now) = %v, want nil", err)
				}
				assertSignedSWID(t, got)
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
		t.Fatalf("WriteToString: %v", err)
	}
	return s
}
