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

// This file lets the unmodified upstream github.com/russellhaering/goxmldsig
// verify NVIDIA RIM signatures. Upstream has two gaps that NVIDIA RIMs hit:
//
//  1. ECDSA SignatureValue. XML-DSig (RFC 4050 / RFC 6931) encodes an ECDSA
//     signature as r||s (IEEE P1363). Upstream passes the decoded bytes
//     straight to x509.Certificate.CheckSignature, which wants ASN.1 DER, so
//     every ecdsa-sha384 RIM fails. Upstream issue #163, PR #164.
//  2. Certificate chains. Upstream only accepts a signing certificate that is
//     itself one of the trusted roots. RIMs carry leaf + intermediates in
//     KeyInfo/X509Data and chain to the NVIDIA RIM root. PR #192.
//
// Both gaps are closed here from the outside, through the exported API:
//
//   - Before calling Validate, the SignatureValue of the signature that
//     Validate will use is rewritten from r||s to DER (on a private copy).
//     SignatureValue is outside SignedInfo, so this does not touch what is
//     signed or digested.
//   - Validate asks its X509CertificateStore for the trusted roots right after
//     it has found the signature and right before it checks the certificate.
//     chainVerifyingStore does the chain check at exactly that point, so the
//     order of errors is unchanged, and hands back the verified leaf as the
//     only "root", which upstream then accepts.
//
// The result is byte-for-byte the behaviour (results and error strings) of
// goxmldsig v1.6.0 with the fixes previously carried in the fork
// github.com/atulpatildbz/goxmldsig@e806be5. selectSignature and
// verifyKeyInfoChain are adapted from goxmldsig (Apache-2.0,
// Copyright (c) 2016 Russell Haering) and that fork.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

var dsigWhiteSpace = regexp.MustCompile(`\s+`)

// defaultIDAttr is dsig.DefaultIdAttr (spelled DefaultIDAttr in some copies).
const defaultIDAttr = "ID"

// compatSignature holds the parts of goxmldsig's types.Signature that the
// fork's logic reads. Tags and namespaces are copied from types.Signature
// (v1.6.x), so it decodes the same values. It is defined here rather than
// reused so that the code does not depend on how a particular copy of
// goxmldsig declares those types (some patched copies declare X509Data as
// a pointer).
type compatSignature struct {
	XMLName        xml.Name            `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     *compatSignedInfo   `xml:"SignedInfo"`
	SignatureValue *compatSignatureVal `xml:"SignatureValue"`
	KeyInfo        *compatKeyInfo      `xml:"KeyInfo"`
}

type compatSignedInfo struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	SignatureMethod struct {
		XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
		Algorithm string   `xml:"Algorithm,attr"`
	} `xml:"SignatureMethod"`
	References []struct {
		XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
		URI     string   `xml:"URI,attr"`
	} `xml:"Reference"`
}

type compatSignatureVal struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	Data    string   `xml:",chardata"`
}

type compatKeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data struct {
		XMLName          xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
		X509Certificates []struct {
			XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
			Data    string   `xml:",chardata"`
		} `xml:"X509Certificate"`
	} `xml:"X509Data"`
}

// validateXMLSignature validates the enveloped signature of root against
// rootCert at time now. It returns the signed content as returned by
// dsig.ValidationContext.Validate.
func validateXMLSignature(root *etree.Element, rootCert *x509.Certificate, now time.Time) (*etree.Element, error) {
	// Work on a copy: the SignatureValue rewrite must not leak into the
	// caller's tree. Validate makes its own copy of what it is given, so
	// handing it a parentless copy is what it would have done anyway.
	el := root.Copy()

	sig, sigEl := selectSignature(el)
	if sig != nil {
		rewriteECDSASignatureValue(sig, sigEl, rootCert)
		// When KeyInfo is present, crypto/x509 treats a zero CurrentTime as
		// time.Now() during chain verification, whereas upstream's clock check
		// uses year 1. Normalize once so both checks use the same time,
		// matching the fork (which still rejects zero now when KeyInfo is absent).
		if now.IsZero() && sig.KeyInfo != nil {
			now = time.Now()
		}
	}

	ctx := dsig.NewDefaultValidationContext(&chainVerifyingStore{sig: sig, root: rootCert, now: now})
	ctx.Clock = dsig.NewFakeClockAt(now)
	return ctx.Validate(el)
}

// selectSignature finds the signature that dsig.ValidationContext.Validate
// (findSignature) will pick for el: the first xmldsig Signature, in document
// order, with a Reference to el. It returns the parsed signature and its
// element in el. If Validate would fail before picking one, the result does
// not matter and may be nil.
func selectSignature(el *etree.Element) (*compatSignature, *etree.Element) {
	idAttr := el.SelectAttrValue(defaultIDAttr, "")
	var sig *compatSignature
	var sigEl *etree.Element
	_ = etreeutils.NSFindIterate(el, dsig.Namespace, dsig.SignatureTag, func(ctx etreeutils.NSContext, signatureEl *etree.Element) error {
		if !validSignatureShape(signatureEl) {
			return dsig.ErrInvalidSignature
		}
		signedInfo, err := etreeutils.NSFindOneChildCtx(ctx, signatureEl, dsig.Namespace, dsig.SignedInfoTag)
		if err != nil {
			return err
		}
		if signedInfo == nil {
			return errors.New("missing SignedInfo")
		}
		s := &compatSignature{}
		if err := etreeutils.NSUnmarshalElement(ctx, signatureEl, s); err != nil {
			return err
		}
		if s.SignedInfo == nil {
			return errors.New("missing SignedInfo")
		}
		for _, ref := range s.SignedInfo.References {
			if ref.URI == "" || ref.URI[1:] == idAttr {
				sig, sigEl = s, signatureEl
				return etreeutils.ErrTraversalHalted
			}
		}
		return nil
	})
	return sig, sigEl
}

// validSignatureShape mirrors goxmldsig's validateShape.
func validSignatureShape(signatureEl *etree.Element) bool {
	counts := map[string]int{}
	for _, child := range signatureEl.ChildElements() {
		counts[child.Tag]++
	}
	return counts[dsig.SignedInfoTag] == 1 && counts[dsig.KeyInfoTag] <= 1 && counts[dsig.SignatureValueTag] == 1
}

// signingCertificate returns the certificate whose key Validate will check
// the signature with, once the certificate check has passed: the first
// KeyInfo certificate, or the single trusted root when there is no KeyInfo.
func signingCertificate(sig *compatSignature, rootCert *x509.Certificate) *x509.Certificate {
	if sig.KeyInfo == nil {
		return rootCert
	}
	if len(sig.KeyInfo.X509Data.X509Certificates) == 0 {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(dsigWhiteSpace.ReplaceAllString(sig.KeyInfo.X509Data.X509Certificates[0].Data, ""))
	if err != nil {
		return nil
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return c
}

func isECDSASignatureMethod(method string) bool {
	switch method {
	case dsig.ECDSASHA1SignatureMethod, dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod:
		return true
	}
	return false
}

// rewriteECDSASignatureValue converts the SignatureValue of an ECDSA
// signature from r||s to ASN.1 DER, in place, when its length is exactly
// twice the curve size of the signing key. Anything else is left untouched,
// so that Validate fails (or passes) on it exactly as before.
func rewriteECDSASignatureValue(sig *compatSignature, sigEl *etree.Element, rootCert *x509.Certificate) {
	if sig.SignedInfo == nil || sig.SignatureValue == nil || !isECDSASignatureMethod(sig.SignedInfo.SignatureMethod.Algorithm) {
		return
	}
	cert := signingCertificate(sig, rootCert)
	if cert == nil {
		return
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(sig.SignatureValue.Data)
	if err != nil {
		return
	}
	keySize := (pub.Curve.Params().BitSize + 7) / 8
	if len(raw) != 2*keySize {
		return
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(raw[:keySize]),
		new(big.Int).SetBytes(raw[keySize:]),
	})
	if err != nil {
		return
	}
	var valueEl *etree.Element
	for _, child := range sigEl.ChildElements() {
		if child.Tag == dsig.SignatureValueTag {
			valueEl = child
		}
	}
	if valueEl == nil {
		return
	}
	// Replace all character data (what encoding/xml's ",chardata" collects)
	// with the DER encoding. Comments and child elements are kept.
	var text []etree.Token
	for _, t := range valueEl.Child {
		if _, ok := t.(*etree.CharData); ok {
			text = append(text, t)
		}
	}
	for _, t := range text {
		valueEl.RemoveChild(t)
	}
	valueEl.SetText(base64.StdEncoding.EncodeToString(der))
}

// chainVerifyingStore is the X509CertificateStore given to Validate. Validate
// calls Certificates after it has found the signature and before it checks
// the signing certificate; this is where the chain is verified.
type chainVerifyingStore struct {
	sig  *compatSignature
	root *x509.Certificate
	now  time.Time
}

// Certificates implements dsig.X509CertificateStore.
func (s *chainVerifyingStore) Certificates() ([]*x509.Certificate, error) {
	if s.sig == nil {
		// Unreachable: Validate only gets here after finding the same
		// signature that selectSignature found.
		return nil, errors.New("rim: xmldsig signature not found")
	}
	c, err := verifyKeyInfoChain(s.sig, s.root, s.now)
	if err != nil {
		return nil, err
	}
	// Upstream accepts a signing certificate that equals a trusted root and
	// is valid at now; c is the verified leaf (or the root itself).
	return []*x509.Certificate{c}, nil
}

// verifyKeyInfoChain checks the signing certificate of sig. It verifies
// the KeyInfo chain (leaf first, then intermediates) up to root at now, with
// crypto/x509 default options, and returns the leaf.
func verifyKeyInfoChain(sig *compatSignature, root *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	if sig.KeyInfo == nil {
		if now.Before(root.NotBefore) || now.After(root.NotAfter) {
			return nil, errors.New("cert is not valid at this time")
		}
		return root, nil
	}
	certs := sig.KeyInfo.X509Data.X509Certificates
	if len(certs) == 0 {
		return nil, errors.New("missing X509Certificate within KeyInfo")
	}
	leafDER, err := base64.StdEncoding.DecodeString(dsigWhiteSpace.ReplaceAllString(certs[0].Data, ""))
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		der, err := base64.StdEncoding.DecodeString(dsigWhiteSpace.ReplaceAllString(c.Data, ""))
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
		}
		ic, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate certificate object: %w", err)
		}
		intermediates.AddCert(ic)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now}); err != nil {
		return nil, fmt.Errorf("could not verify certificate against trusted certs: %w", err)
	}
	return leaf, nil
}
