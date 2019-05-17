// {{{ Copyright (c) Doowon Kim <gotapenny@gmail.com>, 2019
// Parsing a PKCS7 SignedData in the code signing PKI (authenticode)
// This project focuses on only the code signing PKI so that only signedData is handled.
// This project is inspired by referenced from two projects 1) https://github.com/fullsailor/pkcs7 and 2) https://github.com/paultag/go-pkcs7
// Currently it supports only extracting information from pcks7 signeddata.

package mypkcs7

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

var (
	//OIDSignedData is signedData OIDs
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	//OIDContentType is one of Attributes
	OIDContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	//OIDSigningTime is one of Attributes
	OIDSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	//OIDMessageDigest is one of Attributes
	OIDMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	//OIDPKCS7 is PKCS#7
	OIDPKCS7 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	//OIDSpcStatementTypeObjID 1.3.6.1.4.1.311.2.1.11
	OIDSpcStatementTypeObjID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	//OIDSpcSPOpusInfoObjID 1.3.6.1.4.1.311.2.1.12
	OIDSpcSPOpusInfoObjID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
)

// PKCS7 has SignData and signature information (signerInfo)
// Because Authenticode signatures support only one signer,
// digestAlgorithms must contain only one digestAlgorithmIdentifier structure
// and the structure must match the value set in the SignerInfo structure's digestAlgorithm field.
// If not, the signature has been tampered with.
type PKCS7 struct {
	Raw                        interface{}
	ContentType                asn1.ObjectIdentifier      // should be signedData
	Version                    int                        // signedData version
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier // used to sign the contents of the ContentInfo type
	Certificates               []*x509.Certificate        // list of x509 certs
	CRLs                       []pkix.CertificateList     // CRLs
	SignerInfos                []signerInfo               // list of signature information
}

type signerInfo struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerialNumber
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttribute    authenticatedAttribute
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttribute  unauthenticatedAttribute
}

type unauthenticatedAttribute struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerialNumber
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttribute    authenticatedAttribute
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	MessageDigest             []byte
}

type authenticatedAttribute struct {
	ContentType   asn1.ObjectIdentifier
	MessageDigest []byte
	SigningTime   time.Time //this is only for unauthenticatedAttribute
}

// The issuer name and serial number of the signing certificate, as defined by ”PKCS #7: Cryptographic Message Syntax Standard
type issuerAndSerialNumber struct {
	IssuerName   pkix.RDNSequence
	SerialNumber *big.Int
}

// ParsePKCS7 decodes a DER encoded PKCS7 package
// It returns a PKCS#7
func ParsePKCS7(asn1Data []byte) (*PKCS7, error) {
	if len(asn1Data) == 0 {
		return nil, errors.New("pkcs7 DER input data is empty")
	}

	var cInfo asn1ContentInfo
	rest, err := asn1.Unmarshal(asn1Data, &cInfo)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		// fmt.Println(string(rest))
		// 	return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	switch {
	case cInfo.ContentType.Equal(OIDSignedData):
		return parseSignedData(cInfo.Content.Bytes)
	}

	return nil, errors.New("supporting only a signedData format DER input now; other types are not supported yet")
}

// parseSignedData parses a PKCS7 signedData DER
// It returns a PKCS7
func parseSignedData(buf []byte) (*PKCS7, error) {
	var pkcs7 PKCS7

	var signedData asn1SignedData
	rest, err := asn1.Unmarshal(buf, &signedData)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing der bytes in the message"}
	}

	//x.509 certificates
	certs, err := signedData.Certificates.Parse()
	if err != nil {
		return nil, err
	}
	pkcs7.Certificates = certs

	//CRLs & contentType
	pkcs7.Version = signedData.Version
	pkcs7.CRLs = signedData.CRLs
	pkcs7.ContentType = signedData.ContentInfo.ContentType

	//DigestAlgorithmIdentifiers
	for _, algo := range signedData.DigestAlgorithmIdentifiers {
		pkcs7.DigestAlgorithmIdentifiers = append(pkcs7.DigestAlgorithmIdentifiers, algo)
	}

	//Signature information (signerinfo)
	for _, s := range signedData.SignerInfos {
		var signerInfo signerInfo
		signerInfo.Version = s.Version
		signerInfo.DigestAlgorithm = s.DigestAlgorithm
		signerInfo.DigestEncryptionAlgorithm = s.DigestEncryptionAlgorithm
		signerInfo.EncryptedDigest = s.EncryptedDigest
		signerInfo.IssuerAndSerialNumber = s.IssuerAndSerialNumber

		// authenticatedAttribute
		var authenticatedAttr authenticatedAttribute
		for _, attr := range s.AuthenticatedAttributes {
			if attr.Type.Equal(OIDContentType) { //ContentType
				var oid asn1.ObjectIdentifier
				rest, err := asn1.Unmarshal(attr.Value.Bytes, &oid)
				if err != nil {
					return nil, err
				}
				if len(rest) > 0 {
					return nil, asn1.SyntaxError{Msg: "trailing der bytes in the message"}
				}
				authenticatedAttr.ContentType = oid

			} else if attr.Type.Equal(OIDMessageDigest) {
				var msg []byte
				rest, err := asn1.Unmarshal(attr.Value.Bytes, &msg)
				if err != nil {
					return nil, err
				}
				if len(rest) > 0 {
					return nil, asn1.SyntaxError{Msg: "trailing der bytes in the message"}
				}
				authenticatedAttr.MessageDigest = msg

			} else if attr.Type.Equal(OIDSpcSPOpusInfoObjID) {
				//TODO: Implement to handle this OID
				// fmt.Println(attr)
				continue
			} else if attr.Type.Equal(OIDSpcStatementTypeObjID) {
				//TODO: Implement to handle this OID
				// fmt.Println(attr)
				continue
			} else if attr.Type.Equal(OIDSigningTime) {
				// this violates the authenticode specification
				// signingTime should be specified at unauthenticatedAttributes
				// but some old pkcs7 has this signing time in authenticatedAttributes
				var t time.Time
				rest, err = asn1.Unmarshal(attr.Value.Bytes, &t)
				if err != nil {
					return nil, err
				}
				if len(rest) > 0 {
					return nil, asn1.SyntaxError{Msg: "trailing der bytes in the message"}
				}
				authenticatedAttr.SigningTime = t
			}
		}
		signerInfo.AuthenticatedAttribute = authenticatedAttr

		// Handles unauthenticated Attributes
		// Note: a few of pkcs7 have two unauthenticated attributes
		// because some publishers put their additional information into
		// the second unauthenticated attribute.
		// Otherwise, mostly pkcs7 has one unauthenticated attribute and
		// the single attribute has the information about signing time, etc.
		if len(s.UnauthenticatedAttributes) > 0 {
			attr := s.UnauthenticatedAttributes[0]
			var unAuthenticatedAttr unauthenticatedAttribute
			var unAuthAttr asn1UnauthenticatedAttribute
			rest, err := asn1.Unmarshal(attr.Value.Bytes, &unAuthAttr)
			if err != nil {
				return nil, err
			}
			if len(rest) > 0 {
				return nil, asn1.SyntaxError{Msg: "trailing data"}
			}

			unAuthenticatedAttr.Version = unAuthAttr.Version
			unAuthenticatedAttr.MessageDigest = unAuthAttr.MessageDigest
			unAuthenticatedAttr.IssuerAndSerialNumber = unAuthAttr.IssuerAndSerialNumber
			unAuthenticatedAttr.DigestEncryptionAlgorithm = unAuthAttr.DigestEncryptionAlgorithm
			unAuthenticatedAttr.DigestAlgorithm = unAuthAttr.DigestAlgorithm

			//authenticatedAttributes in unauthenticatedAttributes
			//this attribute contains encrypted digest, signing time, contentype
			buf := unAuthAttr.AuthenticatedAttributes.Bytes
			for {
				var at asn1Attribute
				totalRest, err := asn1.Unmarshal(buf, &at)
				if err != nil {
					return nil, err
				}
				if at.Type.Equal(OIDContentType) {
					var oid asn1.ObjectIdentifier
					rest, err = asn1.Unmarshal(at.Value.Bytes, &oid)
					if err != nil {
						return nil, err
					}
					if len(rest) > 0 {
						return nil, asn1.SyntaxError{Msg: "trailing der bytes in the message"}
					}
					// fmt.Printf("%s %s\n", at.Type, oid)
					unAuthenticatedAttr.AuthenticatedAttribute.ContentType = oid
				} else if at.Type.Equal(OIDSigningTime) {
					var t time.Time
					rest, err = asn1.Unmarshal(at.Value.Bytes, &t)
					if err != nil {
						return nil, err
					}
					if len(rest) > 0 {
						return nil, asn1.SyntaxError{Msg: "trailing der bytes in the message"}
					}
					// fmt.Printf("%s %s\n", at.Type, t)
					unAuthenticatedAttr.AuthenticatedAttribute.SigningTime = t
				} else if at.Type.Equal(OIDMessageDigest) {
					var msg []byte
					rest, err = asn1.Unmarshal(at.Value.Bytes, &msg)
					if err != nil {
						return nil, err
					}
					if len(rest) > 0 {
						return nil, asn1.SyntaxError{Msg: "trailing der bytes in the message"}
					}
					// fmt.Printf("%s %X\n", at.Type, msg)
					unAuthenticatedAttr.AuthenticatedAttribute.MessageDigest = msg

				}
				if len(totalRest) <= 0 {
					break
				}
				buf = totalRest
			}
			signerInfo.UnauthenticatedAttribute = unAuthenticatedAttr
		}
		pkcs7.SignerInfos = append(pkcs7.SignerInfos, signerInfo)
	}

	return &pkcs7, nil
}

//Parse parses the list of the certificates bytes in raw
func (raw asn1RawCertificates) Parse() ([]*x509.Certificate, error) {
	if len(raw.RawCerts) == 0 {
		return nil, errors.New("rawCertificates is empty")
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.RawCerts, &val); err != nil {
		return nil, err
	}

	return x509.ParseCertificates(val.Bytes)
}
