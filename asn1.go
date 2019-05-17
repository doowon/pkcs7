package mypkcs7

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// attribute is for attribute in asn.1
type asn1Attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// ContentInfo contains contain and the type of the content.
type asn1ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0`
}

// signerInfo is defined by the PKCS #7 v1.5 specification
type asn1SignerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerialNumber
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []asn1Attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []asn1Attribute `asn1:"optional,tag:1"`
}

// asn1SignedData represents a SignedData in PKCS7 and
// needs to be parsed into signedData.
type asn1SignedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                asn1ContentInfo            // This field contains two fields: contentType and content
	Certificates               asn1RawCertificates        `asn1:"optional,tag:0"` // bytes of raw certificates
	CRLs                       []pkix.CertificateList     `asn1:"optional,tag:1"` // CRLs
	SignerInfos                []asn1SignerInfo           `asn1:"set"`            // signer information
}

// unauthenticatedAttribute is for unauthenticated attributes in the signer info structure
type asn1UnauthenticatedAttribute struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerialNumber
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	MessageDigest             []byte
}

// bytes of x509 certificates in raw
type asn1RawCertificates struct {
	RawCerts asn1.RawContent
}
