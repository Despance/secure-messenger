package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
)

func GetCertificateRequestBytes(name string, privateKey crypto.PrivateKey) []byte {
	cert := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{name},
		},
	}

	certBytes, err := x509.CreateCertificateRequest(rand.Reader, cert, privateKey)
	if err != nil {
		panic(err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certBytes})

	return csrPEM
}

func ParseCertificate(certBytes *[]byte) (*x509.Certificate, error) {
	certPem, a := pem.Decode(*certBytes)

	if certPem == nil {
		fmt.Println("error cert", string(a))
		return nil, errors.New("cant decode")
	}

	if certPem.Type != "CERTIFICATE" {
		fmt.Println("not a certificate", string(certPem.Bytes))
		return nil, errors.New("not a certificate")
	}

	certificate, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, errors.New("cant parse certificate")
	}

	*certBytes = a
	return certificate, nil
}
