package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
