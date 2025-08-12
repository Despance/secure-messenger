package certauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

type CertificateAuthority struct {
	listenAddr string
	listener   net.Listener
	quit       chan struct{}
	ca         *x509.Certificate
	caPrivKey  *rsa.PrivateKey
	caBytes    []byte
}

func NewCertificateAuthority(listenAddr string) *CertificateAuthority {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Despance"},
			Country:      []string{"TR"},
			Province:     []string{"Bursa"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {

		fmt.Println("error on ca creation", err)
		return nil
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {

		fmt.Println("error on ca byte conversion", err)
		return nil
	}

	return &CertificateAuthority{
		listenAddr: listenAddr,
		quit:       make(chan struct{}),
		ca:         ca,
		caPrivKey:  caKey,
		caBytes:    caBytes,
	}
}

func (ca *CertificateAuthority) Start() error {
	listener, err := net.Listen("tcp", ca.listenAddr)
	if err != nil {
		fmt.Println("Start error", err)
		return err
	}
	defer listener.Close()
	ca.listener = listener

	go ca.Accept()

	<-ca.quit
	return nil
}

func (ca *CertificateAuthority) Accept() {
	for {
		conn, err := ca.listener.Accept()
		if err != nil {
			fmt.Println("Accept error", err)
			continue
		}
		fmt.Println("Connection accepted", conn.LocalAddr())

		go ca.Listen(conn)

	}
}

func (ca *CertificateAuthority) Listen(conn net.Conn) {
	buf := make([]byte, 2048)
	for {
		msgSize, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Println("Client disconnected")
			} else {
				fmt.Println("Listening error", err)
			}
			return
		}

		msg := buf[:msgSize]
		fmt.Println(string(msg))

		block, _ := pem.Decode(msg)

		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			fmt.Println("unknown pem block", block.Type)
			continue
		}

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			fmt.Println("error on parse certificate request")
			continue
		}

		if err := csr.CheckSignature(); err != nil {
			fmt.Println("CSR signature invalid:", err)
			continue
		}

		certTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               csr.Subject,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, ca.ca, csr.PublicKey, ca.caPrivKey)
		if err != nil {
			fmt.Println("Cert creation error:", err)
			continue
		}

		fmt.Println("Created certificate: ", certTemplate)

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		conn.Write(certPEM)
		fmt.Println("Certificate issued to: ", csr.Subject.CommonName)

	}
}
