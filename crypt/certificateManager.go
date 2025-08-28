package crypt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"

	"google.golang.org/protobuf/proto"

	"github.com/Despance/secure-messenger/message"
)

type CertificateManager struct {
	privKey         *rsa.PrivateKey
	MyCertificate   *x509.Certificate
	PairCertificate *x509.Certificate
	CertPool        **x509.CertPool
}

func NewCertificateManager(pkey *rsa.PrivateKey) CertificateManager {
	return CertificateManager{
		privKey: pkey,
	}
}

func (certManager *CertificateManager) GetCertificate(caAdress string) error {
	caConn, err := net.Dial("tcp", caAdress)
	if err != nil {
		return err
	}

	certRequest := GetCertificateRequestBytes("Pair", certManager.privKey)

	_, err = caConn.Write(certRequest)
	if err != nil {
		return err
	}

	allBytes, err := io.ReadAll(caConn)
	if err != nil {
		return err
	}

	certManager.MyCertificate, err = ParseCertificate(&allBytes)
	if err != nil {
		return err
	}

	caCert, err := ParseCertificate(&allBytes)
	if err != nil {
		return err
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	certManager.CertPool = &certPool

	opts := x509.VerifyOptions{
		Roots: *certManager.CertPool,
	}

	_, err = certManager.MyCertificate.Verify(opts)
	if err != nil {
		return err
	}

	fmt.Println("Certificate is valid and trusted")
	return nil
}

func (certManager *CertificateManager) ExchangeCertificates(conn net.Conn) {
	pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certManager.MyCertificate.Raw})

	length := make([]byte, 4)

	certMsg := &message.CertificateMsg{
		Length: uint32(len(pem)),
		Cert:   pem,
	}

	env := &message.Envelope{
		Type:      message.Envelope_CERTIFICATE,
		Sequence:  1,
		Timestamp: 3,
		Payload:   &message.Envelope_Cert{Cert: certMsg},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		fmt.Println(err)
	}

	binary.BigEndian.PutUint32(length, uint32(len(data)))
	if _, err := conn.Write(length); err != nil {
		fmt.Println(err)
	}
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("Error on writing", err)
	}

	if _, err := io.ReadFull(conn, length); err != nil {
		fmt.Println(err)
	}

	intlen := binary.BigEndian.Uint32(length)

	readBytes := make([]byte, intlen)
	n, err := io.ReadFull(conn, readBytes)
	if err != nil {
		fmt.Println("error on parse certificate", err)
		return
	}

	msg := readBytes[:n]

	newEnv := &message.Envelope{}

	if err = proto.Unmarshal(msg, newEnv); err != nil {
		fmt.Println("error on unmarshal", err)

		return
	}

	if newEnv.Type != message.Envelope_CERTIFICATE {
		fmt.Println("not a proto certificate")
		return
	}

	msg = newEnv.GetCert().GetCert()
	cert, err := ParseCertificate(&msg)
	if err != nil {
		fmt.Println("err on parse", err)
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: *certManager.CertPool,
	})
	if err != nil {
		fmt.Println("not valid cert", err)
		return
	}

	certManager.PairCertificate = cert
	fmt.Println("Certificate exchange is valid")
}
