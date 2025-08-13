package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Despance/secure-messenger/crypt"
)

type Client struct {
	serverAddress string
	caAdress      string
	connection    net.Conn
	quit          chan struct{}
	privKey       *rsa.PrivateKey
	myCertificate *x509.Certificate
	caPool        *x509.CertPool
}

func NewClient(serverAddress string, caAdress string) *Client {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return &Client{
		serverAddress: serverAddress,
		quit:          make(chan struct{}),
		privKey:       privKey,
		caAdress:      caAdress,
	}
}

func (client *Client) Connect() error {
	conn, err := net.Dial("tcp", client.serverAddress)
	if err != nil {
		return err
	}

	client.connection = conn

	return nil
}

func (client *Client) Read() {
	buf := make([]byte, 8192)

	for {
		n, err := client.connection.Read(buf)
		if err != nil {
			fmt.Println(err)
			continue
		}

		value := buf[:n]
		fmt.Println(string(value))
	}
}

func (client *Client) Write(str string) {
	n, err := client.connection.Write([]byte(str))
	if err != nil {
		fmt.Println("Error on writing n bytes:", n, " err:", err)
	}
}

func main() {
	client := NewClient(":3131", ":3030")

	err := client.getCertificate()
	if err != nil {
		fmt.Println("Error on certificate", err)
	}

	client.Connect()

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {

		message := scanner.Text()
		client.Write(message)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error on reading: ", err)
	}
}

func parseCertificate(certBytes []byte) (*x509.Certificate, error) {
	certPem, a := pem.Decode(certBytes)

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

	certBytes = a
	return certificate, nil
}

func (client *Client) getCertificate() error {
	caConn, err := net.Dial("tcp", client.caAdress)
	if err != nil {
		return err
	}

	certRequest := crypt.GetCertificateRequestBytes("Client", client.privKey)

	_, err = caConn.Write(certRequest)
	if err != nil {
		return err
	}

	allBytes, err := io.ReadAll(caConn)
	if err != nil {
		return err
	}

	client.myCertificate, err = parseCertificate(allBytes)
	if err != nil {
		return err
	}

	caCert, err := parseCertificate(allBytes)
	if err != nil {
		return err
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	client.caPool = certPool

	opts := x509.VerifyOptions{
		Roots: client.caPool,
	}

	_, err = client.myCertificate.Verify(opts)
	if err != nil {
		return err
	}

	fmt.Println("Certificate is valid and trusted")
	return nil
}
