package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/Despance/secure-messenger/crypt"
)

type Client struct {
	serverAddress string
	connection    net.Conn
	quit          chan struct{}
	privKey       *rsa.PrivateKey
}

func NewClient(serverAddress string) *Client {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	return &Client{
		serverAddress: serverAddress,
		quit:          make(chan struct{}),
		privKey:       privKey,
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
		fmt.Printf("hello")

		fmt.Println(string(value))

		cert, _ := parseCertificate(value)

		fmt.Println("Public Key:", cert.PublicKey)

		fmt.Println("Original Public Key:", client.privKey.PublicKey)
	}
}

func parseCertificate(certBytes []byte) (*x509.Certificate, error) {
	certPem, a := pem.Decode(certBytes)

	if certPem == nil {
		fmt.Println("error cert", string(a))
		return nil, errors.New("cant decode")
	}

	if certPem.Type != "CERTIFICATE" {
		fmt.Println("not a certificate", certPem.Bytes)
		return nil, errors.New("Not a certificate")
	}

	certificate, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, errors.New("Cant parse certificate")
	}

	fmt.Println("Parse done")
	return certificate, nil
}

func (client *Client) Write(str string) {
	n, err := client.connection.Write([]byte(str))
	if err != nil {
		fmt.Println("Error on writing n bytes:", n, " err:", err)
	}
}

func main() {
	client := NewClient(":3030")

	err := client.Connect()
	if err != nil {
		fmt.Println("error on connection", err)
	}

	// client.Write("Hello server, i am client")
	go client.Read()

	certRequest := crypt.GetCertificateRequestBytes("Client", client.privKey)

	client.Write(string(certRequest))

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {

		message := scanner.Text()

		client.Write(message)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error on reading: ", err)
	}
}
