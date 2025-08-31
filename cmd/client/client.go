package main

import (
	"bufio"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"net"
	"os"

	"github.com/Despance/secure-messenger/crypt"
)

type Client struct {
	serverAddress      string
	caAdress           string
	connection         net.Conn
	quit               chan struct{}
	privKey            *rsa.PrivateKey
	certificateManager crypt.CertificateManager
	rsaChannel         *crypt.SimpleRSA
	aesChannel         *crypt.SimpleAES
}

func NewClient(serverAddress string, caAdress string) *Client {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return &Client{
		serverAddress:      serverAddress,
		quit:               make(chan struct{}),
		privKey:            privKey,
		certificateManager: crypt.NewCertificateManager(privKey),
		caAdress:           caAdress,
	}
}

func (client *Client) Connect() error {
	// Get the certificate from the CA
	err := client.certificateManager.GetCertificate(client.caAdress)
	if err != nil {
		fmt.Println("error on certificate", err)
	}

	conn, err := net.Dial("tcp", client.serverAddress)
	if err != nil {
		return err
	}
	client.connection = conn

	client.certificateManager.ExchangeCertificates(conn)

	// Establish connection with pair and exchange certificates
	pubKey, ok := client.certificateManager.PairCertificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		panic("Error on keytype")
	}

	// Open a rsa channel to communicate - exchange shared secret.
	client.rsaChannel = crypt.NewSimpleRSA(*client.privKey, *pubKey)

	secret := make([]byte, 32)
	rand.Read(secret)

	client.rsaChannel.SendMessage(conn, secret)
	keys, err := hkdf.Key(sha256.New, secret, []byte("this is my go project 17"), "", 64)

	client.aesChannel = crypt.NewSimpleAES(keys[0:32], keys[32:64], conn)

	go client.ReadAES()

	return nil
}

func (client *Client) ReadAES() {
	for {
		fmt.Println(client.aesChannel.ListenAndDecrypt())
	}
}

func main() {
	client := NewClient(":3131", ":3030")

	client.Connect()

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		message := scanner.Text()

		client.aesChannel.EncryptAndSend([]byte(message))
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error on reading: ", err)
	}
}
