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
	rsaChannel         crypt.SimpleRSA
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

	keys, err := hkdf.Key(sha256.New, secret, []byte("Muho loves miyabi (gooning) "), "", 64)
	if err != nil {
		fmt.Println("error on hkdf", err)
		return err
	}

	fmt.Println("clientkey:", string(keys[0:31]), "serverkey: ", string(keys[32:63]))

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
		fmt.Println("CipherText:", string(value))

		clearText := client.rsaChannel.Decrypt(value)

		fmt.Println("clearText:", clearText)
	}
}

func (client *Client) Write(str string) {
	cipherText := client.rsaChannel.Encrypt(str)

	n, err := client.connection.Write([]byte(cipherText))
	if err != nil {
		fmt.Println("Error on writing n bytes:", n, " err:", err)
	}
}

func main() {
	client := NewClient(":3131", ":3030")

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
