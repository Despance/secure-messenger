package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Despance/secure-messenger/crypt"
)

type Server struct {
	listenAddr         string
	caAdress           string
	privKey            *rsa.PrivateKey
	certificateManager crypt.CertificateManager
	listener           net.Listener
	rsaChannel         crypt.SimpleRSA
	quit               chan struct{}
}

func NewServer(listenAddr string, caAdress string) *Server {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &Server{
		listenAddr:         listenAddr,
		caAdress:           caAdress,
		privKey:            privKey,
		certificateManager: crypt.NewCertificateManager(privKey),
		quit:               make(chan struct{}),
	}
}

func (server *Server) Start() error {
	err := server.certificateManager.GetCertificate(server.caAdress)
	if err != nil {
		fmt.Println("cant get certificate from CA", err)
	}

	listener, err := net.Listen("tcp", server.listenAddr)
	if err != nil {
		return err
	}

	server.listener = listener

	go server.Accept()

	<-server.quit

	return nil
}

func (server *Server) Accept() {
	for {
		conn, err := server.listener.Accept()
		if err != nil {
			fmt.Println("Accept error", err)
			continue
		}
		fmt.Println("Connection accepted", conn.LocalAddr())

		server.certificateManager.ExchangeCertificates(conn)

		pubKey, ok := server.certificateManager.PairCertificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			panic("Key error")
		}
		server.rsaChannel = crypt.NewSimpleRSA(*server.privKey, *pubKey)

		go server.Listen(conn)
		scanner := bufio.NewScanner(os.Stdin)

		for scanner.Scan() {

			message := scanner.Text()
			server.Write(message, conn)
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("Error on reading: ", err)
		}

	}
}

func (server *Server) Listen(conn net.Conn) {
	buf := make([]byte, 8192)

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

		fmt.Println("CipherText:", string(msg))

		clearText := server.rsaChannel.Decrypt(msg)

		fmt.Println("clearText:", clearText)

	}
}

func (server *Server) Write(str string, conn net.Conn) {
	cipherText := server.rsaChannel.Encrypt(str)

	n, err := conn.Write(cipherText)
	if err != nil {
		fmt.Println("Error on writing n bytes:", n, " err:", err)
	}
}

func main() {
	fmt.Println("starting server")

	server := NewServer(":3131", ":3030")

	err := server.Start()
	if err != nil {
		fmt.Println("starting error", err)
	}
}
