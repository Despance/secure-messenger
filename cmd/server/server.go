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

type Server struct {
	listenAddr        string
	caAdress          string
	privKey           *rsa.PrivateKey
	myCertificate     *x509.Certificate
	clientCertificate *x509.Certificate
	certPool          **x509.CertPool
	listener          net.Listener
	rsaChannel        crypt.SimpleRSA
	quit              chan struct{}
}

func NewServer(listenAddr string, caAdress string) *Server {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &Server{
		listenAddr: listenAddr,
		caAdress:   caAdress,
		privKey:    privKey,
		quit:       make(chan struct{}),
	}
}

func (server *Server) Start() error {
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

		server.exchangeCertificates(conn)

		pubKey, ok := server.clientCertificate.PublicKey.(*rsa.PublicKey)
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

func (server *Server) exchangeCertificates(conn net.Conn) {
	pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.myCertificate.Raw})

	_, err := conn.Write(pem)
	if err != nil {
		fmt.Println("Error on writing", err)
	}

	readBytes := make([]byte, 8192)

	n, err := conn.Read(readBytes)
	if err != nil {
		fmt.Println("error on parse certificate", err)
		return
	}

	msg := readBytes[:n]
	cert, err := parseCertificate(&msg)
	if err != nil {
		fmt.Println("err on parse", err)
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: *server.certPool,
	})
	if err != nil {
		fmt.Println("not valid cert", err)
		return
	}

	server.clientCertificate = cert
	fmt.Println("Certificate exchange is valid")
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

	err := server.getCertificate()
	if err != nil {
		fmt.Println("Error on certificate", err)
	}

	err = server.Start()
	if err != nil {
		fmt.Println("starting error", err)
	}
}

func parseCertificate(certBytes *[]byte) (*x509.Certificate, error) {
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

func (server *Server) getCertificate() error {
	caConn, err := net.Dial("tcp", server.caAdress)
	if err != nil {
		return err
	}

	certRequest := crypt.GetCertificateRequestBytes("Server", server.privKey)

	_, err = caConn.Write(certRequest)
	if err != nil {
		return err
	}

	allBytes, err := io.ReadAll(caConn)
	if err != nil {
		return err
	}

	server.myCertificate, err = parseCertificate(&allBytes)
	if err != nil {
		return err
	}

	caCert, err := parseCertificate(&allBytes)
	if err != nil {
		return err
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	server.certPool = &certPool

	opts := x509.VerifyOptions{
		Roots: certPool,
	}

	_, err = server.myCertificate.Verify(opts)
	if err != nil {
		return err
	}

	fmt.Println("Certificate is valid and trusted")

	return nil
}
