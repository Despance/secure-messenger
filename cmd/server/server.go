package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Despance/secure-messenger/crypt"
)

type Server struct {
	listenAddr    string
	caAdress      string
	privKey       *rsa.PrivateKey
	myCertificate *x509.Certificate
	certPool      *x509.CertPool
	listener      net.Listener
	quit          chan struct{}
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

		go server.Listen(conn)
		n, err := conn.Write([]byte("Hello you are connected to the Server"))
		if err != nil {
			fmt.Print(err, n)
		}

	}
}

func (server *Server) Listen(conn net.Conn) {
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

		server.Write("Got your message", conn)
	}
}

func (server *Server) Write(str string, conn net.Conn) {
	n, err := conn.Write([]byte(str))
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

	server.myCertificate, err = parseCertificate(allBytes)
	if err != nil {
		return err
	}

	caCert, err := parseCertificate(allBytes)
	if err != nil {
		return err
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	server.certPool = certPool

	opts := x509.VerifyOptions{
		Roots: server.certPool,
	}

	_, err = server.myCertificate.Verify(opts)
	if err != nil {
		return err
	}

	fmt.Println("Certificate is valid and trusted")

	return nil
}
