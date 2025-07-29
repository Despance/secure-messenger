package certauth

import (
	"fmt"
	"net"
)

type CertificateAuthority struct {
	listenAddr string
	listener   net.Listener
	quit       chan struct{}
}

func NewCertificateAuthority(listenAddr string) *CertificateAuthority {
	return &CertificateAuthority{
		listenAddr: listenAddr,
		quit:       make(chan struct{}),
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
			fmt.Println("Listening error", err)
			continue
		}

		msg := buf[:msgSize]

		fmt.Println(string(msg))

	}
}
