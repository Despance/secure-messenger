package main

import (
	"fmt"
	"net"
)

type Server struct {
	listenAddr string
	listener   net.Listener
	quit       chan struct{}
}

func NewServer(listenAddr string) *Server {
	return &Server{
		listenAddr: listenAddr,
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
			fmt.Println("Listening error", err)
			continue
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

	server := NewServer(":3131")

	err := server.Start()
	if err != nil {
		fmt.Println("starting error", err)
	}
}
