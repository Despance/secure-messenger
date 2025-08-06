package main

import (
	"fmt"
	"net"
)

type Client struct {
	serverAddress string
	connection    net.Conn
	quit          chan struct{}
}

func NewClient(serverAddress string) *Client {
	return &Client{
		serverAddress: serverAddress,
		quit:          make(chan struct{}),
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
	buf := make([]byte, 2048)

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
	client := NewClient(":3131")

	err := client.Connect()
	if err != nil {
		fmt.Println("error on connection", err)
	}

	client.Write("Hello server, i am client")

	go client.Read()

	for {
	}
}
