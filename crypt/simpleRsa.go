package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
)

type SimpleRSA struct {
	privKey           rsa.PrivateKey
	oppositePublicKey rsa.PublicKey
	hash              hash.Hash
	sequence          uint64
	label             []byte
}

func NewSimpleRSA(privKey rsa.PrivateKey, oppositePublicKey rsa.PublicKey) *SimpleRSA {
	return &SimpleRSA{
		privKey:           privKey,
		oppositePublicKey: oppositePublicKey,
		hash:              sha256.New(),
		label:             []byte(""),
	}
}

func (simpleRSA *SimpleRSA) Encrypt(msg string) []byte {
	cipherText, err := rsa.EncryptOAEP(simpleRSA.hash, rand.Reader, &simpleRSA.oppositePublicKey, []byte(msg), simpleRSA.label)
	if err != nil {
		fmt.Println("cant encrypt", err)
		return nil
	}

	return cipherText
}

func (simpleRSA *SimpleRSA) Decrypt(bytes []byte) string {
	plainText, err := rsa.DecryptOAEP(simpleRSA.hash, rand.Reader, &simpleRSA.privKey, bytes, simpleRSA.label)
	if err != nil {
		fmt.Println("cant decrypt", err)
		return "error"
	}
	return string(plainText)
}

func (simpleRSA *SimpleRSA) SendMessage(conn net.Conn, msg []byte) {
	length := make([]byte, 4)

	cipherText := simpleRSA.Encrypt(string(msg))

	binary.BigEndian.PutUint32(length, uint32(len(cipherText)))

	if _, err := conn.Write(length); err != nil {
		fmt.Println("cant send RSA message", err)
	}

	if _, err := conn.Write(cipherText); err != nil {
		fmt.Println("cant send RSA message", err)
	}
}

func (simpleRSA *SimpleRSA) GetMessage(conn net.Conn) string {
	length := make([]byte, 4)

	if _, err := io.ReadFull(conn, length); err != nil {
		fmt.Println("cant read length", err)
		return ""
	}

	intlen := binary.BigEndian.Uint32(length)
	buf := make([]byte, intlen)

	if _, err := io.ReadFull(conn, buf); err != nil {
		fmt.Println("error on read")
		return ""
	}

	return simpleRSA.Decrypt(buf)
}
