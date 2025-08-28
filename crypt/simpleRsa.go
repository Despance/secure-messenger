package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"
)

type SimpleRSA struct {
	privKey           rsa.PrivateKey
	oppositePublicKey rsa.PublicKey
	hash              hash.Hash
	label             []byte
}

func NewSimpleRSA(privKey rsa.PrivateKey, oppositePublicKey rsa.PublicKey) SimpleRSA {
	return SimpleRSA{
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
