package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"google.golang.org/protobuf/proto"

	"github.com/Despance/secure-messenger/message"
)

type SimpleAES struct {
	myKey   []byte
	pairKey []byte
	conn    net.Conn

	myAead   cipher.AEAD
	pairAead cipher.AEAD
}

func NewSimpleAES(myKey []byte, pairKey []byte, conn net.Conn) *SimpleAES {
	myBlock, err := aes.NewCipher(myKey)
	if err != nil {
		fmt.Println("error on aes", err)
		return nil
	}

	myAead, err := cipher.NewGCM(myBlock)
	if err != nil {
		fmt.Println("error on gcm", err)
	}

	pairBlock, err := aes.NewCipher(pairKey)
	if err != nil {
		fmt.Println("error on aes", err)
		return nil
	}

	pairAead, err := cipher.NewGCM(pairBlock)
	if err != nil {
		fmt.Println("error on gcm", err)
	}

	return &SimpleAES{
		myKey:    myKey,
		pairKey:  pairKey,
		conn:     conn,
		myAead:   myAead,
		pairAead: pairAead,
	}
}

func (saes *SimpleAES) Encrypt(plainText []byte) (nonce, cipherText []byte, err error) {
	nonce = make([]byte, saes.myAead.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println("encrpyt error ", err)
		return nil, nil, err
	}

	cipherText = saes.myAead.Seal(nil, nonce, plainText, nil)

	return nonce, cipherText, nil
}

func (saes *SimpleAES) EncryptAndSend(plainText []byte) error {
	nonce, cipherText, err := saes.Encrypt(plainText)
	if err != nil {
		return nil
	}

	chatEnv := &message.ChatMessage{
		Sender:     "hehe",
		Seq:        12,
		Nonce:      nonce,
		Ciphertext: cipherText,
	}

	newEnv := &message.Envelope{
		Type:      message.Envelope_CHAT,
		Sequence:  42,
		Timestamp: 10,
		Payload:   &message.Envelope_Chat{Chat: chatEnv},
	}

	length := make([]byte, 4)

	data, err := proto.Marshal(newEnv)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint32(length, uint32(len(data)))

	if _, err := saes.conn.Write(length); err != nil {
		return err
	}
	_, err = saes.conn.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func (saes *SimpleAES) Decrypt(nonce, cipherText []byte) (plainText []byte, err error) {
	plainText, err = saes.pairAead.Open(nil, nonce, cipherText, nil)

	fmt.Println(string(cipherText))
	return plainText, err
}

func (saes *SimpleAES) ListenAndDecrypt() string {
	msgLength := make([]byte, 4)

	if _, err := io.ReadFull(saes.conn, msgLength); err != nil {
		fmt.Println(err)
	}

	intlen := binary.BigEndian.Uint32(msgLength)

	readBytes := make([]byte, intlen)
	n, err := io.ReadFull(saes.conn, readBytes)
	if err != nil {
		fmt.Println("error on reading msg", err)
		return ""
	}

	msg := readBytes[:n]

	newEnv := &message.Envelope{}

	if err = proto.Unmarshal(msg, newEnv); err != nil {
		fmt.Println("error on unmarshal", err)

		return ""
	}

	if newEnv.Type != message.Envelope_CHAT {
		fmt.Println("not a chat msg")
		return ""
	}

	plainText, err := saes.Decrypt(newEnv.GetChat().GetNonce(), newEnv.GetChat().Ciphertext)

	return string(plainText)
}
