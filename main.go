package main

import (
	"fmt"

	"github.com/Despance/secure-messenger/certauth"
)

func main() {
	fmt.Println("Server Starting")

	ca := certauth.NewCertificateAuthority(":3030")

	err := ca.Start()
	if err != nil {
		fmt.Println("error on starting server", err)
	}
}
