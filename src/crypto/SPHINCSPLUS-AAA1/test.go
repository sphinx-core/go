package main

import (
	"fmt"

	"github.com/sphinx-core/go/src/crypto/SPHINCSPLUS-AAA1/parameters"
	"github.com/sphinx-core/go/src/crypto/SPHINCSPLUS-AAA1/sphincs"
)

func main() {
	params := parameters.SPHINCS_AAA1()
	fmt.Println("N:", params.N) // Should print 16

	sk, pk := sphincs.SPHINCS_AAA1_Keygen()
	fmt.Println("Public Key Size:", len(pk.FullPK))      // Should print 32
	fmt.Println("Secret Key Seed Size:", len(sk.SKseed)) // Use sk
}
