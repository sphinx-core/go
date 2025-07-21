package main

import (
	"fmt"

	"github.com/sphinx-core/go/src/crypto/SPHINCS-AAA/parameters"
	"github.com/sphinx-core/go/src/crypto/SPHINCS-AAA/tweakable"
)

func main() {
	params := parameters.MakeSphincsPlusSHAKE256128fRobustAAA1(true)
	// Override A to match AAA-1 specification
	params.A = 24
	shakeTweak, ok := params.Tweak.(*tweakable.Shake256Tweak)
	if ok {
		fmt.Printf("N: %d, H: %d, D: %d, Hprime: %d, K: %d, A: %d, W: %d, Len: %d, m: %d\n",
			params.N, params.H, params.D, params.Hprime, params.K, params.A, params.W, params.Len, shakeTweak.MessageDigestLength)
	} else {
		fmt.Printf("N: %d, H: %d, D: %d, Hprime: %d, K: %d, A: %d, W: %d, Len: %d\n",
			params.N, params.H, params.D, params.Hprime, params.K, params.A, params.W, params.Len)
	}
}
