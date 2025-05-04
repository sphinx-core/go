package wots

// WOTSParams holds Winternitz parameters
type WOTSParams struct {
	W        int // Winternitz parameter (e.g., 4, 16)
	N        int // Hash output size in bytes (e.g., 32 for SHA-256)
	T        int // Number of hash chains
	T1       int // Length of message chains
	T2       int // Length of checksum chains
	Checksum int // Checksum size in bits
}

// PrivateKey represents a WOTS private key
type PrivateKey struct {
	Params WOTSParams
	Key    [][]byte // t random values of length n
}

// PublicKey represents a WOTS public key
type PublicKey struct {
	Params WOTSParams
	Key    [][]byte // t hashed values of length n
}

// Signature represents a WOTS signature
type Signature struct {
	Params WOTSParams
	Sig    [][]byte // t values of length n
}

// KeyManager manages WOTS key pairs for Alice
type KeyManager struct {
	Params    WOTSParams
	CurrentSK *PrivateKey // Current private key (e.g., skA, skB)
	CurrentPK *PublicKey  // Current public key (e.g., pkA, pkB)
	NextPK    *PublicKey  // Public key for next transaction (optional, for system registration)
}
