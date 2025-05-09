package wots

// WOTSParams holds Winternitz parameters
type WOTSParams struct {
	W        int // Winternitz parameter (fixed to 16)
	N        int // Hash output size in bytes (32 for SHAKE256)
	T        int // Number of hash chains
	T1       int // Length of message chains
	T2       int // Length of checksum chains
	Checksum int // Checksum size in bits
}

// PrivateKey represents a WOTS private key
type PrivateKey struct {
	Params WOTSParams
	Key    [][]byte // T random values of length N
}

// PublicKey represents a WOTS public key
type PublicKey struct {
	Params WOTSParams
	Key    [][]byte // T hashed values of length N
}

// Signature represents a WOTS signature
type Signature struct {
	Params WOTSParams
	Sig    [][]byte // T values of length N
}

// KeyManager manages WOTS key pairs for Alice
type KeyManager struct {
	Params    WOTSParams
	CurrentSK *PrivateKey // Current private key
	CurrentPK *PublicKey  // Current public key
	NextPK    *PublicKey  // Public key for next transaction (optional)
}
