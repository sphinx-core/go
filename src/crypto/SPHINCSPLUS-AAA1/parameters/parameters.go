package parameters

import (
	"math"

	"github.com/sphinx-core/go/src/crypto/SPHINCSPLUS-AAA1/tweakable"
)

type Parameters struct {
	N         int
	W         int  // Winternitz parameter for WOTS (w)
	Hprime    int  // Height per layer (h / d)
	H         int  // Total tree height
	D         int  // Number of layers in hypertree
	K         int  // Number of FORS trees
	T         int  // Number of leaves per FORS tree (2^logt)
	LogT      int  // Logarithm of T
	A         int  // Winternitz parameter for FORS
	RANDOMIZE bool // Randomization flag
	Tweak     tweakable.TweakableHashFunction
	Len1      int // First part of message length
	Len2      int // Second part of message length (checksum)
	Len       int // Total message length
}

// Define SPHINCS_AAA1 with SHAKE256-robust
func SPHINCS_AAA1() *Parameters {
	return MakeSphincsPlus(16, 256, 30, 2, 5, 8, 24, "SHAKE256-robust", true)
}

// SHA256-robust and N = 32
func MakeSphincsPlusSHA256256fRobust(RANDOMIZE bool) *Parameters {
	// Assuming a reasonable 'a' based on k and security (e.g., a = 9 for k=35)
	return MakeSphincsPlus(32, 16, 68, 17, 35, 9, 9, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256256sRobust(RANDOMIZE bool) *Parameters {
	// Assuming a reasonable 'a' based on k and security (e.g., a = 14 for k=22)
	return MakeSphincsPlus(32, 16, 64, 8, 22, 14, 14, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256256fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 68, 17, 35, 9, 9, "SHA256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHA256256sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 64, 8, 22, 14, 14, "SHA256-simple", RANDOMIZE)
}

// SHA256-robust and N = 24
func MakeSphincsPlusSHA256192fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 66, 22, 33, 8, 8, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256192sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 63, 7, 17, 14, 14, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256192fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 66, 22, 33, 8, 8, "SHA256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHA256192sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 63, 7, 17, 14, 14, "SHA256-simple", RANDOMIZE)
}

// SHA256-robust and N = 16
func MakeSphincsPlusSHA256128fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 66, 22, 33, 6, 6, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256128sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 63, 7, 14, 12, 12, "SHA256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHA256128fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 66, 22, 33, 6, 6, "SHA256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHA256128sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 63, 7, 14, 12, 12, "SHA256-simple", RANDOMIZE)
}

// SHAKE256-robust and N = 32
func MakeSphincsPlusSHAKE256256fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 68, 17, 35, 9, 9, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256256sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 64, 8, 22, 14, 14, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256256fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 68, 17, 35, 9, 9, "SHAKE256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256256sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(32, 16, 64, 8, 22, 14, 14, "SHAKE256-simple", RANDOMIZE)
}

// SHAKE256-robust and N = 24
func MakeSphincsPlusSHAKE256192fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 66, 22, 33, 8, 8, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256192sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 63, 7, 17, 14, 14, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256192fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 66, 22, 33, 8, 8, "SHAKE256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256192sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(24, 16, 63, 7, 17, 14, 14, "SHAKE256-simple", RANDOMIZE)
}

// SHAKE256-robust and N = 16
func MakeSphincsPlusSHAKE256128fRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 66, 22, 33, 6, 6, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256128sRobust(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 63, 7, 14, 12, 12, "SHAKE256-robust", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256128fSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 66, 22, 33, 6, 6, "SHAKE256-simple", RANDOMIZE)
}
func MakeSphincsPlusSHAKE256128sSimple(RANDOMIZE bool) *Parameters {
	return MakeSphincsPlus(16, 16, 63, 7, 14, 12, 12, "SHAKE256-simple", RANDOMIZE)
}

func MakeSphincsPlus(n int, w int, h int, d int, k int, logt int, a int, hashFunc string, RANDOMIZE bool) *Parameters {
	params := new(Parameters)
	params.N = n
	params.W = w
	params.H = h
	params.D = d
	params.K = k
	params.LogT = logt
	params.Hprime = params.H / params.D
	params.T = (1 << logt)
	params.A = a // Explicitly set FORS Winternitz parameter
	params.RANDOMIZE = RANDOMIZE
	params.Len1 = int(math.Ceil(8 * float64(n) / math.Log2(float64(w))))
	params.Len2 = int(math.Floor(math.Log2(float64(params.Len1*(w-1)))/math.Log2(float64(w))) + 1)
	params.Len = params.Len1 + params.Len2
	md_len := int(math.Floor((float64(params.K)*float64(a) + 7) / 8)) // Use 'a' for message digest length
	idx_tree_len := int(math.Floor((float64(h - h/d + 7)) / 8))
	idx_leaf_len := int(math.Floor(float64(h/d+7)) / 8)
	m := md_len + idx_tree_len + idx_leaf_len
	switch hashFunc {
	case "SHA256-robust":
		params.Tweak = &tweakable.Sha256Tweak{
			Variant:             tweakable.Robust,
			MessageDigestLength: m,
			N:                   n,
		}
	case "SHA256-simple":
		params.Tweak = &tweakable.Sha256Tweak{
			Variant:             tweakable.Simple,
			MessageDigestLength: m,
			N:                   n,
		}
	case "SHAKE256-robust":
		params.Tweak = &tweakable.Shake256Tweak{
			Variant:             tweakable.Robust,
			MessageDigestLength: m,
			N:                   n,
		}
	case "SHAKE256-simple":
		params.Tweak = &tweakable.Shake256Tweak{
			Variant:             tweakable.Simple,
			MessageDigestLength: m,
			N:                   n,
		}
	default:
		params.Tweak = &tweakable.Sha256Tweak{
			Variant:             tweakable.Robust,
			MessageDigestLength: m,
			N:                   n,
		}
	}
	return params
}
