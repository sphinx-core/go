package wots

import "math"

// NewWOTSParams initializes WOTS parameters
func NewWOTSParams(w int) WOTSParams {
	n := 32 // SHA-256 output size in bytes
	logW := int(math.Log2(float64(w)))
	t1 := int(math.Ceil(float64(256) / float64(logW)))
	checksumBits := int(math.Ceil(math.Log2(float64(t1 * int(math.Pow(2, float64(logW))-1)))))
	t2 := int(math.Ceil(float64(checksumBits) / float64(logW)))
	t := t1 + t2

	return WOTSParams{
		W:        w,
		N:        n,
		T:        t,
		T1:       t1,
		T2:       t2,
		Checksum: checksumBits,
	}
}
