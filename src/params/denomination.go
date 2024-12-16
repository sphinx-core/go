// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package params

// These are the multipliers for SPX denominations, which help to represent
// different units of the SPX token in the Sphinx blockchain, similar to how
// currencies like Bitcoin and Ethereum use smaller units such as satoshis and wei.
// The base unit is nSPX (nano SPX), which is the smallest denomination, and
// larger units such as gSPX (giga SPX) and SPX (1 full token) are represented
// by multiplying nSPX values.

const (
	nSPX = 1e0  // 1 nSPX (nano SPX) is the smallest unit of SPX, similar to "wei" in Ethereum.
	gSPX = 1e9  // 1 gSPX (giga SPX) equals 1e9 nSPX. It's a larger denomination used for easier representation.
	SPX  = 1e18 // 1 SPX equals 1e18 nSPX, similar to how 1 Ether equals 1e18 wei.
)

// In the same way that 1 Ether = 1e18 wei, here:
// 1 SPX = 1e18 nSPX, and 1 gSPX = 1e9 nSPX.
//
// Example of conversions:

// 1. Converting gSPX to nSPX:
// To convert an amount in gSPX to nSPX, multiply the value by the gSPX multiplier (1e9).
// For example, if you have 5 gSPX, the conversion to nSPX would be:
// valueInGSPX := new(big.Int).SetInt64(5)                // 5 gSPX
// valueInNSPX := new(big.Int).Mul(valueInGSPX, big.NewInt(gSPX)) // 5 * 1e9 = 5e9 nSPX
// Result: valueInNSPX is now equal to 5,000,000,000 nSPX

// 2. Converting SPX to nSPX:
// To convert an amount in SPX to nSPX, multiply the value by the SPX multiplier (1e18).
// For example, if you have 2 SPX, the conversion to nSPX would be:
// valueInSPX := new(big.Int).SetInt64(2)                 // 2 SPX
// valueInNSPX2 := new(big.Int).Mul(valueInSPX, big.NewInt(SPX)) // 2 * 1e18 = 2e18 nSPX
// Result: valueInNSPX2 is now equal to 2,000,000,000,000,000,000 nSPX

// 3. Converting nSPX to gSPX:
// To convert an amount in nSPX back to gSPX, divide the value by the gSPX multiplier (1e9).
// For example, if you have 1,000,000,000 nSPX, the conversion to gSPX would be:s
// valueInNSPX3 := new(big.Int).SetInt64(1000000000)          // 1,000,000,000 nSPX
// valueInGSPX2 := new(big.Int).Div(valueInNSPX3, big.NewInt(gSPX)) // 1,000,000,000 / 1e9 = 1 gSPX
// Result: valueInGSPX2 is now equal to 1 gSPX

// 4. Converting nSPX to SPX:
// To convert an amount in nSPX to SPX, divide the value by the SPX multiplier (1e18).
// For example, if you have 1,000,000,000,000,000,000 nSPX, the conversion to SPX would be:
// valueInNSPX4 := new(big.Int).SetInt64(1000000000000000000) // 1,000,000,000,000,000,000 nSPX
// valueInSPX2 := new(big.Int).Div(valueInNSPX4, big.NewInt(SPX)) // 1,000,000,000,000,000,000 / 1e18 = 1 SPX
// Result: valueInSPX2 is now equal to 1 SPX
