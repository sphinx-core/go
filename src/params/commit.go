// MIT License
//
// # Copyright (c) 2024 sphinx-core
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

package types

import "fmt"

// GenerateHeaders generates ledger and asset headers for SPX.
func GenerateHeaders(ledger, asset string, amount float64, address string) string {
	return fmt.Sprintf(
		"Ledger: %s\nAsset: %s\nAmount: %.2f\nAddress: %s",
		ledger, asset, amount, address,
	)
}

func main() {
	ledger := "sphinxchain"
	asset := "spx"
	amount := 1000.00
	address := "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"

	headers := GenerateHeaders(ledger, asset, amount, address)
	fmt.Println(headers)
}
