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

// go/src/params/denom/config.go
package params

import "fmt"

// TokenInfo provides comprehensive information about SPX tokens
type TokenInfo struct {
	Name          string            `json:"name"`
	Symbol        string            `json:"symbol"`
	Decimals      uint8             `json:"decimals"`
	TotalSupply   uint64            `json:"total_supply"`
	Denominations map[string]uint64 `json:"denominations"`
	BIP44CoinType uint32            `json:"bip44_coin_type"`
	ChainID       uint64            `json:"chain_id"`
}

// GetSPXTokenInfo returns comprehensive SPX token information
func GetSPXTokenInfo() *TokenInfo {
	return &TokenInfo{
		Name:          "Sphinx",
		Symbol:        "SPX",
		Decimals:      18,
		TotalSupply:   MaximumSupply / SPX, // Convert to base units
		BIP44CoinType: 7331,
		ChainID:       7331,
		Denominations: map[string]uint64{
			"nSPX": nSPX,
			"gSPX": gSPX,
			"SPX":  SPX,
		},
	}
}

// ConvertToBase converts any denomination to base units (nSPX)
func ConvertToBase(amount float64, denomination string) (uint64, error) {
	info := GetSPXTokenInfo()
	multiplier, exists := info.Denominations[denomination]
	if !exists {
		return 0, fmt.Errorf("unknown denomination: %s", denomination)
	}

	// Convert to base units (nSPX)
	baseAmount := amount * float64(multiplier)
	if baseAmount < 0 {
		return 0, fmt.Errorf("amount cannot be negative")
	}

	return uint64(baseAmount), nil
}

// ConvertFromBase converts base units (nSPX) to specified denomination
func ConvertFromBase(baseAmount uint64, denomination string) (float64, error) {
	info := GetSPXTokenInfo()
	multiplier, exists := info.Denominations[denomination]
	if !exists {
		return 0, fmt.Errorf("unknown denomination: %s", denomination)
	}

	return float64(baseAmount) / float64(multiplier), nil
}

// ValidateAddressFormat validates SPX address format (basic version)
func ValidateAddressFormat(address string) bool {
	// Basic validation - in production, implement proper cryptographic validation
	if len(address) < 26 || len(address) > 42 {
		return false
	}

	// Check if it starts with "spx" for mainnet or "tspx" for testnet
	if address[:3] != "spx" && address[:4] != "tspx" {
		return false
	}

	return true
}

// GetDenominationInfo returns human-readable information about denominations
func GetDenominationInfo() string {
	info := GetSPXTokenInfo()

	return fmt.Sprintf(
		"=== SPX DENOMINATIONS ===\n"+
			"Token: %s (%s)\n"+
			"Decimals: %d\n"+
			"Base Unit: nSPX (1e%d)\n"+
			"Intermediate: gSPX (1e%d)\n"+
			"Main Unit: SPX (1e%d)\n"+
			"Total Supply: %.2f SPX\n"+
			"BIP44 Coin Type: %d\n"+
			"Chain ID: %d\n"+
			"========================",
		info.Name,
		info.Symbol,
		info.Decimals,
		0,  // nSPX exponent
		9,  // gSPX exponent
		18, // SPX exponent
		float64(info.TotalSupply),
		info.BIP44CoinType,
		info.ChainID,
	)
}
