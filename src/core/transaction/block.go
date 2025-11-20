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

// go/src/core/transaction/block.go
package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/sphinx-core/go/src/common"
)

// NewBlockHeader creates a new BlockHeader with centralized time service
// NewBlockHeader creates a new BlockHeader with centralized time service
func NewBlockHeader(height uint64, prevHash []byte, difficulty *big.Int, txsRoot, stateRoot []byte, gasLimit, gasUsed *big.Int,
	extraData, miner []byte, timestamp int64) *BlockHeader {

	// Use time service if timestamp is 0 (auto-generate)
	if timestamp == 0 {
		timestamp = common.GetCurrentTimestamp()
	}

	// For ALL blocks, set meaningful values for ParentHash and UnclesHash
	var parentHash []byte
	var unclesHash []byte

	if height == 0 {
		// Genesis block: no parent, so use zeros
		parentHash = make([]byte, 32)
		unclesHash = common.SpxHash([]byte("genesis-no-uncles"))
	} else {
		// Normal block: ParentHash should be same as PrevHash
		parentHash = prevHash

		// FIX: Set meaningful uncles hash for normal blocks too
		if len(prevHash) > 0 {
			// Create a meaningful uncles hash based on previous block hash
			unclesData := append([]byte("no-uncles-for-block-"), prevHash...)
			unclesHash = common.SpxHash(unclesData)
		} else {
			unclesHash = common.SpxHash([]byte("no-uncles"))
		}
	}

	// FIX: Ensure extraData is never nil
	if extraData == nil {
		extraData = []byte{}
	}

	// FIX: Ensure miner is never nil
	if miner == nil {
		miner = make([]byte, 20) // Default zero address
	}

	return &BlockHeader{
		Version:    1, // Default version
		Block:      height,
		Height:     height,
		Timestamp:  timestamp,
		PrevHash:   prevHash,
		Hash:       []byte{},
		Difficulty: difficulty,
		Nonce:      uint64(0),
		TxsRoot:    txsRoot,
		StateRoot:  stateRoot,
		GasLimit:   gasLimit,
		GasUsed:    gasUsed,
		ParentHash: parentHash, // Now properly set for all blocks
		UnclesHash: unclesHash, // Now meaningful for all blocks
		ExtraData:  extraData,
		Miner:      miner,
	}
}

// NewBlockBody creates a new BlockBody with a list of transactions and uncles hash.
func NewBlockBody(txsList []*Transaction, unclesHash []byte) *BlockBody {
	// FIX: Always set a meaningful uncles hash if empty
	if len(unclesHash) == 0 {
		// Create a meaningful uncles hash based on current timestamp
		timestampData := []byte(fmt.Sprintf("uncles-%d", time.Now().UnixNano()))
		unclesHash = common.SpxHash(timestampData)
	}

	return &BlockBody{
		TxsList:    txsList,
		UnclesHash: unclesHash,
	}
}

// NewBlock creates a new Block using the given header and body.
func NewBlock(header *BlockHeader, body *BlockBody) *Block {
	return &Block{
		Header: header,
		Body:   *body,
	}
}

// GenerateBlockHash generates the hash of the block using the BlockHeader's fields and SphinxHash.
// GenerateBlockHash generates the hash of the block and ALWAYS returns hex-encoded string
func (b *Block) GenerateBlockHash() []byte {
	if b.Header == nil {
		return []byte{}
	}

	// Convert numeric fields to byte arrays
	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, b.Header.Version)

	blockNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumBytes, b.Header.Block)

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(b.Header.Timestamp))

	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, b.Header.Nonce)

	// ENSURE TxsRoot is always calculated from Merkle tree before hash generation
	if len(b.Body.TxsList) > 0 {
		// Always recalculate TxsRoot to ensure it matches MerkleRoot
		calculatedMerkleRoot := b.CalculateTxsRoot()
		if !bytes.Equal(b.Header.TxsRoot, calculatedMerkleRoot) {
			log.Printf("WARNING: TxsRoot doesn't match calculated Merkle root, updating TxsRoot")
			b.Header.TxsRoot = calculatedMerkleRoot
		}
	} else {
		// For empty blocks, ensure TxsRoot is the hash of empty data
		emptyHash := common.SpxHash([]byte{})
		if len(b.Header.TxsRoot) == 0 || !bytes.Equal(b.Header.TxsRoot, emptyHash) {
			b.Header.TxsRoot = emptyHash
		}
	}

	// Include ALL important header fields in the hash calculation
	headerData := versionBytes                                      // Version
	headerData = append(headerData, blockNumBytes...)               // Block number/height
	headerData = append(headerData, timestampBytes...)              // Timestamp
	headerData = append(headerData, b.Header.PrevHash...)           // Previous block hash
	headerData = append(headerData, b.Header.TxsRoot...)            // Transactions Merkle root
	headerData = append(headerData, b.Header.StateRoot...)          // State Merkle root
	headerData = append(headerData, nonceBytes...)                  // Nonce
	headerData = append(headerData, b.Header.Difficulty.Bytes()...) // Difficulty
	headerData = append(headerData, b.Header.GasLimit.Bytes()...)   // Gas limit
	headerData = append(headerData, b.Header.GasUsed.Bytes()...)    // Gas used
	headerData = append(headerData, b.Header.ParentHash...)         // Parent hash
	headerData = append(headerData, b.Header.UnclesHash...)         // Uncles hash
	headerData = append(headerData, b.Header.ExtraData...)          // Extra data
	headerData = append(headerData, b.Header.Miner...)              // Miner address

	// Use common.SpxHash to hash the concatenated data
	hashBytes := common.SpxHash(headerData)

	// CRITICAL FIX: ALWAYS return hex-encoded hash to avoid non-printable characters
	hexHash := hex.EncodeToString(hashBytes)

	// SPECIAL CASE: Only for genesis block (height 0), prefix with "GENESIS_"
	if b.Header.Height == 0 {
		genesisHash := "GENESIS_" + hexHash
		log.Printf("🔷 Genesis block hash created: %s", genesisHash)
		return []byte(genesisHash)
	}

	// For all other blocks, return hex-encoded hash
	log.Printf("🔷 Normal block hash created (hex): %s", hexHash)
	return []byte(hexHash)
}

// generateGenesisHash creates a genesis block hash that starts with "GENESIS_"
// This is ONLY used for the genesis block (height 0)
func (b *Block) generateGenesisHash(originalHash []byte) []byte {
	// Convert the hash to hex string (full length, not truncated)
	fullHexHash := hex.EncodeToString(originalHash)

	// Create the final genesis hash: "GENESIS_" + full_hex_hash
	genesisHash := "GENESIS_" + fullHexHash

	log.Printf("🔷 Genesis block hash created: %s", genesisHash)
	log.Printf("🔷 Genesis hash length: %d characters", len(genesisHash))

	// Return as byte array - this should preserve the text format
	return []byte(genesisHash)
}

// GetHash returns the block hash as string
// GetHash returns the block hash as string - now always returns printable string
func (b *Block) GetHash() string {
	if b.Header == nil || len(b.Header.Hash) == 0 {
		return ""
	}

	hashStr := string(b.Header.Hash)

	// Check if it's already a valid hex string (for normal blocks)
	if isHexString(hashStr) {
		return hashStr
	}

	// Check if it's a genesis hash in text format
	if len(hashStr) > 8 && hashStr[:8] == "GENESIS_" {
		// Verify the part after GENESIS_ is hex
		hexPart := hashStr[8:]
		if isHexString(hexPart) {
			return hashStr
		}
	}

	// If we get here, the hash contains non-printable characters
	// Convert it to hex encoding
	hexHash := hex.EncodeToString(b.Header.Hash)
	log.Printf("⚠️ Converted non-printable hash to hex: %s", hexHash)
	return hexHash
}

// SetHash sets the block hash
func (b *Block) SetHash(hash string) {
	if b.Header == nil {
		return
	}
	b.Header.Hash = []byte(hash)
}

// isHexString checks if a string is hex-encoded
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// IsGenesisHash checks if this block has a genesis hash format
func (b *Block) IsGenesisHash() bool {
	hash := b.GetHash()
	return len(hash) > 8 && hash[:8] == "GENESIS_"
}

// CalculateTxsRoot calculates the Merkle root of all transactions in the block using proper Merkle tree
func (b *Block) CalculateTxsRoot() []byte {
	return CalculateMerkleRoot(b.Body.TxsList)
}

// FinalizeHash ensures TxsRoot is properly set before finalizing the block hash
// FinalizeHash ensures TxsRoot is properly set before finalizing the block hash
func (b *Block) FinalizeHash() {
	if b.Header == nil {
		return
	}
	// Ensure TxsRoot is calculated before generating the final hash
	b.Header.TxsRoot = b.CalculateTxsRoot()

	// Generate the hash (this now returns hex-encoded bytes)
	hashBytes := b.GenerateBlockHash()

	// Validate the generated hash is printable
	hashStr := string(hashBytes)
	for i, r := range hashStr {
		if r < 32 || r > 126 {
			log.Printf("❌ CRITICAL: Generated hash still contains non-printable char at position %d: %d", i, r)
			// Force hex encoding as fallback
			hashBytes = []byte(hex.EncodeToString(hashBytes))
			break
		}
	}

	b.Header.Hash = hashBytes
	log.Printf("✅ Finalized block hash: %s (length: %d)", string(hashBytes), len(hashBytes))
}

// ValidateTxsRoot validates that TxsRoot matches the calculated Merkle root
func (b *Block) ValidateTxsRoot() error {
	if b.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	calculatedMerkleRoot := b.CalculateTxsRoot()
	if !bytes.Equal(b.Header.TxsRoot, calculatedMerkleRoot) {
		return fmt.Errorf("TxsRoot validation failed: expected %x, got %x",
			calculatedMerkleRoot, b.Header.TxsRoot)
	}
	return nil
}

// AddTxs adds a transaction to the block's body.
func (b *Block) AddTxs(tx *Transaction) {
	b.Body.TxsList = append(b.Body.TxsList, tx)
}

// Example of a function to create a transaction
func NewTxs(to, from string, fee float64, storage string, nonce uint64, gasLimit, gasPrice *big.Int, block *Block, key string) error {
	// Create a new Note
	note, err := NewNote(to, from, fee, storage, key)
	if err != nil {
		return err
	}

	// Convert the Note to a Transaction
	tx := note.ToTxs(nonce, gasLimit, gasPrice)

	// Add the Transaction to the Block
	block.AddTxs(tx)

	return nil
}

// GetDifficulty returns the block difficulty
func (b *Block) GetDifficulty() *big.Int {
	if b.Header != nil {
		return b.Header.Difficulty
	}
	return big.NewInt(1)
}

// Validate performs basic block validation
func (b *Block) Validate() error {
	return b.SanityCheck()
}

// GetFormattedTimestamps returns both local and UTC formatted timestamps using centralized service
func (b *Block) GetFormattedTimestamps() (localTime, utcTime string) {
	return common.FormatTimestamp(b.Header.Timestamp)
}

// GetTimeInfo returns comprehensive time information using centralized service
func (b *Block) GetTimeInfo() *common.TimeInfo {
	return common.GetTimeService().GetTimeInfo(b.Header.Timestamp)
}

// MarshalJSON custom marshaling for BlockHeader to prevent base64 encoding
func (h *BlockHeader) MarshalJSON() ([]byte, error) {
	type Alias BlockHeader

	return json.Marshal(&struct {
		PrevHash   string `json:"prev_hash"`
		Hash       string `json:"hash"`
		TxsRoot    string `json:"txs_root"`
		StateRoot  string `json:"state_root"`
		ParentHash string `json:"parent_hash"`
		UnclesHash string `json:"uncles_hash"`
		ExtraData  string `json:"extra_data"`
		Miner      string `json:"miner"`
		*Alias
	}{
		PrevHash:   hex.EncodeToString(h.PrevHash),
		Hash:       string(h.Hash), // This should already be a printable string
		TxsRoot:    hex.EncodeToString(h.TxsRoot),
		StateRoot:  hex.EncodeToString(h.StateRoot),
		ParentHash: hex.EncodeToString(h.ParentHash),
		UnclesHash: hex.EncodeToString(h.UnclesHash),
		ExtraData:  string(h.ExtraData),
		Miner:      hex.EncodeToString(h.Miner),
		Alias:      (*Alias)(h),
	})
}

// UnmarshalJSON custom unmarshaling for BlockHeader
func (h *BlockHeader) UnmarshalJSON(data []byte) error {
	type Alias BlockHeader
	aux := &struct {
		PrevHash   string `json:"prev_hash"`
		Hash       string `json:"hash"`
		TxsRoot    string `json:"txs_root"`
		StateRoot  string `json:"state_root"`
		ParentHash string `json:"parent_hash"`
		UnclesHash string `json:"uncles_hash"`
		ExtraData  string `json:"extra_data"`
		Miner      string `json:"miner"`
		*Alias
	}{
		Alias: (*Alias)(h),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var err error

	h.PrevHash, err = hex.DecodeString(aux.PrevHash)
	if err != nil {
		return fmt.Errorf("failed to decode prev_hash: %w", err)
	}

	h.Hash = []byte(aux.Hash)

	h.TxsRoot, err = hex.DecodeString(aux.TxsRoot)
	if err != nil {
		return fmt.Errorf("failed to decode txs_root: %w", err)
	}

	h.StateRoot, err = hex.DecodeString(aux.StateRoot)
	if err != nil {
		return fmt.Errorf("failed to decode state_root: %w", err)
	}

	h.ParentHash, err = hex.DecodeString(aux.ParentHash)
	if err != nil {
		return fmt.Errorf("failed to decode parent_hash: %w", err)
	}

	h.UnclesHash, err = hex.DecodeString(aux.UnclesHash)
	if err != nil {
		return fmt.Errorf("failed to decode uncles_hash: %w", err)
	}

	h.ExtraData = []byte(aux.ExtraData)

	h.Miner, err = hex.DecodeString(aux.Miner)
	if err != nil {
		return fmt.Errorf("failed to decode miner: %w", err)
	}

	return nil
}

// Custom JSON marshaling for Block to prevent base64 encoding
func (b *Block) MarshalJSON() ([]byte, error) {
	type Alias Block

	// Create a custom structure that converts all []byte fields to hex strings
	return json.Marshal(&struct {
		Header *BlockHeader `json:"header"`
		Body   *BlockBody   `json:"body"`
		*Alias
	}{
		Header: b.Header,
		Body:   &b.Body,
		Alias:  (*Alias)(b),
	})
}

// Custom JSON unmarshaling for Block
func (b *Block) UnmarshalJSON(data []byte) error {
	type Alias Block
	aux := &struct {
		Header *BlockHeader `json:"header"`
		Body   *BlockBody   `json:"body"`
		*Alias
	}{
		Alias: (*Alias)(b),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	b.Header = aux.Header
	b.Body = *aux.Body
	return nil
}

// Custom JSON marshaling for BlockBody to prevent base64 encoding
func (b *BlockBody) MarshalJSON() ([]byte, error) {
	type Alias BlockBody

	return json.Marshal(&struct {
		UnclesHash string `json:"uncles_hash"`
		*Alias
	}{
		UnclesHash: hex.EncodeToString(b.UnclesHash),
		Alias:      (*Alias)(b),
	})
}

// Custom JSON unmarshaling for BlockBody
func (b *BlockBody) UnmarshalJSON(data []byte) error {
	type Alias BlockBody
	aux := &struct {
		UnclesHash string `json:"uncles_hash"`
		*Alias
	}{
		Alias: (*Alias)(b),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var err error
	b.UnclesHash, err = hex.DecodeString(aux.UnclesHash)
	if err != nil {
		return err
	}

	return nil
}

// Enhanced SanityCheck that validates TxsRoot = MerkleRoot with centralized time service
func (b *Block) SanityCheck() error {
	if b.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	// Validate timestamp using centralized service
	if err := common.ValidateBlockTimestamp(b.Header.Timestamp); err != nil {
		return fmt.Errorf("invalid block timestamp: %w", err)
	}

	// Ensure PrevHash is not empty (except for the genesis block)
	if b.Header.Height > 0 && len(b.Header.PrevHash) == 0 {
		return fmt.Errorf("previous hash is missing for block number: %d", b.Header.Height)
	}

	// Check if Difficulty is non-negative
	if b.Header.Difficulty.Sign() == -1 {
		return fmt.Errorf("invalid difficulty: %s", b.Header.Difficulty.String())
	}

	// VALIDATE THAT TxsRoot = MerkleRoot
	if err := b.ValidateTxsRoot(); err != nil {
		return fmt.Errorf("transaction root validation failed: %w", err)
	}

	// Check GasUsed does not exceed GasLimit
	if b.Header.GasUsed.Cmp(b.Header.GasLimit) > 0 {
		return fmt.Errorf("gas used (%s) exceeds gas limit (%s)", b.Header.GasUsed.String(), b.Header.GasLimit.String())
	}

	// Ensure all transactions in the body are valid
	for _, tx := range b.Body.TxsList {
		if err := tx.SanityCheck(); err != nil {
			return fmt.Errorf("invalid transaction: %v", err)
		}
	}

	log.Printf("✓ Block %d TxsRoot validated: TxsRoot = MerkleRoot = %x",
		b.Header.Height, b.Header.TxsRoot)

	// Log timestamp information using centralized service
	localTime, utcTime := common.FormatTimestamp(b.Header.Timestamp)
	log.Printf("✓ Block %d Timestamp: Local=%s, UTC=%s",
		b.Header.Height, localTime, utcTime)

	return nil
}

// SanityCheck verifies the validity of a transaction.
func (tx *Transaction) SanityCheck() error {
	// Validate timestamp using centralized service
	if err := common.ValidateTransactionTimestamp(tx.Timestamp); err != nil {
		return fmt.Errorf("invalid transaction timestamp: %w", err)
	}

	// Ensure sender and receiver addresses are not empty
	if tx.Sender == "" {
		return fmt.Errorf("transaction sender is missing")
	}
	if tx.Receiver == "" {
		return fmt.Errorf("transaction receiver is missing")
	}

	// Ensure the amount is non-negative
	if tx.Amount.Sign() == -1 {
		return fmt.Errorf("transaction amount is negative")
	}

	// Check gas limit and gas price are non-negative
	if tx.GasLimit.Sign() == -1 {
		return fmt.Errorf("invalid gas limit: %s", tx.GasLimit.String())
	}
	if tx.GasPrice.Sign() == -1 {
		return fmt.Errorf("invalid gas price: %s", tx.GasPrice.String())
	}

	return nil
}
