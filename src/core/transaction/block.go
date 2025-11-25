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

	"github.com/sphinx-core/go/src/common"
	logger "github.com/sphinx-core/go/src/log"
)

// NewBlockHeader creates a new BlockHeader with proper parent-uncle relationships
func NewBlockHeader(height uint64, parentHash []byte, difficulty *big.Int, txsRoot, stateRoot []byte, gasLimit, gasUsed *big.Int,
	extraData, miner []byte, timestamp int64, uncles []*BlockHeader) *BlockHeader {

	// Use time service if timestamp is 0 (auto-generate)
	if timestamp == 0 {
		timestamp = common.GetCurrentTimestamp()
	}

	// Calculate uncles hash with block height context
	unclesHash := CalculateUnclesHash(uncles, height) // Pass height here

	// Ensure extraData is never nil
	if extraData == nil {
		extraData = []byte{}
	}

	// Ensure miner is never nil
	if miner == nil {
		miner = make([]byte, 20) // Default zero address
	}

	// For genesis block, parentHash should be empty
	if height == 0 && len(parentHash) == 0 {
		parentHash = make([]byte, 32) // Empty hash for genesis
	}

	// Start with nonce 2 for regular blocks (genesis is 1)
	var nonce string
	if height == 0 {
		// Genesis block uses nonce 1
		nonce = common.FormatNonce(1)
	} else {
		// Regular blocks start from nonce 2 and will be incremented during consensus
		nonce = common.FormatNonce(2)
	}

	return &BlockHeader{
		Version:    1,
		Block:      height,
		Height:     height,
		Timestamp:  timestamp,
		ParentHash: parentHash, // Main chain continuity - using ParentHash consistently
		Hash:       []byte{},
		Difficulty: difficulty,
		Nonce:      nonce,
		TxsRoot:    txsRoot,
		StateRoot:  stateRoot,
		GasLimit:   gasLimit,
		GasUsed:    gasUsed,
		UnclesHash: unclesHash, // References side blocks
		ExtraData:  extraData,
		Miner:      miner,
	}
}

// NewBlockBody creates a new BlockBody with transactions and actual uncle blocks
func NewBlockBody(txsList []*Transaction, uncles []*BlockHeader) *BlockBody {
	// For block body, we don't have height context, so use 0 (will be overridden later)
	// Or you can modify this function to accept height if needed
	unclesHash := CalculateUnclesHash(uncles, 0) // Pass 0 as default

	return &BlockBody{
		TxsList:    txsList,
		Uncles:     uncles,
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

// IncrementNonce increments the block nonce and updates the hash
func (b *Block) IncrementNonce() error {
	if b.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	// Parse current nonce
	currentNonce, err := common.ParseNonce(b.Header.Nonce)
	if err != nil {
		return fmt.Errorf("failed to parse current nonce: %w", err)
	}

	// Increment nonce
	newNonce := currentNonce + 1
	b.Header.Nonce = common.FormatNonce(newNonce)

	// Regenerate block hash with new nonce
	b.FinalizeHash()

	logger.Debug("Incremented nonce for block %s: %s -> %s",
		b.GetHash(), common.FormatNonce(currentNonce), b.Header.Nonce)

	return nil
}

// GetCurrentNonce returns the current nonce as uint64
func (b *Block) GetCurrentNonce() (uint64, error) {
	if b.Header == nil {
		return 0, fmt.Errorf("block header is nil")
	}
	return common.ParseNonce(b.Header.Nonce)
}

// CalculateUnclesHash calculates the Merkle root of uncle block headers
func CalculateUnclesHash(uncles []*BlockHeader, blockHeight uint64) []byte {
	// SPECIAL CASE: Genesis block uses your specific hardcoded hash
	if blockHeight == 0 {
		genesisUnclesHash, _ := hex.DecodeString("3916d45c66e84c612c8a4a403702ec44cc575fc2383dbe4e861dd29ef892bee3")
		log.Printf("🔷 Genesis block %d - Using hardcoded uncles hash: %x", blockHeight, genesisUnclesHash)
		return genesisUnclesHash
	}

	// For non-genesis blocks with empty uncles
	if len(uncles) == 0 {
		// Use a different hash for non-genesis empty uncles
		emptyHash := common.SpxHash([]byte("empty_uncles_list"))
		log.Printf("🔷 Block %d - Using standard empty uncles hash: %x", blockHeight, emptyHash)
		return emptyHash
	}

	// Calculate Merkle root of uncle block headers (existing logic)
	var uncleHashes [][]byte
	for _, uncle := range uncles {
		if uncle != nil && len(uncle.Hash) > 0 {
			uncleHashes = append(uncleHashes, uncle.Hash)
		}
	}

	if len(uncleHashes) == 0 {
		return common.SpxHash([]byte{})
	}

	return CalculateMerkleRootFromHashes(uncleHashes)
}

// CalculateMerkleRootFromHashes calculates Merkle root from a list of hashes
func CalculateMerkleRootFromHashes(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		return common.SpxHash([]byte{})
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	// Build Merkle tree from hashes
	var nodes []*MerkleNode
	for _, hash := range hashes {
		nodes = append(nodes, &MerkleNode{Hash: hash, IsLeaf: true})
	}

	for len(nodes) > 1 {
		var newLevel []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				// Hash concatenation of left and right
				combined := append(nodes[i].Hash, nodes[i+1].Hash...)
				newNode := &MerkleNode{
					Left:  nodes[i],
					Right: nodes[i+1],
					Hash:  common.SpxHash(combined),
				}
				newLevel = append(newLevel, newNode)
			} else {
				// Odd number, duplicate the last one
				combined := append(nodes[i].Hash, nodes[i].Hash...)
				newNode := &MerkleNode{
					Left:  nodes[i],
					Right: &MerkleNode{Hash: nodes[i].Hash},
					Hash:  common.SpxHash(combined),
				}
				newLevel = append(newLevel, newNode)
			}
		}
		nodes = newLevel
	}

	return nodes[0].Hash
}

// GenerateBlockHash generates the block hash with proper parent-uncle relationships
func (b *Block) GenerateBlockHash() []byte {
	if b.Header == nil {
		return []byte{}
	}

	// Ensure UnclesHash is calculated from actual uncle blocks WITH HEIGHT
	calculatedUnclesHash := CalculateUnclesHash(b.Body.Uncles, b.Header.Height) // Pass height here
	if !bytes.Equal(b.Header.UnclesHash, calculatedUnclesHash) {
		log.Printf("WARNING: UnclesHash doesn't match calculated uncles, updating UnclesHash")
		b.Header.UnclesHash = calculatedUnclesHash
	}

	// Ensure TxsRoot is calculated from Merkle tree
	if len(b.Body.TxsList) > 0 {
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

	// Convert numeric fields to byte arrays
	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, b.Header.Version)

	blockNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumBytes, b.Header.Block)

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(b.Header.Timestamp))

	// FIX: Convert string nonce to bytes properly
	nonceBytes, err := common.NonceToBytes(b.Header.Nonce)
	if err != nil {
		// Fallback: use zero nonce if conversion fails
		logger.Warn("Failed to convert nonce to bytes: %v, using zero nonce", err)
		nonceBytes = make([]byte, 8) // 8 zero bytes
	}

	// Include ALL important header fields in the hash calculation
	headerData := versionBytes                                      // Version
	headerData = append(headerData, blockNumBytes...)               // Block number/height
	headerData = append(headerData, timestampBytes...)              // Timestamp
	headerData = append(headerData, b.Header.ParentHash...)         // Parent hash
	headerData = append(headerData, b.Header.TxsRoot...)            // Transactions Merkle root
	headerData = append(headerData, b.Header.StateRoot...)          // State Merkle root
	headerData = append(headerData, nonceBytes...)                  // Nonce (as bytes)
	headerData = append(headerData, b.Header.Difficulty.Bytes()...) // Difficulty
	headerData = append(headerData, b.Header.GasLimit.Bytes()...)   // Gas limit
	headerData = append(headerData, b.Header.GasUsed.Bytes()...)    // Gas used
	headerData = append(headerData, b.Header.UnclesHash...)         // Uncles hash
	headerData = append(headerData, b.Header.ExtraData...)          // Extra data
	headerData = append(headerData, b.Header.Miner...)              // Miner address

	// Use common.SpxHash to hash the concatenated data
	hashBytes := common.SpxHash(headerData)

	// ALWAYS return hex-encoded hash to avoid non-printable characters
	hexHash := hex.EncodeToString(hashBytes)

	// SPECIAL CASE: Only for genesis block (height 0), prefix with "GENESIS_"
	if b.Header.Height == 0 {
		genesisHash := "GENESIS_" + hexHash
		log.Printf("🔷 Genesis block hash created: %s", genesisHash)
		log.Printf("🔷 Genesis ParentHash: %x (empty)", b.Header.ParentHash)
		log.Printf("🔷 Genesis UnclesHash: %x", b.Header.UnclesHash)
		return []byte(genesisHash)
	}

	// For all other blocks, return hex-encoded hash
	log.Printf("🔷 Normal block %d hash created", b.Header.Height)
	log.Printf("🔷 ParentHash: %x", b.Header.ParentHash)
	log.Printf("🔷 UnclesHash: %x (%d uncles)", b.Header.UnclesHash, len(b.Body.Uncles))
	return []byte(hexHash)
}

// GetHash returns the block hash as string
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

// CalculateTxsRoot calculates the Merkle root of all transactions in the block
func (b *Block) CalculateTxsRoot() []byte {
	return CalculateMerkleRoot(b.Body.TxsList)
}

// FinalizeHash ensures all roots are properly set before finalizing the block hash
// FinalizeHash ensures all roots are properly set before finalizing the block hash
func (b *Block) FinalizeHash() {
	if b.Header == nil {
		return
	}

	// Ensure TxsRoot is calculated before generating the final hash
	b.Header.TxsRoot = b.CalculateTxsRoot()

	// Ensure UnclesHash is calculated from actual uncle blocks WITH HEIGHT
	b.Header.UnclesHash = CalculateUnclesHash(b.Body.Uncles, b.Header.Height) // Pass height here

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
	log.Printf("✅ Finalized block %d hash: %s", b.Header.Height, string(hashBytes))
	log.Printf("✅ ParentHash: %x", b.Header.ParentHash)
	log.Printf("✅ UnclesHash: %x (%d uncle blocks)", b.Header.UnclesHash, len(b.Body.Uncles))
}

// ValidateUnclesHash validates that UnclesHash matches the calculated uncles
func (b *Block) ValidateUnclesHash() error {
	if b.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	calculatedUnclesHash := CalculateUnclesHash(b.Body.Uncles, b.Header.Height) // Pass height here
	if !bytes.Equal(b.Header.UnclesHash, calculatedUnclesHash) {
		return fmt.Errorf("UnclesHash validation failed: expected %x, got %x (uncles count: %d)",
			calculatedUnclesHash, b.Header.UnclesHash, len(b.Body.Uncles))
	}
	return nil
}

// AddUncle adds an uncle block to the block
func (b *Block) AddUncle(uncle *BlockHeader) {
	if uncle != nil {
		b.Body.Uncles = append(b.Body.Uncles, uncle)
		// Recalculate uncles hash WITH HEIGHT
		b.Header.UnclesHash = CalculateUnclesHash(b.Body.Uncles, b.Header.Height) // Pass height here
	}
}

// GetUncles returns the list of uncle blocks
func (b *Block) GetUncles() []*BlockHeader {
	return b.Body.Uncles
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

// NewTxs creates a new transaction and adds it to the block
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

// GetFormattedTimestamps returns both local and UTC formatted timestamps
func (b *Block) GetFormattedTimestamps() (localTime, utcTime string) {
	return common.FormatTimestamp(b.Header.Timestamp)
}

// GetTimeInfo returns comprehensive time information
func (b *Block) GetTimeInfo() *common.TimeInfo {
	return common.GetTimeService().GetTimeInfo(b.Header.Timestamp)
}

// MarshalJSON custom marshaling for BlockHeader
// MarshalJSON custom marshaling for BlockHeader
func (h *BlockHeader) MarshalJSON() ([]byte, error) {
	type Alias BlockHeader
	return json.Marshal(&struct {
		Hash       string `json:"hash"`
		TxsRoot    string `json:"txs_root"`
		StateRoot  string `json:"state_root"`
		ParentHash string `json:"parent_hash"`
		UnclesHash string `json:"uncles_hash"`
		ExtraData  string `json:"extra_data"`
		Miner      string `json:"miner"`
		Nonce      string `json:"nonce"` // Correctly handles string nonce
		*Alias
	}{
		Hash:       string(h.Hash),
		TxsRoot:    common.Bytes2Hex(h.TxsRoot),
		StateRoot:  common.Bytes2Hex(h.StateRoot),
		ParentHash: common.Bytes2Hex(h.ParentHash),
		UnclesHash: common.Bytes2Hex(h.UnclesHash),
		ExtraData:  string(h.ExtraData),
		Miner:      common.Bytes2Hex(h.Miner),
		Nonce:      h.Nonce, // String nonce
		Alias:      (*Alias)(h),
	})
}

// UnmarshalJSON custom unmarshaling for BlockHeader
func (h *BlockHeader) UnmarshalJSON(data []byte) error {
	type Alias BlockHeader
	aux := &struct {
		Hash       string `json:"hash"`
		TxsRoot    string `json:"txs_root"`
		StateRoot  string `json:"state_root"`
		ParentHash string `json:"parent_hash"`
		UnclesHash string `json:"uncles_hash"`
		ExtraData  string `json:"extra_data"`
		Miner      string `json:"miner"`
		Nonce      string `json:"nonce"` // Add nonce as string
		*Alias
	}{
		Alias: (*Alias)(h),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var err error
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
	h.Nonce = aux.Nonce // Direct string assignment

	return nil
}

// MarshalJSON for Block
func (b *Block) MarshalJSON() ([]byte, error) {
	type Alias Block
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

// UnmarshalJSON for Block
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

// MarshalJSON for BlockBody
func (b *BlockBody) MarshalJSON() ([]byte, error) {
	type Alias BlockBody
	return json.Marshal(&struct {
		Uncles     []*BlockHeader `json:"uncles"`
		UnclesHash string         `json:"uncles_hash"`
		*Alias
	}{
		Uncles:     b.Uncles,
		UnclesHash: hex.EncodeToString(b.UnclesHash),
		Alias:      (*Alias)(b),
	})
}

// UnmarshalJSON for BlockBody
func (b *BlockBody) UnmarshalJSON(data []byte) error {
	type Alias BlockBody
	aux := &struct {
		Uncles     []*BlockHeader `json:"uncles"`
		UnclesHash string         `json:"uncles_hash"`
		*Alias
	}{
		Alias: (*Alias)(b),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	b.Uncles = aux.Uncles
	var err error
	b.UnclesHash, err = hex.DecodeString(aux.UnclesHash)
	if err != nil {
		return err
	}

	return nil
}

// Enhanced SanityCheck that validates both TxsRoot and UnclesHash
func (b *Block) SanityCheck() error {
	if b.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	// Validate timestamp using centralized service
	if err := common.ValidateBlockTimestamp(b.Header.Timestamp); err != nil {
		return fmt.Errorf("invalid block timestamp: %w", err)
	}

	// Ensure ParentHash is not empty (except for the genesis block)
	if b.Header.Height > 0 && len(b.Header.ParentHash) == 0 {
		return fmt.Errorf("parent hash is missing for block number: %d", b.Header.Height)
	}

	// Check if Difficulty is non-negative
	if b.Header.Difficulty.Sign() == -1 {
		return fmt.Errorf("invalid difficulty: %s", b.Header.Difficulty.String())
	}

	// VALIDATE THAT TxsRoot = MerkleRoot
	if err := b.ValidateTxsRoot(); err != nil {
		return fmt.Errorf("transaction root validation failed: %w", err)
	}

	// VALIDATE THAT UnclesHash matches actual uncles
	if err := b.ValidateUnclesHash(); err != nil {
		return fmt.Errorf("uncles hash validation failed: %w", err)
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

	// Validate uncle blocks
	for i, uncle := range b.Body.Uncles {
		if uncle == nil {
			return fmt.Errorf("uncle block %d is nil", i)
		}
		if len(uncle.Hash) == 0 {
			return fmt.Errorf("uncle block %d has empty hash", i)
		}
	}

	log.Printf("✓ Block %d validation passed:", b.Header.Height)
	log.Printf("  TxsRoot = MerkleRoot = %x", b.Header.TxsRoot)
	log.Printf("  UnclesHash validated with %d uncle blocks", len(b.Body.Uncles))
	log.Printf("  ParentHash: %x", b.Header.ParentHash)

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
