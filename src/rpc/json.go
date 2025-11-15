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

// go/src/rpc/json.go
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sphinx-core/go/src/core"
	types "github.com/sphinx-core/go/src/core/transaction"
	security "github.com/sphinx-core/go/src/handshake"
)

// NewJSONRPCHandler creates a new JSON-RPC handler with registered methods.
func NewJSONRPCHandler(server *Server) *JSONRPCHandler {
	handler := &JSONRPCHandler{
		server:  server,
		methods: make(map[string]RPCHandler),
	}
	handler.registerMethods() // Register all supported RPC methods
	return handler
}

// getBlockByNumber retrieves a block by its height (number)
func (h *JSONRPCHandler) getBlockByNumber(params interface{}) (interface{}, error) {
	var paramsArray []interface{}
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err // Failed to parse parameters
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing block number parameter") // Require at least one parameter
	}

	height, ok := paramsArray[0].(float64)
	if !ok {
		return nil, errors.New("invalid block number parameter") // Height must be numeric
	}

	// Use the direct method that returns *types.Block (not wrapped)
	block := h.server.blockchain.GetBlockByNumber(uint64(height))
	if block == nil {
		return nil, errors.New("block not found") // Block does not exist at this height
	}
	return block, nil
}

// getBlockHash returns the hash of a block at a given height
func (h *JSONRPCHandler) getBlockHash(params interface{}) (interface{}, error) {
	var paramsArray []interface{}
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing block height parameter")
	}

	height, ok := paramsArray[0].(float64)
	if !ok {
		return nil, errors.New("invalid block height parameter")
	}

	hash := h.server.blockchain.GetBlockHash(uint64(height))
	if hash == "" {
		return nil, errors.New("block not found")
	}
	return hash, nil
}

// getDifficulty returns the current network difficulty as a string
func (h *JSONRPCHandler) getDifficulty(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetDifficulty().String(), nil
}

// getChainTip returns information about the current chain tip (latest block)
func (h *JSONRPCHandler) getChainTip(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetChainTip(), nil
}

// getNetworkInfo returns network-related statistics and configuration
func (h *JSONRPCHandler) getNetworkInfo(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetNetworkInfo(), nil
}

// getMiningInfo returns mining-related statistics
func (h *JSONRPCHandler) getMiningInfo(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetMiningInfo(), nil
}

// estimateFee estimates the transaction fee per byte for confirmation within N blocks
func (h *JSONRPCHandler) estimateFee(params interface{}) (interface{}, error) {
	var paramsArray []interface{}
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}

	blocks := 6 // default
	if len(paramsArray) > 0 {
		if blocksParam, ok := paramsArray[0].(float64); ok {
			blocks = int(blocksParam) // Override default if provided
		}
	}

	return h.server.blockchain.EstimateFee(blocks), nil
}

// getMemPoolInfo returns statistics about the memory pool
func (h *JSONRPCHandler) getMemPoolInfo(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetMemPoolInfo(), nil
}

// validateAddress checks if a given address is valid according to network rules
func (h *JSONRPCHandler) validateAddress(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing address parameter")
	}

	isValid := h.server.blockchain.ValidateAddress(paramsArray[0])
	return map[string]interface{}{
		"isvalid": isValid,
		"address": paramsArray[0],
	}, nil
}

// verifyMessage verifies a cryptographic signature for a message and address
func (h *JSONRPCHandler) verifyMessage(params interface{}) (interface{}, error) {
	var paramsStruct struct {
		Address   string `json:"address"`
		Signature string `json:"signature"`
		Message   string `json:"message"`
	}
	if err := h.parseParams(params, &paramsStruct); err != nil {
		return nil, err
	}

	isValid := h.server.blockchain.VerifyMessage(
		paramsStruct.Address,
		paramsStruct.Signature,
		paramsStruct.Message,
	)

	return map[string]interface{}{
		"verified": isValid,
	}, nil
}

// getRawTransaction returns raw transaction data, optionally in verbose format
func (h *JSONRPCHandler) getRawTransaction(params interface{}) (interface{}, error) {
	var paramsArray []interface{}
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing transaction ID parameter")
	}

	txID, ok := paramsArray[0].(string)
	if !ok {
		return nil, errors.New("invalid transaction ID parameter")
	}

	verbose := false
	if len(paramsArray) > 1 {
		if verboseParam, ok := paramsArray[1].(bool); ok {
			verbose = verboseParam // Second param controls verbosity
		}
	}

	result := h.server.blockchain.GetRawTransaction(txID, verbose)
	if result == nil {
		return nil, errors.New("transaction not found")
	}
	return result, nil
}

// registerMethods registers all supported RPC methods with their handler functions
func (h *JSONRPCHandler) registerMethods() {
	// Existing methods
	h.methods["getblockcount"] = h.getBlockCount
	h.methods["getbestblockhash"] = h.getBestBlockHash
	h.methods["getblock"] = h.getBlock
	h.methods["getblocks"] = h.getBlocks
	h.methods["sendrawtransaction"] = h.sendRawTransaction
	h.methods["gettransaction"] = h.getTransaction
	h.methods["ping"] = h.ping
	h.methods["join"] = h.join
	h.methods["findnode"] = h.findNode
	h.methods["get"] = h.get
	h.methods["store"] = h.store

	// New blockchain methods
	h.methods["getblockbynumber"] = h.getBlockByNumber
	h.methods["getblockhash"] = h.getBlockHash
	h.methods["getdifficulty"] = h.getDifficulty
	h.methods["getchaintip"] = h.getChainTip
	h.methods["getnetworkinfo"] = h.getNetworkInfo
	h.methods["getmininginfo"] = h.getMiningInfo
	h.methods["estimatefee"] = h.estimateFee
	h.methods["getmempoolinfo"] = h.getMemPoolInfo
	h.methods["validateaddress"] = h.validateAddress
	h.methods["verifymessage"] = h.verifyMessage
	h.methods["getrawtransaction"] = h.getRawTransaction
}

// ProcessRequest processes a JSON-RPC request or batch of requests.
// It first attempts to parse as binary Message, then falls back to JSON-RPC.
func (h *JSONRPCHandler) ProcessRequest(data []byte) ([]byte, error) {
	// Try to parse as a Message (binary format)
	var msg Message
	if err := msg.Unmarshal(data); err == nil {
		return h.processBinaryMessage(msg) // Handle binary protocol message
	}

	// Fallback to JSON-RPC
	var singleReq JSONRPCRequest
	if err := json.Unmarshal(data, &singleReq); err == nil && singleReq.JSONRPC == "2.0" {
		return h.processSingleRequest(singleReq) // Handle single JSON-RPC request
	}

	// Try to parse as a batch request
	var batchReq []JSONRPCRequest
	if err := json.Unmarshal(data, &batchReq); err == nil && len(batchReq) > 0 {
		return h.processBatchRequest(batchReq) // Handle batch of JSON-RPC requests
	}

	return h.errorResponse(nil, ErrCodeParseError, "Parse error: invalid JSON or binary format")
}

// processBinaryMessage handles a binary Message.
func (h *JSONRPCHandler) processBinaryMessage(msg Message) ([]byte, error) {
	start := time.Now()
	method := msg.RPCType.String()
	h.server.metrics.RequestCount.WithLabelValues(method).Inc() // Increment request counter
	defer func() {
		h.server.metrics.RequestLatency.WithLabelValues(method).Observe(time.Since(start).Seconds()) // Record latency
	}()

	// Validate TTL
	if msg.TTL == 0 {
		return h.errorResponse(msg.RPCID, ErrCodeInvalidRequest, "Invalid TTL")
	}

	// Map RPCType to method name
	methodName, err := h.mapRPCTypeToMethod(msg.RPCType)
	if err != nil {
		h.server.metrics.ErrorCount.WithLabelValues(method).Inc()
		return h.errorResponse(msg.RPCID, ErrCodeMethodNotFound, err.Error())
	}

	// Convert Values to params
	var params interface{}
	if len(msg.Values) > 0 {
		if err := json.Unmarshal(msg.Values[0], &params); err != nil {
			h.server.metrics.ErrorCount.WithLabelValues(method).Inc()
			return h.errorResponse(msg.RPCID, ErrCodeInvalidParams, "Invalid parameters format")
		}
	}

	// Execute method
	handler, exists := h.methods[methodName]
	if !exists {
		h.server.metrics.ErrorCount.WithLabelValues(method).Inc()
		return h.errorResponse(msg.RPCID, ErrCodeMethodNotFound, fmt.Sprintf("Method %s not found", methodName))
	}

	// Track queries for specific RPC types
	if msg.Query {
		switch msg.RPCType {
		case RPCPing:
			h.server.queryManager.AddPing(msg.RPCID, msg.Target)
		case RPCJoin:
			h.server.queryManager.AddJoin(msg.RPCID)
		case RPCFindNode:
			h.server.queryManager.AddFindNode(msg.RPCID, msg.Target, nil)
		case RPCGet, RPCStore:
			h.server.queryManager.AddGet(msg.RPCID)
		}
	}

	result, err := handler(params)
	if err != nil {
		h.server.metrics.ErrorCount.WithLabelValues(method).Inc()
		return h.errorResponse(msg.RPCID, ErrCodeInvalidParams, err.Error())
	}

	// Prepare response Message
	respMsg := Message{
		RPCType:   msg.RPCType,
		Query:     false,
		TTL:       msg.TTL,
		Target:    msg.From.NodeID,
		RPCID:     msg.RPCID,
		From:      msg.From, // Use server's node info in production
		Values:    [][]byte{},
		Iteration: msg.Iteration,
		Secret:    msg.Secret,
	}
	if result != nil {
		resultData, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		respMsg.Values = append(respMsg.Values, resultData)
	}

	return respMsg.Marshal(make([]byte, respMsg.MarshalSize()))
}

// processSingleRequest handles a single JSON-RPC request.
func (h *JSONRPCHandler) processSingleRequest(req JSONRPCRequest) ([]byte, error) {
	start := time.Now()
	h.server.metrics.RequestCount.WithLabelValues(req.Method).Inc()
	defer func() {
		h.server.metrics.RequestLatency.WithLabelValues(req.Method).Observe(time.Since(start).Seconds())
	}()

	if req.JSONRPC != "2.0" {
		return h.errorResponse(req.ID, ErrCodeInvalidRequest, "Invalid JSON-RPC version")
	}
	if req.Method == "" {
		return h.errorResponse(req.ID, ErrCodeInvalidRequest, "Method is required")
	}

	handler, exists := h.methods[req.Method]
	if !exists {
		h.server.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
		return h.errorResponse(req.ID, ErrCodeMethodNotFound, fmt.Sprintf("Method %s not found", req.Method))
	}

	result, err := handler(req.Params)
	if err != nil {
		h.server.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
		return h.errorResponse(req.ID, ErrCodeInvalidParams, err.Error())
	}

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      req.ID,
	}
	return json.Marshal(resp)
}

// processBatchRequest handles a batch of JSON-RPC requests.
func (h *JSONRPCHandler) processBatchRequest(reqs []JSONRPCRequest) ([]byte, error) {
	responses := make([]JSONRPCResponse, 0, len(reqs))
	for _, req := range reqs {
		respData, err := h.processSingleRequest(req)
		if err != nil {
			continue // Skip failed requests in batch
		}
		var resp JSONRPCResponse
		if err := json.Unmarshal(respData, &resp); err != nil {
			continue
		}
		responses = append(responses, resp)
	}
	if len(responses) == 0 {
		return h.errorResponse(nil, ErrCodeInvalidRequest, "Empty batch request")
	}
	return json.Marshal(responses)
}

// errorResponse creates a JSON-RPC error response.
func (h *JSONRPCHandler) errorResponse(id interface{}, code int, message string) ([]byte, error) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
		ID: id,
	}
	return json.Marshal(resp)
}

// mapRPCTypeToMethod maps an RPCType to a method name.
func (h *JSONRPCHandler) mapRPCTypeToMethod(rpcType RPCType) (string, error) {
	switch rpcType {
	case RPCGetBlockCount:
		return "getblockcount", nil
	case RPCGetBestBlockHash:
		return "getbestblockhash", nil
	case RPCGetBlock:
		return "getblock", nil
	case RPCGetBlocks:
		return "getblocks", nil
	case RPCSendRawTransaction:
		return "sendrawtransaction", nil
	case RPCGetTransaction:
		return "gettransaction", nil
	case RPCPing:
		return "ping", nil
	case RPCJoin:
		return "join", nil
	case RPCFindNode:
		return "findnode", nil
	case RPCGet:
		return "get", nil
	case RPCStore:
		return "store", nil
	case RPCGetBlockByNumber:
		return "getblockbynumber", nil
	case RPCGetBlockHash:
		return "getblockhash", nil
	case RPCGetDifficulty:
		return "getdifficulty", nil
	case RPCGetChainTip:
		return "getchaintip", nil
	case RPCGetNetworkInfo:
		return "getnetworkinfo", nil
	case RPCGetMiningInfo:
		return "getmininginfo", nil
	case RPCEstimateFee:
		return "estimatefee", nil
	case RPCGetMemPoolInfo:
		return "getmempoolinfo", nil
	case RPCValidateAddress:
		return "validateaddress", nil
	case RPCVerifyMessage:
		return "verifymessage", nil
	case RPCGetRawTransaction:
		return "getrawtransaction", nil
	default:
		return "", ErrUnsupportedRPCType
	}
}

// String converts an RPCType to its string representation.
func (t RPCType) String() string {
	switch t {
	case RPCGetBlockCount:
		return "getblockcount"
	case RPCGetBestBlockHash:
		return "getbestblockhash"
	case RPCGetBlock:
		return "getblock"
	case RPCGetBlocks:
		return "getblocks"
	case RPCSendRawTransaction:
		return "sendrawtransaction"
	case RPCGetTransaction:
		return "gettransaction"
	case RPCPing:
		return "ping"
	case RPCJoin:
		return "join"
	case RPCFindNode:
		return "findnode"
	case RPCGet:
		return "get"
	case RPCStore:
		return "store"
	case RPCGetBlockByNumber:
		return "getblockbynumber"
	case RPCGetBlockHash:
		return "getblockhash"
	case RPCGetDifficulty:
		return "getdifficulty"
	case RPCGetChainTip:
		return "getchaintip"
	case RPCGetNetworkInfo:
		return "getnetworkinfo"
	case RPCGetMiningInfo:
		return "getmininginfo"
	case RPCEstimateFee:
		return "estimatefee"
	case RPCGetMemPoolInfo:
		return "getmempoolinfo"
	case RPCValidateAddress:
		return "validateaddress"
	case RPCVerifyMessage:
		return "verifymessage"
	case RPCGetRawTransaction:
		return "getrawtransaction"
	default:
		return "unknown"
	}
}

// RPC Method Handlers

// getBlockCount returns the current block height
func (h *JSONRPCHandler) getBlockCount(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetBlockCount(), nil
}

// getBestBlockHash returns the hash of the best (tip) block
func (h *JSONRPCHandler) getBestBlockHash(_ interface{}) (interface{}, error) {
	hash := h.server.blockchain.GetBestBlockHash()
	return fmt.Sprintf("%x", hash), nil
}

// getBlock retrieves a block by its hash
func (h *JSONRPCHandler) getBlock(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing block hash parameter")
	}
	hashStr := paramsArray[0]

	// Get block using the consensus interface
	block := h.server.blockchain.GetBlockByHash(hashStr)
	if block == nil {
		return nil, errors.New("block not found")
	}

	// Convert back to types.Block for JSON serialization
	if adapter, ok := block.(*core.BlockHelper); ok {
		return adapter.GetUnderlyingBlock(), nil
	}

	return block, nil
}

// getBlocks returns a list of recent blocks
func (h *JSONRPCHandler) getBlocks(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetBlocks(), nil
}

// sendRawTransaction broadcasts a signed transaction to the network
func (h *JSONRPCHandler) sendRawTransaction(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing transaction hex parameter")
	}
	rawTx := paramsArray[0]
	txBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction hex: %v", err)
	}
	var tx types.Transaction
	if err := json.Unmarshal(txBytes, &tx); err != nil {
		return nil, fmt.Errorf("invalid transaction format: %v", err)
	}
	if tx.ID == "" {
		tx.ID = tx.Hash() // Compute ID if not present
	}
	if err := h.server.blockchain.AddTransaction(&tx); err != nil {
		return nil, err
	}
	h.server.messageCh <- &security.Message{Type: "transaction", Data: &tx} // Broadcast via network
	return map[string]string{"txid": tx.ID}, nil
}

// getTransaction retrieves a transaction by its ID
func (h *JSONRPCHandler) getTransaction(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing transaction ID parameter")
	}
	txID := paramsArray[0]

	// Use the string-based method
	tx, err := h.server.blockchain.GetTransactionByIDString(txID)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// ping responds to health checks
func (h *JSONRPCHandler) ping(params interface{}) (interface{}, error) {
	return map[string]string{"status": "pong"}, nil
}

// join acknowledges node joining the network
func (h *JSONRPCHandler) join(params interface{}) (interface{}, error) {
	return map[string]string{"status": "joined"}, nil
}

// findNode locates a node by its ID (placeholder implementation)
func (h *JSONRPCHandler) findNode(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing node ID parameter")
	}
	nodeIDStr := paramsArray[0]
	nodeIDBytes, err := hex.DecodeString(nodeIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid node ID: %v", err)
	}
	var nodeID NodeID
	copy(nodeID[:], nodeIDBytes)
	// Placeholder: Implement node lookup logic
	return map[string]string{"nodeID": nodeIDStr}, nil
}

// get retrieves stored values by key from the DHT
func (h *JSONRPCHandler) get(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing key parameter")
	}
	keyStr := paramsArray[0]
	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %v", err)
	}
	var key Key
	copy(key[:], keyBytes)
	values, ok := h.server.store.Get(key)
	if !ok {
		return nil, errors.New("key not found")
	}
	// Convert values to hex strings for JSON response
	hexValues := make([]string, len(values))
	for i, v := range values {
		hexValues[i] = hex.EncodeToString(v)
	}
	return map[string]interface{}{"values": hexValues}, nil
}

// store saves a value under a key with optional TTL
func (h *JSONRPCHandler) store(params interface{}) (interface{}, error) {
	var paramsStruct struct {
		Key   string `json:"key"`
		Value string `json:"value"`
		TTL   uint16 `json:"ttl"`
	}
	if err := h.parseParams(params, &paramsStruct); err != nil {
		return nil, err
	}
	if paramsStruct.Key == "" || paramsStruct.Value == "" {
		return nil, errors.New("missing key or value parameter")
	}
	keyBytes, err := hex.DecodeString(paramsStruct.Key)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %v", err)
	}
	valueBytes, err := hex.DecodeString(paramsStruct.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid value: %v", err)
	}
	var key Key
	copy(key[:], keyBytes)
	h.server.store.Put(key, valueBytes, paramsStruct.TTL)
	return map[string]string{"status": "stored"}, nil
}

// parseParams safely converts interface{} params into a target struct or slice
func (h *JSONRPCHandler) parseParams(params interface{}, target interface{}) error {
	if params == nil {
		return errors.New("missing parameters")
	}
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("invalid parameters: %v", err)
	}
	return json.Unmarshal(data, target)
}
