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

	types "github.com/sphinx-core/go/src/core/transaction"
	security "github.com/sphinx-core/go/src/handshake"
)

// Standard JSON-RPC error codes.
const (
	ErrCodeParseError     = -32700 // Invalid JSON
	ErrCodeInvalidRequest = -32600 // Not a valid JSON-RPC request
	ErrCodeMethodNotFound = -32601 // Method does not exist
	ErrCodeInvalidParams  = -32602 // Invalid parameters
	ErrCodeInternalError  = -32603 // Internal server error
)

// NewJSONRPCHandler creates a new JSON-RPC handler with registered methods.
func NewJSONRPCHandler(server *Server) *JSONRPCHandler {
	handler := &JSONRPCHandler{
		server:  server,
		methods: make(map[string]RPCHandler),
	}
	handler.registerMethods()
	return handler
}

// registerMethods registers supported RPC methods.
func (h *JSONRPCHandler) registerMethods() {
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
}

// ProcessRequest processes a JSON-RPC request or batch of requests.
func (h *JSONRPCHandler) ProcessRequest(data []byte) ([]byte, error) {
	// Try to parse as a Message (binary format)
	var msg Message
	if err := msg.Unmarshal(data); err == nil {
		return h.processBinaryMessage(msg)
	}

	// Fallback to JSON-RPC
	var singleReq JSONRPCRequest
	if err := json.Unmarshal(data, &singleReq); err == nil && singleReq.JSONRPC == "2.0" {
		return h.processSingleRequest(singleReq)
	}

	// Try to parse as a batch request
	var batchReq []JSONRPCRequest
	if err := json.Unmarshal(data, &batchReq); err == nil && len(batchReq) > 0 {
		return h.processBatchRequest(batchReq)
	}

	return h.errorResponse(nil, ErrCodeParseError, "Parse error: invalid JSON or binary format")
}

// processBinaryMessage handles a binary Message.
func (h *JSONRPCHandler) processBinaryMessage(msg Message) ([]byte, error) {
	start := time.Now()
	method := msg.RPCType.String()
	h.server.metrics.RequestCount.WithLabelValues(method).Inc()
	defer func() {
		h.server.metrics.RequestLatency.WithLabelValues(method).Observe(time.Since(start).Seconds())
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
			continue
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
	default:
		return "unknown"
	}
}

// RPC Method Handlers
func (h *JSONRPCHandler) getBlockCount(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetBlockCount(), nil
}

func (h *JSONRPCHandler) getBestBlockHash(_ interface{}) (interface{}, error) {
	hash := h.server.blockchain.GetBestBlockHash()
	return fmt.Sprintf("%x", hash), nil
}

// rpc/json.go – getBlock method
func (h *JSONRPCHandler) getBlock(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing block hash parameter")
	}
	hashStr := paramsArray[0] // <-- hex string from JSON-RPC
	// Use the new string-based GetBlockByHash (no []byte conversion)
	block := h.server.blockchain.GetBlockByHash(hashStr)
	if block == nil {
		return nil, errors.New("block not found")
	}
	return block, nil
}

func (h *JSONRPCHandler) getBlocks(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetBlocks(), nil
}

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
		tx.ID = tx.Hash()
	}
	if err := h.server.blockchain.AddTransaction(&tx); err != nil {
		return nil, err
	}
	h.server.messageCh <- &security.Message{Type: "transaction", Data: &tx}
	return map[string]string{"txid": tx.ID}, nil
}

func (h *JSONRPCHandler) getTransaction(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing transaction ID parameter")
	}
	txID := paramsArray[0]
	txIDBytes, err := hex.DecodeString(txID)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction ID: %v", err)
	}
	tx, err := h.server.blockchain.GetTransactionByID(txIDBytes)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (h *JSONRPCHandler) ping(params interface{}) (interface{}, error) {
	return map[string]string{"status": "pong"}, nil
}

func (h *JSONRPCHandler) join(params interface{}) (interface{}, error) {
	return map[string]string{"status": "joined"}, nil
}

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
