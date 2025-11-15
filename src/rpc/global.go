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

// go/src/rpc/global.go
package rpc

// Standard JSON-RPC error codes.
const (
	ErrCodeParseError     = -32700 // Invalid JSON
	ErrCodeInvalidRequest = -32600 // Not a valid JSON-RPC request
	ErrCodeMethodNotFound = -32601 // Method does not exist
	ErrCodeInvalidParams  = -32602 // Invalid parameters
	ErrCodeInternalError  = -32603 // Internal server error
)

// RPC message types.
const (
	RPCGetBlockCount RPCType = iota
	RPCGetBestBlockHash
	RPCGetBlock
	RPCGetBlocks
	RPCSendRawTransaction
	RPCGetTransaction
	RPCPing
	RPCJoin
	RPCFindNode
	RPCGet
	RPCStore
	RPCGetBlockByNumber
	RPCGetBlockHash
	RPCGetDifficulty
	RPCGetChainTip
	RPCGetNetworkInfo
	RPCGetMiningInfo
	RPCEstimateFee
	RPCGetMemPoolInfo
	RPCValidateAddress
	RPCVerifyMessage
	RPCGetRawTransaction
)
