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

package main

import (
	"log"

	"github.com/sphinx-core/go/src/rpc"
)

func main() {
	// Add transaction
	resp, err := rpc.CallRPC("127.0.0.1:30303", "add_transaction", `{"from":"Alice","to":"Bob","amount":100}`)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Add transaction: %v", resp)

	// Get block count
	resp, err = rpc.CallRPC("127.0.0.1:30303", "getblockcount", "")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Block count: %v", resp)

	// Get best block hash
	resp, err = rpc.CallRPC("127.0.0.1:30303", "getbestblockhash", "")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Best block hash: %v", resp)

	// Get block by hash
	hash := resp.Result.(string)
	resp, err = rpc.CallRPC("127.0.0.1:30303", "getblock", `"`+hash+`"`)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Block: %v", resp)
}
