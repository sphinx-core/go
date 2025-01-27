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

package multisig

import (
	"fmt"
	"sync"
)

// RecoveryKey allows Alice to recover her wallet using proofs from other participants.
// The function takes two parameters:
// - message: The message or data that needs to be signed by the participants for wallet recovery.
// - requiredParticipants: A list of participants whose signatures and proofs are required to perform the recovery.
func (m *MultisigManager) RecoveryKey(message []byte, requiredParticipants []string) ([]byte, error) {
	// Step 1: Lock the mutex to ensure thread-safety during recovery.
	m.mu.Lock()
	defer m.mu.Unlock()

	// Step 2: Initialize a channel to collect signatures and proofs from goroutines.
	proofChan := make(chan []byte, len(requiredParticipants))

	// Step 3: Initialize a WaitGroup to synchronize goroutines.
	var wg sync.WaitGroup

	// Step 4: Loop through each participant in the requiredParticipants list.
	for _, partyID := range requiredParticipants {
		wg.Add(1)
		go func(partyID string) {
			defer wg.Done()

			// Step 5: Check if the participant has signed the message.
			sig, exists := m.signatures[partyID]
			if !exists {
				return // no signature found for participant, skip this goroutine
			}

			// Step 6: Check if the proof for the participant exists.
			proof, exists := m.proofs[partyID]
			if !exists {
				return // no proof found for participant, skip this goroutine
			}

			// Step 7: Validate the proof for the participant.
			valid, err := m.ValidateProof(partyID, message)
			if err != nil || !valid {
				return // invalid proof, skip this goroutine
			}

			// Step 8: Send the combined signature and proof to the channel.
			proofChan <- append(sig, proof...)
		}(partyID)
	}

	// Step 9: Wait for all goroutines to finish processing.
	wg.Wait()

	// Step 10: Close the channel after all goroutines are done.
	close(proofChan)

	// Step 11: Combine the results from the channel into a single recovery proof slice.
	var finalProof []byte
	for proof := range proofChan {
		finalProof = append(finalProof, proof...)
	}

	// Step 12: Check if enough signatures have been collected to meet the quorum.
	if len(finalProof) < m.quorum {
		return nil, fmt.Errorf("not enough signatures to recover the wallet, need at least %d signatures", m.quorum)
	}

	// Step 13: Return the recovery proof.
	return finalProof, nil
}
