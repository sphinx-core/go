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

package sips3

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/sphinx-core/go/src/common"
	"golang.org/x/crypto/argon2"
)

// Argon2 parameters
// OWASP have published guidance on Argon2 at https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
// At time of writing (Jan 2023), this says:
// Argon2id should use one of the following configuration settings as a base minimum which includes the minimum memory size (m), the minimum number of iterations (t) and the degree of parallelism (p).
// m=37 MiB, t=1, p=1
// m=15 MiB, t=2, p=1
// Both of these configuration settings are equivalent in the defense they provide. The only difference is a trade off between CPU and RAM usage.
const (
	memory      = 64 * 1024 // Memory cost set to 64 KiB (64 * 1024 bytes) is for demonstration purpose
	iterations  = 2         // Number of iterations for Argon2id set to 2
	parallelism = 1         // Degree of parallelism set to 1
	tagSize     = 32        // Tag size set to 256 bits (32 bytes)
)

var (
	mu               sync.Mutex              // Ensures thread-safe access to shared resources
	passphraseHashes = map[string]struct{}{} // Stores hashes of generated passphrases (used database in production)
)

// GitHubFile represents the structure of file information returned by GitHub's API
type GitHubFile struct {
	Name string `json:"name"` // Name of the file
	Path string `json:"path"` // Path to the file in the repository
	Type string `json:"type"` // Type of the file (e.g., file, directory)
}

// Base URL for accessing the repository directory on GitHub (HTTPS version)
const baseURL = "https://api.github.com/repos/sphinx-core/sips/contents/.github/workflows/sips0003"

// FetchFileList fetches the list of files from a specified URL
func FetchFileList(url string) ([]GitHubFile, error) {
	resp, err := http.Get(url) // Sends an HTTP GET request to the specified URL
	if err != nil {
		return nil, fmt.Errorf("failed to fetch file list: %w", err) // Returns an error if the request fails
	}
	defer resp.Body.Close() // Ensures the response body is closed after function execution

	if resp.StatusCode != http.StatusOK { // Checks if the HTTP status is OK (200)
		return nil, fmt.Errorf("unexpected response: %s", resp.Status) // Returns an error for unexpected responses
	}

	var files []GitHubFile                                            // Declares a slice to store file information
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil { // Decodes the JSON response into the slice
		return nil, fmt.Errorf("failed to decode response: %w", err) // Returns an error if decoding fails
	}

	return files, nil // Returns the list of files
}

// SelectAndLoadTxtFile selects a random .txt file and loads its content
func SelectAndLoadTxtFile(url string) ([]string, error) {
	files, err := FetchFileList(url) // Fetches the list of files from the repository
	if err != nil {
		return nil, err // Returns an error if file fetching fails
	}

	// Filters the files to include only those with a .txt extension
	var txtFiles []GitHubFile
	for _, file := range files {
		if strings.HasSuffix(file.Name, ".txt") { // Checks if the file name ends with .txt
			txtFiles = append(txtFiles, file) // Adds the .txt file to the list
		}
	}

	if len(txtFiles) == 0 { // Checks if no .txt files were found
		return nil, errors.New("no .txt files found in the directory") // Returns an error
	}

	// Selects a random .txt file from the list
	var selectedFile GitHubFile
	if len(txtFiles) > 0 { // Check if there are any files
		randIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(txtFiles)))) // Generates a random index
		selectedFile = txtFiles[randIndex.Int64()]                              // Selects the file at the random index
	} else {
		return nil, errors.New("no .txt files found") // Error if no files are found
	}

	// Constructs the URL for fetching the raw content of the selected file
	rawBaseURL := "https://raw.githubusercontent.com/sphinx-core/sips/main/.github/workflows/sips0003/" // Changed to HTTPS
	fileURL := rawBaseURL + selectedFile.Name

	// Fetches the content of the selected file
	resp, err := http.Get(fileURL) // Sends an HTTP GET request to the file URL
	if err != nil {
		return nil, fmt.Errorf("failed to fetch file content: %w", err) // Returns an error if the request fails
	}
	defer resp.Body.Close() // Ensures the response body is closed after function execution

	body, err := io.ReadAll(resp.Body) // Reads the response body
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %w", err) // Returns an error if reading fails
	}

	// Splits the content into individual words and trims whitespace
	var words []string
	for _, word := range strings.Split(string(body), "\n") {
		trimmedWord := strings.TrimSpace(word) // Removes leading/trailing whitespace
		if trimmedWord != "" {                 // Ignores empty lines
			words = append(words, trimmedWord) // Adds the word to the list
		}
	}

	return words, nil // Returns the list of words
}

// GeneratePassphrase creates a secure passphrase using a given word list
func GeneratePassphrase(words []string, wordCount int) (string, string, error) {
	// Check if the word list is empty; if so, return an error
	if len(words) == 0 {
		return "", "", errors.New("word list is empty")
	}

	var passphrase []string
	// Loop to generate a passphrase by selecting random words from the word list
	for i := 0; i < wordCount; i++ {
		// Generate a random index to pick a word from the list
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			// Return an error if random index generation fails
			return "", "", fmt.Errorf("failed to generate random index: %w", err)
		}
		// Append the selected word to the passphrase slice
		passphrase = append(passphrase, words[randIndex.Int64()])
	}

	// Join the words in the passphrase slice into a single string separated by spaces
	passphraseStr := strings.Join(passphrase, " ")

	// Create a slice to hold the 16-byte nonce
	nonce := make([]byte, 16)
	// Generate random bytes to populate the nonce
	if _, err := rand.Read(nonce); err != nil {
		// Return an error if nonce generation fails
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Convert the passphrase string to a byte slice for encoding
	passphraseBytes := []byte(passphraseStr)
	// Check if the byte slice is valid UTF-8
	if !utf8.Valid(passphraseBytes) {
		// Return an error if the passphrase contains invalid UTF-8 characters
		return "", "", errors.New("invalid UTF-8 encoding in passphrase")
	}

	// Use the generated passphrase as part of the salt (to stretch)
	salt := "mnemonic" + passphraseStr
	// Convert the salt string to a byte slice for encoding
	saltBytes := []byte(salt)

	// Use SpxHash from the common package to generate a hash (256-bit)
	hash := common.SpxHash([]byte(passphraseStr))

	// Append the hash to the salt or use it directly in the stretching process
	extendedSalt := append(saltBytes, hash...) // Combine salt and hash

	// Use Argon2 IDKey to stretch the passphrase and salt into a fixed-length hash
	stretchedHash := argon2.IDKey(passphraseBytes, extendedSalt, iterations, memory, parallelism, tagSize)
	// Convert the stretched hash to a hexadecimal string representation
	stretchedHashStr := fmt.Sprintf("%x", stretchedHash)

	// Lock the mutex to ensure thread safety when accessing shared data
	mu.Lock()
	defer mu.Unlock()
	// Check if the generated hash already exists in the hash map
	if _, exists := passphraseHashes[stretchedHashStr]; exists {
		// Return an error if a duplicate passphrase is detected
		return "", "", errors.New("duplicate passphrase detected, regenerate")
	}

	// Store the hash in the map to avoid future duplicates
	passphraseHashes[stretchedHashStr] = struct{}{}

	return passphraseStr, stretchedHashStr, nil // Return the generated passphrase and stretched hash
}

// isValidEntropy checks if the entropy is a valid multiple of 32 bits and within the allowed range.
func isValidEntropy(entropy int) bool {
	validEntropies := []int{128, 160, 192, 224, 256}
	for _, e := range validEntropies {
		if entropy == e {
			return true
		}
	}
	return false
}

// NewMnemonic generates a mnemonic from any .txt file in the directory
func NewMnemonic(entropy int) (string, string, error) {
	// Validate the entropy
	if !isValidEntropy(entropy) {
		return "", "", errors.New("invalid entropy: must be one of 128, 160, 192, 224, or 256")
	}

	// Adjust word count to 12, 15, 18, 21, or 24 based on entropy and checksum
	var wordCount int
	switch entropy {
	case 128:
		wordCount = 12
	case 160:
		wordCount = 15
	case 192:
		wordCount = 18
	case 224:
		wordCount = 21
	case 256:
		wordCount = 24
	}

	words, err := SelectAndLoadTxtFile(baseURL) // Loads the word list from the repository
	if err != nil {
		return "", "", fmt.Errorf("failed to load words: %w", err) // Returns an error if loading fails
	}

	passphrase, nonce, err := GeneratePassphrase(words, wordCount) // Generates a passphrase using the word list
	if err != nil {
		return "", "", fmt.Errorf("failed to generate passphrase: %w", err) // Returns an error if generation fails
	}

	return passphrase, nonce, nil // Returns the generated passphrase and nonce
}
