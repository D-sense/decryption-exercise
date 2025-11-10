# Go Software Backend Engineer Coding Exercise

A Go implementation demonstrating AES decryption, JSON processing, SHA256 hashing, and JWT token creation using HMAC.

## Project Overview

This project implements a cryptographic workflow that:
1. Decrypts AES-encrypted text using a passphrase
2. Creates a JSON object with the decrypted text
3. Generates a SHA256 hash of the JSON string
4. Creates a JWT token using HMAC-SHA256 with the passphrase


## Installation

### Prerequisites
- Go 1.24 or later
- Go modules enabled

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd lloyds-exercise
```

2. Ensure Go modules are enabled:
```bash
export GO111MODULE=on
```

3. Install dependencies:
```bash
go mod tidy
```

## Usage

### Run the Main Program

```bash
go run main.go
```


## Testing

### Run All Tests

```bash
go test ./...
```

### Run Tests with Verbose Output

```bash
go test -v ./...
```

### Run Tests for Specific Package

```bash
# Test decrypt package
go test -v ./decrypt

# Test jwt package
go test -v ./jwt

# Test main package
go test -v .
```

### Test Coverage

```bash
go test -cover ./...
```


## Tutorial

For a detailed, step-by-step explanation of how the `decrypt` and `jwt` packages work internally, see [TUTORIAL](https://go-cookbook.com/snippets/cryptography/encryption-and-decryption). The tutorial covers:

- How AES decryption works (base64 decoding, key derivation, IV extraction, CFB mode)
- How JWT creation works (header/payload encoding, HMAC signing)
- Visual flow diagrams
- Real-world examples
- Security considerations

## AI Assistant Disclaimer
AI Assistant: Claude Code was used to help improve the README.md file 
