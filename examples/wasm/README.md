# Fast Paillier WASM Example

This example demonstrates using the Fast Paillier library in WebAssembly.

## Features

- Create encryption/decryption keys
- Encrypt/decrypt messages
- Use precomputed tables for faster encryption
- Perform homomorphic operations (addition, scalar multiplication)

## Requirements

- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [Node.js](https://nodejs.org/)

## Building and Running

1. Install wasm-pack if you haven't already:
   ```
   curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
   ```

2. Navigate to the example directory:
   ```
   cd examples/wasm
   ```

3. Install dependencies:
   ```
   npm install
   ```

4. Build the WASM module:
   ```
   npm run build
   ```

5. Start the local server:
   ```
   npm run serve
   ```

6. Open a browser and navigate to http://localhost:3000

## How to Use

1. Click "Initialize Paillier" to create encryption and decryption keys
2. Optionally, click "Create Precomputed Table" to enable faster encryption
3. Enter a plaintext number and encrypt it
4. Try decrypting the ciphertext
5. Test homomorphic operations with the generated ciphertexts 
