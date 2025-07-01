import init, { PaillierWasm } from './pkg/fast_paillier.js';

async function run() {
    await init();

    const paillier = new PaillierWasm();

    // Display modulus bits
    document.getElementById('n-bits').textContent = paillier.n_bits;

    // Encrypt button
    document.getElementById('encrypt-btn').addEventListener('click', () => {
        const plaintext = document.getElementById('plaintext-input').value.trim();
        if (!plaintext) return;
        try {
            const ct = paillier.encrypt(plaintext);
            document.getElementById('ciphertext-output').value = ct;
        } catch (err) {
            alert(`Encryption failed: ${err}`);
        }
    });

    // Decrypt button
    document.getElementById('decrypt-btn').addEventListener('click', () => {
        const ciphertext = document.getElementById('ciphertext-input').value.trim();
        if (!ciphertext) return;
        try {
            const pt = paillier.decrypt(ciphertext);
            document.getElementById('plaintext-output').textContent = pt;
        } catch (err) {
            alert(`Decryption failed: ${err}`);
        }
    });
}

run(); 
