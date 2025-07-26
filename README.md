# Recon - a trash encryption library

### Overview:
- C++17
- Cross-platform
- string encryption only for now
- most thiongs are automatic, just manage encryption and decryption by yourself.
- Use this for testing stuff, but you should use proper encryption frameworks like Crypto++, OpenSSL, libSodium etc.

### How it works:
- **Key and IV Generation**: 256 bit key + 128 bit iv is **randomly and automatically generated.**

- **Encryption**: strings are is XORed with the key and IV, shifted, substituted via a randomized S-Box like AES uses, and HMAC'd.

- **Decryption**: The HMAC is verified before inverting the substitution and transformation. If tampering is detected, decryption is rejected.

- **Any security?**: key reuse, padding oracle etc. attacks shouldn't work. AES key scanners shouldn't work either. The custom HMAC also makes sure that the ciphertext can't be modified.

### Usage:
See [`main.cpp`](./main.cpp) for an example.
