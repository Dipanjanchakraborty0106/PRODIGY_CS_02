Image Encryption Tool using Pixel Manipulation A simple tool using pixel manipulation, we'll use Python with the Pillow library for image processing. This tool will allow users to encrypt and decrypt images by swapping RGB channels and applying XOR operations with a key. Features 🔒 Basic image encryption/decryption

🎨 RGB channel swapping (red ↔ blue)

🔑 XOR pixel manipulation with custom key

💾 Preserves original image format

🖼️ Supports common image formats (JPG, PNG, BMP) OUTPUT Enter image path: secret_cat.jpg Choose mode (encrypt/decrypt): encrypt Choose operation (1/2/3): 3 Enter encryption key (0-255): 123 Success! Image saved to: secret_cat_encrypted.jpg

Security Notes ⚠️ Important Security Disclaimer This tool provides basic obfuscation only and should NOT be used for sensitive data:

XOR operation has only 256 possible keys (trivial to brute-force)

Swap operation is easily reversible without a key

No protection against advanced cryptanalysis

For real security requirements:

Use industry-standard encryption (AES, etc.)

Encrypt entire files rather than just pixel data

Implement proper key management
