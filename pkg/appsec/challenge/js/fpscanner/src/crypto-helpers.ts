/**
 * Simple and fast XOR-based encryption/decryption
 * Note: This is NOT cryptographically secure - use only for obfuscation
 */

/**
 * Encrypts a string using XOR cipher with the provided key
 * @param plaintext - The string to encrypt
 * @param key - The encryption key as a string
 * @returns Encrypted string (base64 encoded)
 */
export async function encryptString(plaintext: string, key: string): Promise<string> {
    const keyBytes = new TextEncoder().encode(key);
    const textBytes = new TextEncoder().encode(plaintext);
    const encrypted = new Uint8Array(textBytes.length);

    for (let i = 0; i < textBytes.length; i++) {
        encrypted[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
    }

    // Convert to base64 for safe string representation
    const binaryString = String.fromCharCode(...encrypted);
    return btoa(binaryString);
}

/**
 * Decrypts a string that was encrypted with encryptString
 * @param ciphertext - The encrypted string (base64 encoded)
 * @param key - The decryption key as a string (must match encryption key)
 * @returns Decrypted string
 */
export async function decryptString(ciphertext: string, key: string): Promise<string> {
    // Decode from base64
    const binaryString = atob(ciphertext);
    const encrypted = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        encrypted[i] = binaryString.charCodeAt(i);
    }

    const keyBytes = new TextEncoder().encode(key);
    const decrypted = new Uint8Array(encrypted.length);

    // XOR is symmetric, so decryption is the same as encryption
    for (let i = 0; i < encrypted.length; i++) {
        decrypted[i] = encrypted[i] ^ keyBytes[i % keyBytes.length];
    }

    return new TextDecoder().decode(decrypted);
}

