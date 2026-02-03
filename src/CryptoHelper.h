#pragma once

#include "common.h"

//
// CryptoHelper - AES-256-GCM encryption/decryption using Windows CNG
//
// This class provides encryption using a key derived from the Titan Key's
// hmac-secret extension, ensuring only the specific hardware key can decrypt.
//
class CryptoHelper {
public:
    // Salt size for hmac-secret
    static constexpr DWORD SALT_SIZE = 32;
    
    // AES-256-GCM parameters
    static constexpr DWORD KEY_SIZE = 32;      // 256 bits
    static constexpr DWORD NONCE_SIZE = 12;    // 96 bits (standard for GCM)
    static constexpr DWORD TAG_SIZE = 16;      // 128 bits

    // Generate a random salt for hmac-secret
    static HRESULT GenerateSalt(std::vector<BYTE>& salt);

    // Encrypt data using AES-256-GCM
    // Input: plaintext, 32-byte key (from hmac-secret)
    // Output: nonce || ciphertext || tag
    static HRESULT Encrypt(
        const BYTE* plaintext,
        DWORD plaintextSize,
        const BYTE* key,        // 32-byte key from hmac-secret
        std::vector<BYTE>& encryptedData);

    // Decrypt data using AES-256-GCM
    // Input: nonce || ciphertext || tag, 32-byte key
    // Output: plaintext
    static HRESULT Decrypt(
        const std::vector<BYTE>& encryptedData,
        const BYTE* key,        // 32-byte key from hmac-secret
        std::vector<BYTE>& plaintext);

    // Encrypt a password string
    static HRESULT EncryptPassword(
        PCWSTR password,
        const BYTE* key,
        std::vector<BYTE>& encryptedData);

    // Decrypt to a password string
    static HRESULT DecryptPassword(
        const std::vector<BYTE>& encryptedData,
        const BYTE* key,
        SecureString& password);
};
