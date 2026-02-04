#pragma once

#include "common.h"
#include <ncrypt.h>

//
// TpmCrypto - TPM-backed encryption using Windows CNG
//
// Uses NCrypt to create a TPM-protected RSA key for wrapping an AES key.
// The AES key encrypts the actual password. This provides hardware-backed
// security - the key cannot be extracted even with admin access.
//
class TpmCrypto {
public:
    TpmCrypto();
    ~TpmCrypto();

    // Initialize - opens the TPM storage provider
    HRESULT Initialize();

    // Check if TPM is available
    BOOL IsAvailable() const { return m_isAvailable; }

    // Create or open a persistent TPM key for this user
    // keyName should be unique per user (e.g., "TitanKeyCP_<UserSID>")
    HRESULT OpenOrCreateKey(PCWSTR keyName);

    // Encrypt data using TPM-protected key
    // Internally: generates AES key, encrypts data, wraps AES key with TPM RSA
    // Output format: wrapped_aes_key_len(4) || wrapped_aes_key || nonce(12) || ciphertext || tag(16)
    HRESULT Encrypt(
        const BYTE* plaintext,
        DWORD plaintextSize,
        std::vector<BYTE>& encryptedBlob);

    // Decrypt data using TPM-protected key
    HRESULT Decrypt(
        const std::vector<BYTE>& encryptedBlob,
        std::vector<BYTE>& plaintext);

    // Encrypt a password string
    HRESULT EncryptPassword(PCWSTR password, std::vector<BYTE>& encryptedBlob);

    // Decrypt to a password string
    HRESULT DecryptPassword(const std::vector<BYTE>& encryptedBlob, SecureString& password);

    // Delete the persistent key (currently open)
    HRESULT DeleteKey();

    // Delete a key by name (static - doesn't require open key)
    static HRESULT DeleteKeyByName(PCWSTR keyName);

    // Close handles
    void Close();

private:
    // AES-256-GCM encryption with a given key
    HRESULT AesGcmEncrypt(
        const BYTE* key,
        DWORD keySize,
        const BYTE* plaintext,
        DWORD plaintextSize,
        std::vector<BYTE>& output);  // nonce || ciphertext || tag

    // AES-256-GCM decryption
    HRESULT AesGcmDecrypt(
        const BYTE* key,
        DWORD keySize,
        const BYTE* encryptedData,
        DWORD encryptedDataSize,
        std::vector<BYTE>& plaintext);

    NCRYPT_PROV_HANDLE m_hProvider;
    NCRYPT_KEY_HANDLE m_hKey;
    BOOL m_isAvailable;
    std::wstring m_keyName;

    static constexpr DWORD AES_KEY_SIZE = 32;    // 256 bits
    static constexpr DWORD AES_NONCE_SIZE = 12;  // 96 bits for GCM
    static constexpr DWORD AES_TAG_SIZE = 16;    // 128 bits
};
