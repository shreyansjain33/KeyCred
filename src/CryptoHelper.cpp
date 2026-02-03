//
// CryptoHelper.cpp - AES-256-GCM encryption using Windows CNG
//

#include "CryptoHelper.h"

//
// GenerateSalt - Generate random bytes for hmac-secret salt
//
HRESULT CryptoHelper::GenerateSalt(std::vector<BYTE>& salt) {
    salt.resize(SALT_SIZE);

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        salt.data(),
        SALT_SIZE,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!BCRYPT_SUCCESS(status)) {
        salt.clear();
        return HRESULT_FROM_NT(status);
    }

    return S_OK;
}

//
// Encrypt - AES-256-GCM encryption
//
HRESULT CryptoHelper::Encrypt(
    const BYTE* plaintext,
    DWORD plaintextSize,
    const BYTE* key,
    std::vector<BYTE>& encryptedData)
{
    if (!plaintext || plaintextSize == 0 || !key) {
        return E_INVALIDARG;
    }

    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    // Output format: nonce (12) || ciphertext (plaintextSize) || tag (16)
    encryptedData.clear();

    do {
        // Open AES algorithm provider
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_AES_ALGORITHM,
            nullptr,
            0);

        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Set GCM chaining mode
        status = BCryptSetProperty(
            hAlg,
            BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            sizeof(BCRYPT_CHAIN_MODE_GCM),
            0);

        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Generate key object
        status = BCryptGenerateSymmetricKey(
            hAlg,
            &hKey,
            nullptr, 0,
            (PUCHAR)key,
            KEY_SIZE,
            0);

        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Generate random nonce
        std::vector<BYTE> nonce(NONCE_SIZE);
        status = BCryptGenRandom(nullptr, nonce.data(), NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Setup auth info for GCM
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = nonce.data();
        authInfo.cbNonce = NONCE_SIZE;
        authInfo.pbTag = nullptr;  // Will be set after encryption
        authInfo.cbTag = TAG_SIZE;

        // Allocate tag buffer
        std::vector<BYTE> tag(TAG_SIZE);
        authInfo.pbTag = tag.data();

        // Allocate ciphertext buffer
        std::vector<BYTE> ciphertext(plaintextSize);
        DWORD ciphertextSize = 0;

        // Encrypt
        status = BCryptEncrypt(
            hKey,
            (PUCHAR)plaintext,
            plaintextSize,
            &authInfo,
            nullptr, 0,
            ciphertext.data(),
            (DWORD)ciphertext.size(),
            &ciphertextSize,
            0);

        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Build output: nonce || ciphertext || tag
        encryptedData.reserve(NONCE_SIZE + ciphertextSize + TAG_SIZE);
        encryptedData.insert(encryptedData.end(), nonce.begin(), nonce.end());
        encryptedData.insert(encryptedData.end(), ciphertext.begin(), ciphertext.begin() + ciphertextSize);
        encryptedData.insert(encryptedData.end(), tag.begin(), tag.end());

        hr = S_OK;

    } while (false);

    // Cleanup
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return hr;
}

//
// Decrypt - AES-256-GCM decryption
//
HRESULT CryptoHelper::Decrypt(
    const std::vector<BYTE>& encryptedData,
    const BYTE* key,
    std::vector<BYTE>& plaintext)
{
    // Minimum size: nonce (12) + tag (16) = 28 bytes
    if (encryptedData.size() < NONCE_SIZE + TAG_SIZE || !key) {
        return E_INVALIDARG;
    }

    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    plaintext.clear();

    do {
        // Open AES algorithm provider
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_AES_ALGORITHM,
            nullptr,
            0);

        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Set GCM chaining mode
        status = BCryptSetProperty(
            hAlg,
            BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            sizeof(BCRYPT_CHAIN_MODE_GCM),
            0);

        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Generate key object
        status = BCryptGenerateSymmetricKey(
            hAlg,
            &hKey,
            nullptr, 0,
            (PUCHAR)key,
            KEY_SIZE,
            0);

        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Extract nonce, ciphertext, and tag
        DWORD ciphertextSize = (DWORD)encryptedData.size() - NONCE_SIZE - TAG_SIZE;
        
        const BYTE* nonce = encryptedData.data();
        const BYTE* ciphertext = encryptedData.data() + NONCE_SIZE;
        const BYTE* tag = encryptedData.data() + NONCE_SIZE + ciphertextSize;

        // Setup auth info for GCM
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)nonce;
        authInfo.cbNonce = NONCE_SIZE;
        authInfo.pbTag = (PUCHAR)tag;
        authInfo.cbTag = TAG_SIZE;

        // Allocate plaintext buffer
        plaintext.resize(ciphertextSize);
        DWORD plaintextSize = 0;

        // Decrypt
        status = BCryptDecrypt(
            hKey,
            (PUCHAR)ciphertext,
            ciphertextSize,
            &authInfo,
            nullptr, 0,
            plaintext.data(),
            (DWORD)plaintext.size(),
            &plaintextSize,
            0);

        if (!BCRYPT_SUCCESS(status)) {
            plaintext.clear();
            hr = HRESULT_FROM_NT(status);
            break;
        }

        plaintext.resize(plaintextSize);
        hr = S_OK;

    } while (false);

    // Cleanup
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return hr;
}

//
// EncryptPassword - Encrypt a password string
//
HRESULT CryptoHelper::EncryptPassword(
    PCWSTR password,
    const BYTE* key,
    std::vector<BYTE>& encryptedData)
{
    if (!password || !key) {
        return E_INVALIDARG;
    }

    // Convert password to bytes (including null terminator for easier decryption)
    DWORD passwordBytes = (DWORD)((wcslen(password) + 1) * sizeof(WCHAR));

    return Encrypt((const BYTE*)password, passwordBytes, key, encryptedData);
}

//
// DecryptPassword - Decrypt to a password string
//
HRESULT CryptoHelper::DecryptPassword(
    const std::vector<BYTE>& encryptedData,
    const BYTE* key,
    SecureString& password)
{
    std::vector<BYTE> plaintext;
    HRESULT hr = Decrypt(encryptedData, key, plaintext);

    if (FAILED(hr)) {
        return hr;
    }

    if (plaintext.empty()) {
        return E_FAIL;
    }

    // The plaintext should be a null-terminated wide string
    password.Set((const WCHAR*)plaintext.data());

    // Securely clear plaintext
    SecureZeroMemory(plaintext.data(), plaintext.size());

    return S_OK;
}
