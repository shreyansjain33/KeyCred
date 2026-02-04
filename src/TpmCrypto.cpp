//
// TpmCrypto.cpp - TPM-backed encryption using Windows CNG
//

#include "TpmCrypto.h"

// TPM Platform Crypto Provider
static const WCHAR* TPM_PROVIDER = MS_PLATFORM_CRYPTO_PROVIDER;
// Fallback to software provider if no TPM
static const WCHAR* SOFTWARE_PROVIDER = MS_KEY_STORAGE_PROVIDER;

TpmCrypto::TpmCrypto()
    : m_hProvider(0)
    , m_hKey(0)
    , m_isAvailable(FALSE)
{
    TITAN_LOG(L"TpmCrypto created");
}

TpmCrypto::~TpmCrypto() {
    Close();
    TITAN_LOG(L"TpmCrypto destroyed");
}

//
// Initialize - Open the TPM storage provider
//
HRESULT TpmCrypto::Initialize() {
    TITAN_LOG(L"TpmCrypto::Initialize");

    if (m_hProvider) {
        return S_OK;  // Already initialized
    }

    // Try TPM provider first
    SECURITY_STATUS status = NCryptOpenStorageProvider(&m_hProvider, TPM_PROVIDER, 0);
    
    if (SUCCEEDED(status)) {
        m_isAvailable = TRUE;
        TITAN_LOG(L"TPM provider opened successfully");
        return S_OK;
    }

    TITAN_LOG(L"TPM not available, falling back to software provider");

    // Fallback to software key storage
    status = NCryptOpenStorageProvider(&m_hProvider, SOFTWARE_PROVIDER, 0);
    
    if (SUCCEEDED(status)) {
        m_isAvailable = TRUE;
        TITAN_LOG(L"Software provider opened successfully");
        return S_OK;
    }

    TITAN_LOG_HR(L"Failed to open any storage provider", status);
    return HRESULT_FROM_WIN32(status);
}

//
// OpenOrCreateKey - Create or open a persistent RSA key
//
// IMPORTANT: Uses NCRYPT_MACHINE_KEY_FLAG to store key in machine-wide store.
// This is required because credential providers run as SYSTEM on the lock screen
// and cannot access user-specific key stores.
//
HRESULT TpmCrypto::OpenOrCreateKey(PCWSTR keyName) {
    TITAN_LOG(L"TpmCrypto::OpenOrCreateKey");

    if (!m_hProvider) {
        return E_FAIL;
    }

    if (!keyName || !*keyName) {
        return E_INVALIDARG;
    }

    m_keyName = keyName;

    // Try to open existing key first (from machine key store)
    SECURITY_STATUS status = NCryptOpenKey(
        m_hProvider,
        &m_hKey,
        keyName,
        0,
        NCRYPT_MACHINE_KEY_FLAG);  // Use machine key store

    if (SUCCEEDED(status)) {
        TITAN_LOG(L"Opened existing TPM key from machine store");
        return S_OK;
    }

    // Key doesn't exist, create new one in machine key store
    TITAN_LOG(L"Creating new TPM key in machine store");

    status = NCryptCreatePersistedKey(
        m_hProvider,
        &m_hKey,
        NCRYPT_RSA_ALGORITHM,
        keyName,
        0,
        NCRYPT_MACHINE_KEY_FLAG);  // Use machine key store

    if (FAILED(status)) {
        TITAN_LOG_HR(L"NCryptCreatePersistedKey failed", status);
        return HRESULT_FROM_WIN32(status);
    }

    // Set key size to 2048 bits
    DWORD keySize = 2048;
    status = NCryptSetProperty(
        m_hKey,
        NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&keySize,
        sizeof(keySize),
        0);

    if (FAILED(status)) {
        NCryptFreeObject(m_hKey);
        m_hKey = 0;
        TITAN_LOG_HR(L"NCryptSetProperty (key size) failed", status);
        return HRESULT_FROM_WIN32(status);
    }

    // Set export policy - not exportable
    DWORD exportPolicy = 0;
    status = NCryptSetProperty(
        m_hKey,
        NCRYPT_EXPORT_POLICY_PROPERTY,
        (PBYTE)&exportPolicy,
        sizeof(exportPolicy),
        0);

    if (FAILED(status)) {
        NCryptFreeObject(m_hKey);
        m_hKey = 0;
        TITAN_LOG_HR(L"NCryptSetProperty (export policy) failed", status);
        return HRESULT_FROM_WIN32(status);
    }

    // Finalize the key
    status = NCryptFinalizeKey(m_hKey, 0);

    if (FAILED(status)) {
        NCryptFreeObject(m_hKey);
        m_hKey = 0;
        TITAN_LOG_HR(L"NCryptFinalizeKey failed", status);
        return HRESULT_FROM_WIN32(status);
    }

    TITAN_LOG(L"TPM key created successfully in machine store");
    return S_OK;
}

//
// Encrypt - Encrypt data using TPM-protected key
//
HRESULT TpmCrypto::Encrypt(
    const BYTE* plaintext,
    DWORD plaintextSize,
    std::vector<BYTE>& encryptedBlob)
{
    TITAN_LOG(L"TpmCrypto::Encrypt");

    if (!m_hKey || !plaintext || plaintextSize == 0) {
        return E_INVALIDARG;
    }

    encryptedBlob.clear();
    HRESULT hr = S_OK;

    // Generate random AES-256 key
    BYTE aesKey[AES_KEY_SIZE];
    NTSTATUS status = BCryptGenRandom(nullptr, aesKey, AES_KEY_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        return HRESULT_FROM_NT(status);
    }

    do {
        // Setup OAEP padding info (required for NCRYPT_PAD_OAEP_FLAG)
        BCRYPT_OAEP_PADDING_INFO oaepInfo = { 0 };
        oaepInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        oaepInfo.pbLabel = nullptr;
        oaepInfo.cbLabel = 0;

        // Wrap (encrypt) the AES key with TPM RSA key
        DWORD wrappedKeySize = 0;
        SECURITY_STATUS secStatus = NCryptEncrypt(
            m_hKey,
            aesKey,
            AES_KEY_SIZE,
            &oaepInfo,
            nullptr,
            0,
            &wrappedKeySize,
            NCRYPT_PAD_OAEP_FLAG);

        if (FAILED(secStatus)) {
            hr = HRESULT_FROM_WIN32(secStatus);
            break;
        }

        std::vector<BYTE> wrappedKey(wrappedKeySize);
        secStatus = NCryptEncrypt(
            m_hKey,
            aesKey,
            AES_KEY_SIZE,
            &oaepInfo,
            wrappedKey.data(),
            wrappedKeySize,
            &wrappedKeySize,
            NCRYPT_PAD_OAEP_FLAG);

        if (FAILED(secStatus)) {
            hr = HRESULT_FROM_WIN32(secStatus);
            break;
        }

        // Encrypt the plaintext with AES-GCM
        std::vector<BYTE> aesEncrypted;
        hr = AesGcmEncrypt(aesKey, AES_KEY_SIZE, plaintext, plaintextSize, aesEncrypted);
        if (FAILED(hr)) {
            break;
        }

        // Build output: wrapped_key_len(4) || wrapped_key || aes_encrypted
        encryptedBlob.reserve(4 + wrappedKeySize + aesEncrypted.size());
        
        // Write wrapped key length (4 bytes, little-endian)
        encryptedBlob.push_back((BYTE)(wrappedKeySize & 0xFF));
        encryptedBlob.push_back((BYTE)((wrappedKeySize >> 8) & 0xFF));
        encryptedBlob.push_back((BYTE)((wrappedKeySize >> 16) & 0xFF));
        encryptedBlob.push_back((BYTE)((wrappedKeySize >> 24) & 0xFF));
        
        // Write wrapped key
        encryptedBlob.insert(encryptedBlob.end(), wrappedKey.begin(), wrappedKey.end());
        
        // Write AES-encrypted data
        encryptedBlob.insert(encryptedBlob.end(), aesEncrypted.begin(), aesEncrypted.end());

        hr = S_OK;

    } while (false);

    // Securely clear AES key from memory
    SecureZeroMemory(aesKey, sizeof(aesKey));

    return hr;
}

//
// Decrypt - Decrypt data using TPM-protected key
//
HRESULT TpmCrypto::Decrypt(
    const std::vector<BYTE>& encryptedBlob,
    std::vector<BYTE>& plaintext)
{
    TITAN_LOG(L"TpmCrypto::Decrypt");

    if (!m_hKey || encryptedBlob.size() < 4) {
        return E_INVALIDARG;
    }

    plaintext.clear();
    HRESULT hr = S_OK;
    BYTE aesKey[AES_KEY_SIZE] = { 0 };

    do {
        // Read wrapped key length
        DWORD wrappedKeySize = 
            (DWORD)encryptedBlob[0] |
            ((DWORD)encryptedBlob[1] << 8) |
            ((DWORD)encryptedBlob[2] << 16) |
            ((DWORD)encryptedBlob[3] << 24);

        if (encryptedBlob.size() < 4 + wrappedKeySize + AES_NONCE_SIZE + AES_TAG_SIZE) {
            hr = E_INVALIDARG;
            break;
        }

        // Extract wrapped key
        const BYTE* wrappedKey = encryptedBlob.data() + 4;

        // Setup OAEP padding info (must match encryption)
        BCRYPT_OAEP_PADDING_INFO oaepInfo = { 0 };
        oaepInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        oaepInfo.pbLabel = nullptr;
        oaepInfo.cbLabel = 0;

        // Unwrap AES key using TPM
        DWORD aesKeySize = 0;
        SECURITY_STATUS secStatus = NCryptDecrypt(
            m_hKey,
            const_cast<BYTE*>(wrappedKey),
            wrappedKeySize,
            &oaepInfo,
            nullptr,
            0,
            &aesKeySize,
            NCRYPT_PAD_OAEP_FLAG);

        if (FAILED(secStatus) || aesKeySize != AES_KEY_SIZE) {
            hr = HRESULT_FROM_WIN32(secStatus);
            break;
        }

        secStatus = NCryptDecrypt(
            m_hKey,
            const_cast<BYTE*>(wrappedKey),
            wrappedKeySize,
            &oaepInfo,
            aesKey,
            AES_KEY_SIZE,
            &aesKeySize,
            NCRYPT_PAD_OAEP_FLAG);

        if (FAILED(secStatus)) {
            hr = HRESULT_FROM_WIN32(secStatus);
            break;
        }

        // Extract AES-encrypted data
        const BYTE* aesEncrypted = encryptedBlob.data() + 4 + wrappedKeySize;
        DWORD aesEncryptedSize = (DWORD)encryptedBlob.size() - 4 - wrappedKeySize;

        // Decrypt with AES-GCM
        hr = AesGcmDecrypt(aesKey, AES_KEY_SIZE, aesEncrypted, aesEncryptedSize, plaintext);

    } while (false);

    // Securely clear AES key
    SecureZeroMemory(aesKey, sizeof(aesKey));

    return hr;
}

//
// EncryptPassword - Encrypt a password string
//
HRESULT TpmCrypto::EncryptPassword(PCWSTR password, std::vector<BYTE>& encryptedBlob) {
    if (!password) {
        return E_INVALIDARG;
    }

    DWORD passwordBytes = (DWORD)((wcslen(password) + 1) * sizeof(WCHAR));
    return Encrypt((const BYTE*)password, passwordBytes, encryptedBlob);
}

//
// DecryptPassword - Decrypt to a password string
//
HRESULT TpmCrypto::DecryptPassword(const std::vector<BYTE>& encryptedBlob, SecureString& password) {
    std::vector<BYTE> plaintext;
    HRESULT hr = Decrypt(encryptedBlob, plaintext);

    if (FAILED(hr)) {
        return hr;
    }

    if (plaintext.empty()) {
        return E_FAIL;
    }

    password.Set((const WCHAR*)plaintext.data());
    SecureZeroMemory(plaintext.data(), plaintext.size());

    return S_OK;
}

//
// DeleteKey - Delete the persistent key
//
HRESULT TpmCrypto::DeleteKey() {
    TITAN_LOG(L"TpmCrypto::DeleteKey");

    if (m_hKey) {
        SECURITY_STATUS status = NCryptDeleteKey(m_hKey, 0);
        m_hKey = 0;
        
        if (FAILED(status)) {
            return HRESULT_FROM_WIN32(status);
        }
    }

    return S_OK;
}

//
// Close - Release handles
//
void TpmCrypto::Close() {
    if (m_hKey) {
        NCryptFreeObject(m_hKey);
        m_hKey = 0;
    }

    if (m_hProvider) {
        NCryptFreeObject(m_hProvider);
        m_hProvider = 0;
    }

    m_isAvailable = FALSE;
}

//
// AesGcmEncrypt - AES-256-GCM encryption
//
HRESULT TpmCrypto::AesGcmEncrypt(
    const BYTE* key,
    DWORD keySize,
    const BYTE* plaintext,
    DWORD plaintextSize,
    std::vector<BYTE>& output)
{
    output.clear();

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    HRESULT hr = S_OK;

    do {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, 
            const_cast<PUCHAR>(key), keySize, 0);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Generate nonce
        std::vector<BYTE> nonce(AES_NONCE_SIZE);
        status = BCryptGenRandom(nullptr, nonce.data(), AES_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Setup auth info
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = nonce.data();
        authInfo.cbNonce = AES_NONCE_SIZE;

        std::vector<BYTE> tag(AES_TAG_SIZE);
        authInfo.pbTag = tag.data();
        authInfo.cbTag = AES_TAG_SIZE;

        // Encrypt
        std::vector<BYTE> ciphertext(plaintextSize);
        DWORD ciphertextSize = 0;

        status = BCryptEncrypt(hKey, const_cast<PUCHAR>(plaintext), plaintextSize,
            &authInfo, nullptr, 0, ciphertext.data(), plaintextSize, &ciphertextSize, 0);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Output: nonce || ciphertext || tag
        output.reserve(AES_NONCE_SIZE + ciphertextSize + AES_TAG_SIZE);
        output.insert(output.end(), nonce.begin(), nonce.end());
        output.insert(output.end(), ciphertext.begin(), ciphertext.begin() + ciphertextSize);
        output.insert(output.end(), tag.begin(), tag.end());

    } while (false);

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return hr;
}

//
// AesGcmDecrypt - AES-256-GCM decryption
//
HRESULT TpmCrypto::AesGcmDecrypt(
    const BYTE* key,
    DWORD keySize,
    const BYTE* encryptedData,
    DWORD encryptedDataSize,
    std::vector<BYTE>& plaintext)
{
    plaintext.clear();

    if (encryptedDataSize < AES_NONCE_SIZE + AES_TAG_SIZE) {
        return E_INVALIDARG;
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    HRESULT hr = S_OK;

    do {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key), keySize, 0);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Extract nonce, ciphertext, tag
        DWORD ciphertextSize = encryptedDataSize - AES_NONCE_SIZE - AES_TAG_SIZE;
        const BYTE* nonce = encryptedData;
        const BYTE* ciphertext = encryptedData + AES_NONCE_SIZE;
        const BYTE* tag = encryptedData + AES_NONCE_SIZE + ciphertextSize;

        // Setup auth info
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<PUCHAR>(nonce);
        authInfo.cbNonce = AES_NONCE_SIZE;
        authInfo.pbTag = const_cast<PUCHAR>(tag);
        authInfo.cbTag = AES_TAG_SIZE;

        // Decrypt
        plaintext.resize(ciphertextSize);
        DWORD plaintextSize = 0;

        status = BCryptDecrypt(hKey, const_cast<PUCHAR>(ciphertext), ciphertextSize,
            &authInfo, nullptr, 0, plaintext.data(), ciphertextSize, &plaintextSize, 0);
        if (!BCRYPT_SUCCESS(status)) {
            plaintext.clear();
            hr = HRESULT_FROM_NT(status);
            break;
        }

        plaintext.resize(plaintextSize);

    } while (false);

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return hr;
}
