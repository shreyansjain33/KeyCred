//
// CredentialStorage.cpp - Encrypted credential storage using Windows Registry and DPAPI
//

#include "CredentialStorage.h"

// Registry value names
static const WCHAR* VALUE_USERNAME = L"Username";
static const WCHAR* VALUE_DOMAIN = L"Domain";
static const WCHAR* VALUE_ENCRYPTED_PASSWORD = L"EncryptedPassword";
static const WCHAR* VALUE_CREDENTIAL_ID = L"CredentialId";
static const WCHAR* VALUE_PUBLIC_KEY = L"PublicKey";
static const WCHAR* VALUE_RELYING_PARTY_ID = L"RelyingPartyId";

CredentialStorage::CredentialStorage() {
    TITAN_LOG(L"CredentialStorage initialized");
}

CredentialStorage::~CredentialStorage() {
    TITAN_LOG(L"CredentialStorage destroyed");
}

//
// StoreCredential - Store encrypted credentials for a user
//
HRESULT CredentialStorage::StoreCredential(
    PCWSTR userSid,
    PCWSTR username,
    PCWSTR domain,
    PCWSTR password,
    const BYTE* credentialId,
    DWORD credentialIdSize,
    const BYTE* publicKey,
    DWORD publicKeySize,
    PCWSTR relyingPartyId)
{
    TITAN_LOG(L"StoreCredential called");

    if (!userSid || !username || !password) {
        return E_INVALIDARG;
    }

    // Encrypt the password using DPAPI
    std::vector<BYTE> encryptedPassword;
    HRESULT hr = EncryptPassword(password, encryptedPassword);
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"Failed to encrypt password", hr);
        return hr;
    }

    // Open or create the user's registry key
    HKEY hKey = nullptr;
    hr = OpenUserKey(userSid, TRUE, &hKey);
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"Failed to open user key", hr);
        return hr;
    }

    // Store all values
    do {
        hr = WriteStringValue(hKey, VALUE_USERNAME, username);
        if (FAILED(hr)) break;

        hr = WriteStringValue(hKey, VALUE_DOMAIN, domain ? domain : L".");
        if (FAILED(hr)) break;

        hr = WriteBinaryValue(hKey, VALUE_ENCRYPTED_PASSWORD,
            encryptedPassword.data(), (DWORD)encryptedPassword.size());
        if (FAILED(hr)) break;

        if (credentialId && credentialIdSize > 0) {
            hr = WriteBinaryValue(hKey, VALUE_CREDENTIAL_ID,
                credentialId, credentialIdSize);
            if (FAILED(hr)) break;
        }

        if (publicKey && publicKeySize > 0) {
            hr = WriteBinaryValue(hKey, VALUE_PUBLIC_KEY,
                publicKey, publicKeySize);
            if (FAILED(hr)) break;
        }

        hr = WriteStringValue(hKey, VALUE_RELYING_PARTY_ID,
            relyingPartyId ? relyingPartyId : TITAN_KEY_CP_RELYING_PARTY_ID);

    } while (false);

    RegCloseKey(hKey);

    // Clear the encrypted password from memory
    SecureZeroMemory(encryptedPassword.data(), encryptedPassword.size());

    TITAN_LOG_HR(L"StoreCredential completed", hr);
    return hr;
}

//
// GetCredential - Retrieve credentials for a user
//
HRESULT CredentialStorage::GetCredential(
    PCWSTR userSid,
    UserCredential& credential)
{
    TITAN_LOG(L"GetCredential called");

    if (!userSid) {
        return E_INVALIDARG;
    }

    HKEY hKey = nullptr;
    HRESULT hr = OpenUserKey(userSid, FALSE, &hKey);
    if (FAILED(hr)) {
        return hr;
    }

    do {
        hr = ReadStringValue(hKey, VALUE_USERNAME, credential.username);
        if (FAILED(hr)) break;

        hr = ReadStringValue(hKey, VALUE_DOMAIN, credential.domain);
        if (FAILED(hr)) {
            // Domain is optional, default to local machine
            credential.domain = L".";
            hr = S_OK;
        }

        hr = ReadBinaryValue(hKey, VALUE_ENCRYPTED_PASSWORD, credential.encryptedPassword);
        if (FAILED(hr)) break;

        // These are optional for backward compatibility
        ReadBinaryValue(hKey, VALUE_CREDENTIAL_ID, credential.credentialId);
        ReadBinaryValue(hKey, VALUE_PUBLIC_KEY, credential.publicKey);
        ReadStringValue(hKey, VALUE_RELYING_PARTY_ID, credential.relyingPartyId);

        if (credential.relyingPartyId.empty()) {
            credential.relyingPartyId = TITAN_KEY_CP_RELYING_PARTY_ID;
        }

        hr = S_OK;

    } while (false);

    RegCloseKey(hKey);

    TITAN_LOG_HR(L"GetCredential completed", hr);
    return hr;
}

//
// DecryptPassword - Decrypt password using DPAPI
//
HRESULT CredentialStorage::DecryptPassword(
    const std::vector<BYTE>& encryptedData,
    SecureString& password)
{
    TITAN_LOG(L"DecryptPassword called");

    if (encryptedData.empty()) {
        return E_INVALIDARG;
    }

    DATA_BLOB encryptedBlob;
    encryptedBlob.pbData = const_cast<BYTE*>(encryptedData.data());
    encryptedBlob.cbData = (DWORD)encryptedData.size();

    DATA_BLOB decryptedBlob = { 0 };

    // Decrypt using DPAPI
    if (!CryptUnprotectData(
        &encryptedBlob,
        nullptr,       // description
        nullptr,       // optional entropy
        nullptr,       // reserved
        nullptr,       // prompt struct
        CRYPTPROTECT_LOCAL_MACHINE,  // flags
        &decryptedBlob))
    {
        HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
        TITAN_LOG_HR(L"CryptUnprotectData failed", hr);
        return hr;
    }

    // Convert to wide string and store in SecureString
    if (decryptedBlob.cbData > 0 && decryptedBlob.pbData) {
        // The data should be a null-terminated wide string
        password.Set(reinterpret_cast<const WCHAR*>(decryptedBlob.pbData));

        // Securely clear and free the decrypted data
        SecureZeroMemory(decryptedBlob.pbData, decryptedBlob.cbData);
        LocalFree(decryptedBlob.pbData);
    } else {
        return E_FAIL;
    }

    TITAN_LOG(L"DecryptPassword succeeded");
    return S_OK;
}

//
// HasCredential - Check if credentials exist for a user
//
BOOL CredentialStorage::HasCredential(PCWSTR userSid) {
    if (!userSid) {
        return FALSE;
    }

    HKEY hKey = nullptr;
    HRESULT hr = OpenUserKey(userSid, FALSE, &hKey);
    if (SUCCEEDED(hr)) {
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

//
// DeleteCredential - Delete credentials for a user
//
HRESULT CredentialStorage::DeleteCredential(PCWSTR userSid) {
    TITAN_LOG(L"DeleteCredential called");

    if (!userSid) {
        return E_INVALIDARG;
    }

    std::wstring keyPath = REGISTRY_BASE_PATH;
    keyPath += L"\\";
    keyPath += userSid;

    LONG result = RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        return HRESULT_FROM_WIN32(result);
    }

    return S_OK;
}

//
// EnumerateUsers - Get list of users with stored credentials
//
HRESULT CredentialStorage::EnumerateUsers(std::vector<std::wstring>& userSids) {
    TITAN_LOG(L"EnumerateUsers called");

    userSids.clear();

    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        REGISTRY_BASE_PATH,
        0,
        KEY_READ,
        &hKey);

    if (result == ERROR_FILE_NOT_FOUND) {
        // No credentials stored yet
        return S_OK;
    }

    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    DWORD index = 0;
    WCHAR subKeyName[256];
    DWORD subKeyNameSize;

    while (true) {
        subKeyNameSize = ARRAYSIZE(subKeyName);
        result = RegEnumKeyExW(
            hKey,
            index++,
            subKeyName,
            &subKeyNameSize,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (result != ERROR_SUCCESS) {
            continue;
        }

        userSids.push_back(subKeyName);
    }

    RegCloseKey(hKey);
    return S_OK;
}

//
// EncryptPassword - Encrypt password using DPAPI (static method for tools)
//
HRESULT CredentialStorage::EncryptPassword(
    PCWSTR password,
    std::vector<BYTE>& encryptedData)
{
    if (!password) {
        return E_INVALIDARG;
    }

    DATA_BLOB inputBlob;
    inputBlob.pbData = (BYTE*)password;
    inputBlob.cbData = (DWORD)((wcslen(password) + 1) * sizeof(WCHAR));

    DATA_BLOB outputBlob = { 0 };

    // Encrypt using DPAPI with local machine scope
    if (!CryptProtectData(
        &inputBlob,
        L"TitanKeyCP Password",  // description
        nullptr,                  // optional entropy
        nullptr,                  // reserved
        nullptr,                  // prompt struct
        CRYPTPROTECT_LOCAL_MACHINE,  // flags
        &outputBlob))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Copy to vector
    encryptedData.assign(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);

    // Free the output blob
    LocalFree(outputBlob.pbData);

    return S_OK;
}

//
// OpenUserKey - Open or create registry key for a user
//
HRESULT CredentialStorage::OpenUserKey(PCWSTR userSid, BOOL createIfMissing, HKEY* phKey) {
    if (!userSid || !phKey) {
        return E_INVALIDARG;
    }

    *phKey = nullptr;

    std::wstring keyPath = REGISTRY_BASE_PATH;
    keyPath += L"\\";
    keyPath += userSid;

    LONG result;
    if (createIfMissing) {
        result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            keyPath.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            nullptr,
            phKey,
            nullptr);
    } else {
        result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            keyPath.c_str(),
            0,
            KEY_READ,
            phKey);
    }

    return HRESULT_FROM_WIN32(result);
}

//
// ReadBinaryValue - Read binary data from registry
//
HRESULT CredentialStorage::ReadBinaryValue(HKEY hKey, PCWSTR valueName, std::vector<BYTE>& data) {
    data.clear();

    DWORD dataSize = 0;
    LONG result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, nullptr, &dataSize);
    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    data.resize(dataSize);
    result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, data.data(), &dataSize);
    if (result != ERROR_SUCCESS) {
        data.clear();
        return HRESULT_FROM_WIN32(result);
    }

    return S_OK;
}

//
// WriteBinaryValue - Write binary data to registry
//
HRESULT CredentialStorage::WriteBinaryValue(HKEY hKey, PCWSTR valueName, const BYTE* data, DWORD dataSize) {
    LONG result = RegSetValueExW(hKey, valueName, 0, REG_BINARY, data, dataSize);
    return HRESULT_FROM_WIN32(result);
}

//
// ReadStringValue - Read string from registry
//
HRESULT CredentialStorage::ReadStringValue(HKEY hKey, PCWSTR valueName, std::wstring& value) {
    value.clear();

    DWORD dataSize = 0;
    LONG result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, nullptr, &dataSize);
    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    std::vector<WCHAR> buffer(dataSize / sizeof(WCHAR) + 1);
    result = RegQueryValueExW(hKey, valueName, nullptr, nullptr,
        reinterpret_cast<BYTE*>(buffer.data()), &dataSize);

    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    value = buffer.data();
    return S_OK;
}

//
// WriteStringValue - Write string to registry
//
HRESULT CredentialStorage::WriteStringValue(HKEY hKey, PCWSTR valueName, PCWSTR value) {
    DWORD dataSize = (DWORD)((wcslen(value) + 1) * sizeof(WCHAR));
    LONG result = RegSetValueExW(hKey, valueName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value), dataSize);
    return HRESULT_FROM_WIN32(result);
}
