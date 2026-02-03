//
// CredentialStorage.cpp - Encrypted credential storage using hmac-secret
//
// Passwords are encrypted with AES-256-GCM using a key derived from the
// Titan Key's hmac-secret extension. Without the physical key, decryption
// is cryptographically impossible.
//
// SECURITY: Registry keys are protected with ACLs:
//   - Deny: Everyone
//   - Allow: SYSTEM (for LogonUI)
//   - Allow: Administrators (for enrollment)
//

#include "CredentialStorage.h"
#include "CryptoHelper.h"
#include <aclapi.h>
#include <sddl.h>

// Registry value names
static const WCHAR* VALUE_USERNAME = L"Username";
static const WCHAR* VALUE_DOMAIN = L"Domain";
static const WCHAR* VALUE_ENCRYPTED_PASSWORD = L"EncryptedPassword";
static const WCHAR* VALUE_CREDENTIAL_ID = L"CredentialId";
static const WCHAR* VALUE_SALT = L"Salt";
static const WCHAR* VALUE_RELYING_PARTY_ID = L"RelyingPartyId";

//
// SetRestrictedAcl - Protect registry key with restrictive ACLs
//
// Only SYSTEM and Administrators can access, preventing malicious apps
// from reading the encrypted password blob for offline attacks.
//
static HRESULT SetRestrictedAcl(HKEY hKey) {
    // SDDL string for restrictive permissions:
    // D:P                    - DACL, protected (no inheritance)
    // (A;;KA;;;SY)          - Allow SYSTEM full control
    // (A;;KA;;;BA)          - Allow Administrators full control
    // (D;;KA;;;WD)          - Deny Everyone (this is overridden by explicit allows above)
    //
    // Note: Explicit allows take precedence over explicit denies for the same SID
    // SYSTEM and Admins can access, everyone else is denied
    PCWSTR sddl = L"D:P(A;;KA;;;SY)(A;;KA;;;BA)";
    
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &pSD, nullptr)) {
        TITAN_LOG(L"Failed to create security descriptor");
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Get the DACL from the security descriptor
    PACL pDacl = nullptr;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted)) {
        LocalFree(pSD);
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Apply the DACL to the registry key
    DWORD dwResult = SetSecurityInfo(
        hKey,
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,  // Owner
        nullptr,  // Group
        pDacl,    // DACL
        nullptr); // SACL
    
    LocalFree(pSD);
    
    if (dwResult != ERROR_SUCCESS) {
        TITAN_LOG(L"Failed to set registry ACL");
        return HRESULT_FROM_WIN32(dwResult);
    }
    
    TITAN_LOG(L"Registry ACL set - protected from unauthorized access");
    return S_OK;
}

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
    const std::vector<BYTE>& encryptedPassword,
    const BYTE* credentialId,
    DWORD credentialIdSize,
    const BYTE* salt,
    DWORD saltSize,
    PCWSTR relyingPartyId)
{
    TITAN_LOG(L"StoreCredential called");

    if (!userSid || !username || encryptedPassword.empty() || !credentialId || !salt) {
        return E_INVALIDARG;
    }

    // Open or create the user's registry key
    HKEY hKey = nullptr;
    HRESULT hr = OpenUserKey(userSid, TRUE, &hKey);
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"Failed to open user key", hr);
        return hr;
    }

    // Apply restrictive ACLs to protect the encrypted data
    HRESULT aclHr = SetRestrictedAcl(hKey);
    if (FAILED(aclHr)) {
        TITAN_LOG_HR(L"Warning: Could not set restrictive ACL", aclHr);
        // Continue anyway - data will still be encrypted
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

        hr = WriteBinaryValue(hKey, VALUE_CREDENTIAL_ID,
            credentialId, credentialIdSize);
        if (FAILED(hr)) break;

        hr = WriteBinaryValue(hKey, VALUE_SALT, salt, saltSize);
        if (FAILED(hr)) break;

        hr = WriteStringValue(hKey, VALUE_RELYING_PARTY_ID,
            relyingPartyId ? relyingPartyId : TITAN_KEY_CP_RELYING_PARTY_ID);

    } while (false);

    RegCloseKey(hKey);

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
            credential.domain = L".";
            hr = S_OK;
        }

        hr = ReadBinaryValue(hKey, VALUE_ENCRYPTED_PASSWORD, credential.encryptedPassword);
        if (FAILED(hr)) break;

        hr = ReadBinaryValue(hKey, VALUE_CREDENTIAL_ID, credential.credentialId);
        if (FAILED(hr)) break;

        hr = ReadBinaryValue(hKey, VALUE_SALT, credential.salt);
        if (FAILED(hr)) break;

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
// DecryptPassword - Decrypt password using hmac-secret derived key
//
HRESULT CredentialStorage::DecryptPassword(
    const std::vector<BYTE>& encryptedData,
    const std::vector<BYTE>& hmacSecret,
    SecureString& password)
{
    TITAN_LOG(L"DecryptPassword called");

    if (encryptedData.empty() || hmacSecret.size() != 32) {
        return E_INVALIDARG;
    }

    return CryptoHelper::DecryptPassword(encryptedData, hmacSecret.data(), password);
}

//
// EncryptPassword - Encrypt password using hmac-secret derived key
//
HRESULT CredentialStorage::EncryptPassword(
    PCWSTR password,
    const std::vector<BYTE>& hmacSecret,
    std::vector<BYTE>& encryptedData)
{
    TITAN_LOG(L"EncryptPassword called");

    if (!password || hmacSecret.size() != 32) {
        return E_INVALIDARG;
    }

    return CryptoHelper::EncryptPassword(password, hmacSecret.data(), encryptedData);
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
