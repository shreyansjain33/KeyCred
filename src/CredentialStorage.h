#pragma once

#include "common.h"

//
// CredentialStorage - Manages encrypted credential storage in the Windows Registry
//
// Stores user credentials encrypted with DPAPI, along with WebAuthn credential
// information (credential ID, public key) for signature verification.
//
class CredentialStorage {
public:
    CredentialStorage();
    ~CredentialStorage();

    // Credential data structure
    struct UserCredential {
        std::wstring username;
        std::wstring domain;
        std::vector<BYTE> encryptedPassword;
        std::vector<BYTE> credentialId;      // WebAuthn credential ID
        std::vector<BYTE> publicKey;         // COSE public key for verification
        std::wstring relyingPartyId;
    };

    // Store credentials for a user
    HRESULT StoreCredential(
        PCWSTR userSid,
        PCWSTR username,
        PCWSTR domain,
        PCWSTR password,
        const BYTE* credentialId,
        DWORD credentialIdSize,
        const BYTE* publicKey,
        DWORD publicKeySize,
        PCWSTR relyingPartyId);

    // Retrieve credentials for a user
    HRESULT GetCredential(
        PCWSTR userSid,
        UserCredential& credential);

    // Decrypt password using DPAPI
    HRESULT DecryptPassword(
        const std::vector<BYTE>& encryptedData,
        SecureString& password);

    // Check if credentials exist for a user
    BOOL HasCredential(PCWSTR userSid);

    // Delete credentials for a user
    HRESULT DeleteCredential(PCWSTR userSid);

    // Get list of users with stored credentials
    HRESULT EnumerateUsers(std::vector<std::wstring>& userSids);

    // Encrypt password using DPAPI
    static HRESULT EncryptPassword(
        PCWSTR password,
        std::vector<BYTE>& encryptedData);

private:
    // Registry key management
    HRESULT OpenUserKey(PCWSTR userSid, BOOL createIfMissing, HKEY* phKey);
    HRESULT ReadBinaryValue(HKEY hKey, PCWSTR valueName, std::vector<BYTE>& data);
    HRESULT WriteBinaryValue(HKEY hKey, PCWSTR valueName, const BYTE* data, DWORD dataSize);
    HRESULT ReadStringValue(HKEY hKey, PCWSTR valueName, std::wstring& value);
    HRESULT WriteStringValue(HKEY hKey, PCWSTR valueName, PCWSTR value);

    // Base registry key path
    static constexpr const WCHAR* REGISTRY_BASE_PATH = TITAN_KEY_CP_REGISTRY_PATH;
};
