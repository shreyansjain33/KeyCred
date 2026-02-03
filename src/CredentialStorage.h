#pragma once

#include "common.h"

//
// CredentialStorage - Manages encrypted credential storage in the Windows Registry
//
// Stores user credentials encrypted with TPM-backed keys (via CNG).
// The password is protected by:
//   1. TPM hardware (cannot be extracted even with admin access)
//   2. Titan Key signature verification (physical presence required)
//
class CredentialStorage {
public:
    CredentialStorage();
    ~CredentialStorage();

    // Credential data structure
    struct UserCredential {
        std::wstring username;
        std::wstring domain;
        std::vector<BYTE> encryptedPassword;  // TPM-encrypted
        std::vector<BYTE> credentialId;       // WebAuthn credential ID
        std::vector<BYTE> publicKey;          // Public key for signature verification
        std::wstring relyingPartyId;
    };

    // Store credentials for a user
    HRESULT StoreCredential(
        PCWSTR userSid,
        PCWSTR username,
        PCWSTR domain,
        const std::vector<BYTE>& encryptedPassword,  // Already TPM-encrypted
        const BYTE* credentialId,
        DWORD credentialIdSize,
        const BYTE* publicKey,
        DWORD publicKeySize,
        PCWSTR relyingPartyId);

    // Retrieve credentials for a user
    HRESULT GetCredential(
        PCWSTR userSid,
        UserCredential& credential);

    // Check if credentials exist for a user
    BOOL HasCredential(PCWSTR userSid);

    // Delete credentials for a user
    HRESULT DeleteCredential(PCWSTR userSid);

    // Get list of users with stored credentials
    HRESULT EnumerateUsers(std::vector<std::wstring>& userSids);

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
