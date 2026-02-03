#pragma once

#include "common.h"

//
// CredentialStorage - Manages encrypted credential storage in the Windows Registry
//
// Stores user credentials encrypted with AES-256-GCM using a key derived from
// the Titan Key's hmac-secret extension. The password can ONLY be decrypted
// using the same physical security key that was used during enrollment.
//
class CredentialStorage {
public:
    CredentialStorage();
    ~CredentialStorage();

    // Credential data structure
    struct UserCredential {
        std::wstring username;
        std::wstring domain;
        std::vector<BYTE> encryptedPassword;  // AES-256-GCM encrypted
        std::vector<BYTE> credentialId;       // WebAuthn credential ID
        std::vector<BYTE> salt;               // 32-byte salt for hmac-secret
        std::wstring relyingPartyId;
    };

    // Store credentials for a user (encrypted with hmac-secret derived key)
    HRESULT StoreCredential(
        PCWSTR userSid,
        PCWSTR username,
        PCWSTR domain,
        const std::vector<BYTE>& encryptedPassword,  // Already encrypted with AES-GCM
        const BYTE* credentialId,
        DWORD credentialIdSize,
        const BYTE* salt,
        DWORD saltSize,
        PCWSTR relyingPartyId);

    // Retrieve credentials for a user
    HRESULT GetCredential(
        PCWSTR userSid,
        UserCredential& credential);

    // Decrypt password using hmac-secret derived key
    static HRESULT DecryptPassword(
        const std::vector<BYTE>& encryptedData,
        const std::vector<BYTE>& hmacSecret,  // 32-byte key from Titan Key
        SecureString& password);

    // Encrypt password using hmac-secret derived key
    static HRESULT EncryptPassword(
        PCWSTR password,
        const std::vector<BYTE>& hmacSecret,  // 32-byte key from Titan Key
        std::vector<BYTE>& encryptedData);

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
