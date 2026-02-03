#pragma once

#include "common.h"

//
// WebAuthnHelper - Wrapper for Windows WebAuthn API (webauthn.dll)
//
// Provides methods for FIDO2/WebAuthn authentication with security keys
// like the Google Titan Key. Supports hmac-secret extension for deriving
// encryption keys from the hardware key.
//
class WebAuthnHelper {
public:
    WebAuthnHelper();
    ~WebAuthnHelper();

    // Assertion result structure
    struct AssertionResult {
        std::vector<BYTE> authenticatorData;
        std::vector<BYTE> signature;
        std::vector<BYTE> userId;
        std::vector<BYTE> credentialId;
        std::vector<BYTE> hmacSecret;      // 32-byte secret from hmac-secret extension
        DWORD usedTransport;
    };

    // Make credential (enrollment) result
    struct CredentialResult {
        std::vector<BYTE> credentialId;
        std::vector<BYTE> publicKey;       // COSE public key
        std::vector<BYTE> attestationObject;
        DWORD usedTransport;
        bool hmacSecretSupported;          // Whether the key supports hmac-secret
    };

    // Initialize WebAuthn - must be called before other operations
    HRESULT Initialize();

    // Check if WebAuthn is available on this system
    BOOL IsAvailable() const { return m_isAvailable; }

    // Get WebAuthn API version
    DWORD GetApiVersion() const { return m_apiVersion; }

    // Generate a cryptographically secure challenge
    static HRESULT GenerateChallenge(std::vector<BYTE>& challenge, DWORD size = 32);

    // Create a new credential (enrollment)
    HRESULT MakeCredential(
        HWND hWnd,
        PCWSTR relyingPartyId,
        PCWSTR relyingPartyName,
        PCWSTR userId,
        PCWSTR userName,
        PCWSTR userDisplayName,
        const std::vector<BYTE>& challenge,
        CredentialResult& result);

    // Get assertion (authentication)
    // If salt is provided, hmac-secret extension is used to derive a 32-byte secret
    HRESULT GetAssertion(
        HWND hWnd,
        PCWSTR relyingPartyId,
        const std::vector<BYTE>& challenge,
        const std::vector<BYTE>* allowCredentialId,  // Optional: specific credential to use
        const std::vector<BYTE>* salt,               // Optional: 32-byte salt for hmac-secret
        AssertionResult& result);

    // Verify assertion signature using stored public key
    static HRESULT VerifyAssertion(
        const std::vector<BYTE>& publicKey,
        const std::vector<BYTE>& authenticatorData,
        const std::vector<BYTE>& clientDataHash,
        const std::vector<BYTE>& signature);

    // Cancel any ongoing operation
    void CancelOperation();

    // Get last error description
    PCWSTR GetLastErrorDescription() const { return m_lastError.c_str(); }

private:
    // Parse COSE public key from attestation
    HRESULT ParseCosePublicKey(
        const BYTE* coseKey,
        DWORD coseKeySize,
        BCRYPT_KEY_HANDLE* phKey);

    // Create client data JSON and hash
    HRESULT CreateClientData(
        PCWSTR type,
        const std::vector<BYTE>& challenge,
        PCWSTR origin,
        std::vector<BYTE>& clientDataJson,
        std::vector<BYTE>& clientDataHash);

    BOOL m_isAvailable;
    DWORD m_apiVersion;
    std::wstring m_lastError;
    GUID m_cancellationId;
};
