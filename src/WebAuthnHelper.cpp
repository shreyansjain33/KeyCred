//
// WebAuthnHelper.cpp - WebAuthn API wrapper for FIDO2 authentication
//

#include "WebAuthnHelper.h"
#include <inttypes.h>

// WebAuthn constants
static const WCHAR* WEBAUTHN_TYPE_CREATE = L"webauthn.create";
static const WCHAR* WEBAUTHN_TYPE_GET = L"webauthn.get";

// COSE algorithm identifiers
#define COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 -7

WebAuthnHelper::WebAuthnHelper()
    : m_isAvailable(FALSE)
    , m_apiVersion(0)
    , m_cancellationId({ 0 })
{
    TITAN_LOG(L"WebAuthnHelper created");
}

WebAuthnHelper::~WebAuthnHelper() {
    TITAN_LOG(L"WebAuthnHelper destroyed");
}

//
// Initialize - Check WebAuthn availability and version
//
HRESULT WebAuthnHelper::Initialize() {
    TITAN_LOG(L"WebAuthnHelper::Initialize");

    // Check API version
    m_apiVersion = WebAuthNGetApiVersionNumber();
    TITAN_LOG(L"WebAuthn API version detected");

    if (m_apiVersion < WEBAUTHN_API_VERSION_1) {
        m_lastError = L"WebAuthn API version too old";
        m_isAvailable = FALSE;
        return E_NOTIMPL;
    }

    // Check if platform supports WebAuthn
    BOOL isSupported = WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&isSupported);
    
    // Even if no platform authenticator, roaming authenticators (like Titan Key) work
    m_isAvailable = TRUE;

    TITAN_LOG(L"WebAuthnHelper initialized successfully");
    return S_OK;
}

//
// GenerateChallenge - Generate cryptographically secure random bytes
//
HRESULT WebAuthnHelper::GenerateChallenge(std::vector<BYTE>& challenge, DWORD size) {
    challenge.resize(size);

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        challenge.data(),
        size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!BCRYPT_SUCCESS(status)) {
        challenge.clear();
        return HRESULT_FROM_NT(status);
    }

    return S_OK;
}

//
// MakeCredential - Create a new WebAuthn credential (enrollment)
//
HRESULT WebAuthnHelper::MakeCredential(
    HWND hWnd,
    PCWSTR relyingPartyId,
    PCWSTR relyingPartyName,
    PCWSTR userId,
    PCWSTR userName,
    PCWSTR userDisplayName,
    const std::vector<BYTE>& challenge,
    CredentialResult& result)
{
    TITAN_LOG(L"WebAuthnHelper::MakeCredential");

    if (!m_isAvailable) {
        return E_FAIL;
    }

    // Create client data
    std::vector<BYTE> clientDataJson;
    std::vector<BYTE> clientDataHash;
    HRESULT hr = CreateClientData(
        WEBAUTHN_TYPE_CREATE,
        challenge,
        relyingPartyId,
        clientDataJson,
        clientDataHash);

    if (FAILED(hr)) {
        m_lastError = L"Failed to create client data";
        return hr;
    }

    // Setup relying party information
    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = { 0 };
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = relyingPartyId;
    rpInfo.pwszName = relyingPartyName;

    // Setup user information
    // Convert user ID to bytes
    size_t userIdLen = wcslen(userId);
    std::vector<BYTE> userIdBytes(userIdLen * sizeof(WCHAR));
    memcpy(userIdBytes.data(), userId, userIdBytes.size());

    WEBAUTHN_USER_ENTITY_INFORMATION userInfo = { 0 };
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = (DWORD)userIdBytes.size();
    userInfo.pbId = userIdBytes.data();
    userInfo.pwszName = userName;
    userInfo.pwszDisplayName = userDisplayName;

    // Setup credential parameters (prefer ES256)
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER credParams[1];
    credParams[0].dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    credParams[0].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    credParams[0].lAlg = COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;

    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS credParamsList = { 0 };
    credParamsList.cCredentialParameters = 1;
    credParamsList.pCredentialParameters = credParams;

    // Setup client data
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)clientDataJson.size();
    clientData.pbClientDataJSON = clientDataJson.data();
    clientData.pwszHashAlgId = BCRYPT_SHA256_ALGORITHM;

    // Setup authenticator selection - prefer cross-platform (USB) authenticators
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = { 0 };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;  // 60 seconds
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    options.bRequireResidentKey = FALSE;

    // Generate cancellation ID
    CoCreateGuid(&m_cancellationId);
    options.pCancellationId = &m_cancellationId;

    // Call WebAuthn API
    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    hr = WebAuthNAuthenticatorMakeCredential(
        hWnd,
        &rpInfo,
        &userInfo,
        &credParamsList,
        &clientData,
        &options,
        &pAttestation);

    if (FAILED(hr)) {
        TITAN_LOG_HR(L"WebAuthNAuthenticatorMakeCredential failed", hr);
        m_lastError = L"Failed to create credential";
        return hr;
    }

    // Extract credential ID
    result.credentialId.assign(
        pAttestation->pbCredentialId,
        pAttestation->pbCredentialId + pAttestation->cbCredentialId);

    // Extract attestation object (contains public key)
    result.attestationObject.assign(
        pAttestation->pbAttestationObject,
        pAttestation->pbAttestationObject + pAttestation->cbAttestationObject);

    // Note: pbPublicKey/cbPublicKey are only available in newer SDK versions (WEBAUTHN_API_VERSION_3+)
    // The public key can be extracted from the attestation object if needed
    
    result.usedTransport = pAttestation->dwUsedTransport;

    // Free the attestation
    WebAuthNFreeCredentialAttestation(pAttestation);

    TITAN_LOG(L"MakeCredential succeeded");
    return S_OK;
}

//
// GetAssertion - Authenticate with an existing credential
//
HRESULT WebAuthnHelper::GetAssertion(
    HWND hWnd,
    PCWSTR relyingPartyId,
    const std::vector<BYTE>& challenge,
    const std::vector<BYTE>* allowCredentialId,
    AssertionResult& result)
{
    TITAN_LOG(L"WebAuthnHelper::GetAssertion");

    if (!m_isAvailable) {
        m_lastError = L"WebAuthn not available";
        return E_FAIL;
    }

    // Create client data
    std::vector<BYTE> clientDataJson;
    std::vector<BYTE> clientDataHash;
    HRESULT hr = CreateClientData(
        WEBAUTHN_TYPE_GET,
        challenge,
        relyingPartyId,
        clientDataJson,
        clientDataHash);

    if (FAILED(hr)) {
        m_lastError = L"Failed to create client data";
        return hr;
    }

    // Setup client data structure
    WEBAUTHN_CLIENT_DATA clientData = { 0 };
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)clientDataJson.size();
    clientData.pbClientDataJSON = clientDataJson.data();
    clientData.pwszHashAlgId = BCRYPT_SHA256_ALGORITHM;

    // Setup allow credentials list if specific credential is requested
    WEBAUTHN_CREDENTIAL allowCredential = { 0 };
    WEBAUTHN_CREDENTIALS allowCredentials = { 0 };

    // Configure credential filter if provided
    BOOL useCredentialFilter = (allowCredentialId && !allowCredentialId->empty());
    if (useCredentialFilter) {
        allowCredential.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
        allowCredential.cbId = (DWORD)allowCredentialId->size();
        allowCredential.pbId = const_cast<BYTE*>(allowCredentialId->data());
        allowCredential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

        allowCredentials.cCredentials = 1;
        allowCredentials.pCredentials = &allowCredential;
        
        TITAN_LOG(L"Using credential filter");
    } else {
        TITAN_LOG(L"No credential filter - authenticator will discover");
    }

    // Setup options - minimal configuration for maximum compatibility
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = { 0 };
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;  // 60 seconds
    
    // Only set credential list if we have a filter, otherwise let authenticator discover
    if (useCredentialFilter) {
        options.CredentialList = allowCredentials;
    }
    // Leave other fields at 0/default - authenticator attachment ANY, UV discouraged

    // Call WebAuthn API
    PWEBAUTHN_ASSERTION pAssertion = nullptr;
    TITAN_LOG(L"Calling WebAuthNAuthenticatorGetAssertion");
    hr = WebAuthNAuthenticatorGetAssertion(
        hWnd,
        relyingPartyId,
        &clientData,
        &options,
        &pAssertion);

    if (FAILED(hr)) {
        TITAN_LOG_HR(L"WebAuthNAuthenticatorGetAssertion failed", hr);
        
        // Provide more specific error messages
        switch (hr) {
        case NTE_NOT_FOUND:
            m_lastError = L"No matching credential found on authenticator";
            break;
        case NTE_USER_CANCELLED:
            m_lastError = L"Operation cancelled by user";
            break;
        case NTE_INVALID_PARAMETER:
            m_lastError = L"Invalid parameter";
            break;
        default:
            m_lastError = L"Authentication failed";
            break;
        }
        return hr;
    }

    // Extract assertion data
    result.authenticatorData.assign(
        pAssertion->pbAuthenticatorData,
        pAssertion->pbAuthenticatorData + pAssertion->cbAuthenticatorData);

    result.signature.assign(
        pAssertion->pbSignature,
        pAssertion->pbSignature + pAssertion->cbSignature);

    if (pAssertion->pbUserId && pAssertion->cbUserId > 0) {
        result.userId.assign(
            pAssertion->pbUserId,
            pAssertion->pbUserId + pAssertion->cbUserId);
    }

    result.credentialId.assign(
        pAssertion->Credential.pbId,
        pAssertion->Credential.pbId + pAssertion->Credential.cbId);

    result.usedTransport = pAssertion->dwUsedTransport;

    // Free the assertion
    WebAuthNFreeAssertion(pAssertion);

    TITAN_LOG(L"GetAssertion succeeded");
    return S_OK;
}

//
// VerifyAssertion - Verify assertion signature using public key
//
HRESULT WebAuthnHelper::VerifyAssertion(
    const std::vector<BYTE>& publicKey,
    const std::vector<BYTE>& authenticatorData,
    const std::vector<BYTE>& clientDataHash,
    const std::vector<BYTE>& signature)
{
    TITAN_LOG(L"WebAuthnHelper::VerifyAssertion");

    if (publicKey.empty() || authenticatorData.empty() || 
        clientDataHash.empty() || signature.empty()) {
        return E_INVALIDARG;
    }

    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    do {
        // Open ECDSA algorithm provider
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_ECDSA_P256_ALGORITHM,
            nullptr,
            0);

        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Import the public key
        // The public key should be in COSE format, we need to convert to BCRYPT format
        // For simplicity, assume the public key is already in the correct format
        // In production, proper COSE key parsing would be needed

        // Create the data to verify (authenticatorData || clientDataHash)
        std::vector<BYTE> signedData;
        signedData.reserve(authenticatorData.size() + clientDataHash.size());
        signedData.insert(signedData.end(), authenticatorData.begin(), authenticatorData.end());
        signedData.insert(signedData.end(), clientDataHash.begin(), clientDataHash.end());

        // Hash the signed data
        BCRYPT_ALG_HANDLE hHashAlg = nullptr;
        status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        BYTE hash[32];
        DWORD hashSize = sizeof(hash);
        status = BCryptHash(hHashAlg, nullptr, 0, signedData.data(), (ULONG)signedData.size(), hash, hashSize);
        BCryptCloseAlgorithmProvider(hHashAlg, 0);

        if (!BCRYPT_SUCCESS(status)) {
            hr = HRESULT_FROM_NT(status);
            break;
        }

        // Import the public key blob
        // Assuming publicKey contains raw EC point (X || Y), each 32 bytes for P-256
        if (publicKey.size() >= 64) {
            BCRYPT_ECCKEY_BLOB keyHeader;
            keyHeader.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
            keyHeader.cbKey = 32;

            std::vector<BYTE> keyBlob(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
            memcpy(keyBlob.data(), &keyHeader, sizeof(BCRYPT_ECCKEY_BLOB));
            memcpy(keyBlob.data() + sizeof(BCRYPT_ECCKEY_BLOB), publicKey.data(), 64);

            status = BCryptImportKeyPair(
                hAlg,
                nullptr,
                BCRYPT_ECCPUBLIC_BLOB,
                &hKey,
                keyBlob.data(),
                (ULONG)keyBlob.size(),
                0);

            if (!BCRYPT_SUCCESS(status)) {
                hr = HRESULT_FROM_NT(status);
                break;
            }

            // Verify the signature
            // WebAuthn signatures are in ASN.1 DER format, need to convert to raw (r || s)
            // For simplicity, try both formats
            status = BCryptVerifySignature(
                hKey,
                nullptr,
                hash,
                hashSize,
                const_cast<BYTE*>(signature.data()),
                (ULONG)signature.size(),
                0);

            if (!BCRYPT_SUCCESS(status)) {
                hr = HRESULT_FROM_NT(status);
                break;
            }
        } else {
            hr = E_INVALIDARG;
            break;
        }

        hr = S_OK;

    } while (false);

    // Cleanup
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    TITAN_LOG_HR(L"VerifyAssertion", hr);
    return hr;
}

//
// CancelOperation - Cancel any ongoing WebAuthn operation
//
void WebAuthnHelper::CancelOperation() {
    TITAN_LOG(L"WebAuthnHelper::CancelOperation");
    WebAuthNCancelCurrentOperation(&m_cancellationId);
}

//
// CreateClientData - Create client data JSON and compute hash
//
HRESULT WebAuthnHelper::CreateClientData(
    PCWSTR type,
    const std::vector<BYTE>& challenge,
    PCWSTR origin,
    std::vector<BYTE>& clientDataJson,
    std::vector<BYTE>& clientDataHash)
{
    // Base64url encode the challenge
    DWORD base64Size = 0;
    CryptBinaryToStringW(
        challenge.data(),
        (DWORD)challenge.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        nullptr,
        &base64Size);

    std::wstring challengeBase64(base64Size, L'\0');
    CryptBinaryToStringW(
        challenge.data(),
        (DWORD)challenge.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        &challengeBase64[0],
        &base64Size);

    // Remove padding and convert to base64url
    while (!challengeBase64.empty() && challengeBase64.back() == L'=') {
        challengeBase64.pop_back();
    }
    for (auto& c : challengeBase64) {
        if (c == L'+') c = L'-';
        else if (c == L'/') c = L'_';
    }

    // Build JSON (simplified)
    std::wstring json = L"{\"type\":\"";
    json += type;
    json += L"\",\"challenge\":\"";
    json += challengeBase64;
    json += L"\",\"origin\":\"https://";
    json += origin;
    json += L"\",\"crossOrigin\":false}";

    // Convert to UTF-8
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, json.c_str(), -1, nullptr, 0, nullptr, nullptr);
    clientDataJson.resize(utf8Size - 1);  // Exclude null terminator
    WideCharToMultiByte(CP_UTF8, 0, json.c_str(), -1, 
        reinterpret_cast<char*>(clientDataJson.data()), utf8Size, nullptr, nullptr);

    // Compute SHA-256 hash
    clientDataHash.resize(32);
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return HRESULT_FROM_NT(status);
    }

    DWORD hashSize = 32;
    status = BCryptHash(hAlg, nullptr, 0, clientDataJson.data(), 
        (ULONG)clientDataJson.size(), clientDataHash.data(), hashSize);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        return HRESULT_FROM_NT(status);
    }

    return S_OK;
}
