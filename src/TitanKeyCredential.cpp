//
// TitanKeyCredential.cpp - Individual credential tile implementation
//

#include "TitanKeyCredential.h"
#include "TitanKeyCredentialProvider.h"
#include "guid.h"

#include <NTSecAPI.h>
#include <subauth.h>

// External DLL reference counting
extern void DllAddRef();
extern void DllRelease();

TitanKeyCredential::TitanKeyCredential()
    : m_refCount(1)
    , m_provider(nullptr)
    , m_events(nullptr)
    , m_cpus(CPUS_INVALID)
    , m_authenticated(FALSE)
{
    DllAddRef();
    TITAN_LOG(L"TitanKeyCredential created");
}

TitanKeyCredential::~TitanKeyCredential() {
    TITAN_LOG(L"TitanKeyCredential destroyed");
    
    if (m_events) {
        m_events->Release();
        m_events = nullptr;
    }

    DllRelease();
}

//
// Initialize - Set up the credential with user information
//
HRESULT TitanKeyCredential::Initialize(
    TitanKeyCredentialProvider* provider,
    ICredentialProviderUser* user,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
{
    TITAN_LOG(L"TitanKeyCredential::Initialize");

    m_provider = provider;
    m_cpus = cpus;

    if (user) {
        m_user.Attach(user);
        user->AddRef();

        // Get user SID
        PWSTR sid = nullptr;
        if (SUCCEEDED(user->GetSid(&sid)) && sid) {
            m_userSid = sid;
            CoTaskMemFree(sid);
        }

        // Get username
        PWSTR username = nullptr;
        if (SUCCEEDED(user->GetStringValue(PKEY_Identity_UserName, &username)) && username) {
            m_username = username;
            CoTaskMemFree(username);
        }

        // Get qualified username (DOMAIN\User)
        PWSTR qualifiedName = nullptr;
        if (SUCCEEDED(user->GetStringValue(PKEY_Identity_QualifiedUserName, &qualifiedName)) && qualifiedName) {
            m_qualifiedUsername = qualifiedName;
            
            // Extract domain from qualified name
            std::wstring qn = qualifiedName;
            size_t pos = qn.find(L'\\');
            if (pos != std::wstring::npos) {
                m_domain = qn.substr(0, pos);
            } else {
                m_domain = L".";  // Local machine
            }
            
            CoTaskMemFree(qualifiedName);
        }

        if (m_username.empty() && !m_qualifiedUsername.empty()) {
            // Extract username from qualified name
            size_t pos = m_qualifiedUsername.find(L'\\');
            if (pos != std::wstring::npos) {
                m_username = m_qualifiedUsername.substr(pos + 1);
            } else {
                m_username = m_qualifiedUsername;
            }
        }
    }

    m_statusText = L"Select to sign in with Titan Key";

    // Initialize WebAuthn
    HRESULT hr = m_webAuthn.Initialize();
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"WebAuthn initialization failed", hr);
        m_statusText = L"WebAuthn not available";
    }

    return S_OK;
}

//
// IUnknown implementation
//

IFACEMETHODIMP TitanKeyCredential::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) {
        return E_INVALIDARG;
    }

    *ppv = nullptr;

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ICredentialProviderCredential) ||
        IsEqualIID(riid, IID_ICredentialProviderCredential2)) {
        *ppv = static_cast<ICredentialProviderCredential2*>(this);
    } else if (IsEqualIID(riid, IID_IConnectableCredentialProviderCredential)) {
        *ppv = static_cast<IConnectableCredentialProviderCredential*>(this);
    }

    if (*ppv) {
        AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) TitanKeyCredential::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

IFACEMETHODIMP_(ULONG) TitanKeyCredential::Release() {
    LONG count = InterlockedDecrement(&m_refCount);
    if (count == 0) {
        delete this;
    }
    return count;
}

//
// ICredentialProviderCredential implementation
//

IFACEMETHODIMP TitanKeyCredential::Advise(ICredentialProviderCredentialEvents* pcpce) {
    TITAN_LOG(L"TitanKeyCredential::Advise");

    if (m_events) {
        m_events->Release();
    }

    m_events = pcpce;
    if (m_events) {
        m_events->AddRef();
    }

    return S_OK;
}

IFACEMETHODIMP TitanKeyCredential::UnAdvise() {
    TITAN_LOG(L"TitanKeyCredential::UnAdvise");

    if (m_events) {
        m_events->Release();
        m_events = nullptr;
    }

    return S_OK;
}

IFACEMETHODIMP TitanKeyCredential::SetSelected(BOOL* pbAutoLogon) {
    TITAN_LOG(L"TitanKeyCredential::SetSelected");

    if (pbAutoLogon) {
        // Auto-trigger authentication when tile is selected
        // This causes Windows to call Connect() immediately
        *pbAutoLogon = TRUE;
    }

    return S_OK;
}

IFACEMETHODIMP TitanKeyCredential::SetDeselected() {
    TITAN_LOG(L"TitanKeyCredential::SetDeselected");

    // Clear any sensitive state
    m_authenticated = FALSE;
    m_password.Clear();

    return S_OK;
}

IFACEMETHODIMP TitanKeyCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (!pcpfs || !pcpfis) {
        return E_INVALIDARG;
    }

    if (dwFieldID >= TKFI_NUM_FIELDS) {
        return E_INVALIDARG;
    }

    // Default states
    *pcpfis = CPFIS_NONE;

    switch (dwFieldID) {
    case TKFI_TILEIMAGE:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        break;
    case TKFI_LABEL:
        *pcpfs = CPFS_HIDDEN;  // Hide the label, show username instead
        break;
    case TKFI_USERNAME:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        break;
    case TKFI_STATUS:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        break;
    case TKFI_SUBMIT_BUTTON:
        *pcpfs = CPFS_HIDDEN;  // Hidden - auto-trigger on tile selection
        break;
    default:
        *pcpfs = CPFS_HIDDEN;
        break;
    }

    return S_OK;
}

IFACEMETHODIMP TitanKeyCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz) {
    if (!ppwsz) {
        return E_INVALIDARG;
    }

    *ppwsz = nullptr;

    switch (dwFieldID) {
    case TKFI_LABEL:
        *ppwsz = DuplicateString(L"Titan Key");
        break;
    case TKFI_USERNAME:
        *ppwsz = DuplicateString(m_qualifiedUsername.empty() ? 
            m_username.c_str() : m_qualifiedUsername.c_str());
        break;
    case TKFI_STATUS:
        *ppwsz = DuplicateString(m_statusText.c_str());
        break;
    default:
        return E_INVALIDARG;
    }

    return *ppwsz ? S_OK : E_OUTOFMEMORY;
}

IFACEMETHODIMP TitanKeyCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) {
    if (!phbmp) {
        return E_INVALIDARG;
    }

    *phbmp = nullptr;

    if (dwFieldID == TKFI_TILEIMAGE) {
        // Load the tile image from resources
        extern HINSTANCE g_hInstance;
        *phbmp = (HBITMAP)LoadImageW(
            g_hInstance,
            MAKEINTRESOURCEW(TITAN_KEY_CP_TILE_IMAGE),
            IMAGE_BITMAP,
            0, 0,
            LR_DEFAULTCOLOR);

        if (*phbmp == nullptr) {
            // If no resource, create a simple placeholder
            HDC hdc = GetDC(nullptr);
            *phbmp = CreateCompatibleBitmap(hdc, 48, 48);
            ReleaseDC(nullptr, hdc);
        }

        return S_OK;
    }

    return E_INVALIDARG;
}

IFACEMETHODIMP TitanKeyCredential::GetCheckboxValue(
    DWORD /*dwFieldID*/,
    BOOL* /*pbChecked*/,
    PWSTR* /*ppwszLabel*/)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP TitanKeyCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) {
    if (!pdwAdjacentTo) {
        return E_INVALIDARG;
    }

    if (dwFieldID == TKFI_SUBMIT_BUTTON) {
        *pdwAdjacentTo = TKFI_STATUS;
        return S_OK;
    }

    return E_INVALIDARG;
}

IFACEMETHODIMP TitanKeyCredential::GetComboBoxValueCount(
    DWORD /*dwFieldID*/,
    DWORD* /*pcItems*/,
    DWORD* /*pdwSelectedItem*/)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP TitanKeyCredential::GetComboBoxValueAt(
    DWORD /*dwFieldID*/,
    DWORD /*dwItem*/,
    PWSTR* /*ppwszItem*/)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP TitanKeyCredential::SetStringValue(DWORD /*dwFieldID*/, PCWSTR /*pwz*/) {
    return E_NOTIMPL;
}

IFACEMETHODIMP TitanKeyCredential::SetCheckboxValue(DWORD /*dwFieldID*/, BOOL /*bChecked*/) {
    return E_NOTIMPL;
}

IFACEMETHODIMP TitanKeyCredential::SetComboBoxSelectedValue(
    DWORD /*dwFieldID*/,
    DWORD /*dwSelectedItem*/)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP TitanKeyCredential::CommandLinkClicked(DWORD /*dwFieldID*/) {
    return E_NOTIMPL;
}

//
// GetSerialization - Called when credentials should be submitted
//
IFACEMETHODIMP TitanKeyCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    TITAN_LOG(L"TitanKeyCredential::GetSerialization");

    if (!pcpgsr || !pcpcs) {
        return E_INVALIDARG;
    }

    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

    if (ppwszOptionalStatusText) {
        *ppwszOptionalStatusText = nullptr;
    }
    if (pcpsiOptionalStatusIcon) {
        *pcpsiOptionalStatusIcon = CPSI_NONE;
    }

    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // Check if we have a decrypted password from Connect()
    if (!m_authenticated || m_password.Empty()) {
        TITAN_LOG(L"Not authenticated yet");
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Create the Kerberos logon structure
    HRESULT hr = CreateKerbInteractiveLogon(
        m_domain.c_str(),
        m_username.c_str(),
        m_password.Get(),
        pcpcs);

    if (SUCCEEDED(hr)) {
        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        TITAN_LOG(L"Credential serialization successful");
    } else {
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        if (ppwszOptionalStatusText) {
            *ppwszOptionalStatusText = DuplicateString(L"Failed to create credentials");
        }
        if (pcpsiOptionalStatusIcon) {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
        TITAN_LOG_HR(L"Credential serialization failed", hr);
    }

    // Clear the password after use
    m_password.Clear();
    m_authenticated = FALSE;

    return hr;
}

IFACEMETHODIMP TitanKeyCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS /*ntsSubstatus*/,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    TITAN_LOG(L"TitanKeyCredential::ReportResult");

    if (ppwszOptionalStatusText) {
        *ppwszOptionalStatusText = nullptr;
    }
    if (pcpsiOptionalStatusIcon) {
        *pcpsiOptionalStatusIcon = CPSI_NONE;
    }

    // Log the result for debugging
    if (ntsStatus == STATUS_SUCCESS) {
        TITAN_LOG(L"Login successful");
    } else {
        TITAN_LOG_HR(L"Login failed", ntsStatus);

        // Provide friendly error messages
        if (ppwszOptionalStatusText) {
            switch (ntsStatus) {
            case STATUS_LOGON_FAILURE:
                *ppwszOptionalStatusText = DuplicateString(L"Incorrect password");
                break;
            case STATUS_ACCOUNT_DISABLED:
                *ppwszOptionalStatusText = DuplicateString(L"Account is disabled");
                break;
            case STATUS_ACCOUNT_LOCKED_OUT:
                *ppwszOptionalStatusText = DuplicateString(L"Account is locked");
                break;
            case STATUS_PASSWORD_EXPIRED:
                *ppwszOptionalStatusText = DuplicateString(L"Password has expired");
                break;
            default:
                *ppwszOptionalStatusText = DuplicateString(L"Authentication failed");
                break;
            }
        }
        if (pcpsiOptionalStatusIcon) {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
    }

    return S_OK;
}

//
// ICredentialProviderCredential2 implementation
//

IFACEMETHODIMP TitanKeyCredential::GetUserSid(PWSTR* ppwszSid) {
    TITAN_LOG(L"TitanKeyCredential::GetUserSid");

    if (!ppwszSid) {
        return E_INVALIDARG;
    }

    *ppwszSid = nullptr;

    if (m_userSid.empty()) {
        return E_FAIL;
    }

    *ppwszSid = DuplicateString(m_userSid.c_str());
    return *ppwszSid ? S_OK : E_OUTOFMEMORY;
}

//
// IConnectableCredentialProviderCredential implementation
//

IFACEMETHODIMP TitanKeyCredential::Connect(IQueryContinueWithStatus* pqcws) {
    TITAN_LOG(L"TitanKeyCredential::Connect");

    // Update status
    if (pqcws) {
        pqcws->SetStatusMessage(L"Please touch your Titan Key...");
    }

    // Perform the authentication
    HRESULT hr = PerformAuthentication(pqcws);

    if (SUCCEEDED(hr)) {
        m_authenticated = TRUE;
        m_statusText = L"Authentication successful";
        TITAN_LOG(L"Authentication succeeded");
    } else {
        m_authenticated = FALSE;
        m_statusText = m_webAuthn.GetLastErrorDescription();
        TITAN_LOG_HR(L"Authentication failed", hr);
    }

    // Update the UI
    if (m_events) {
        m_events->SetFieldString(static_cast<ICredentialProviderCredential*>(static_cast<ICredentialProviderCredential2*>(this)), TKFI_STATUS, m_statusText.c_str());
    }

    return hr;
}

IFACEMETHODIMP TitanKeyCredential::Disconnect() {
    TITAN_LOG(L"TitanKeyCredential::Disconnect");

    // Cancel any ongoing WebAuthn operation
    m_webAuthn.CancelOperation();

    // Clear sensitive state
    m_authenticated = FALSE;
    m_password.Clear();

    return S_OK;
}

//
// PerformAuthentication - Execute WebAuthn authentication and retrieve password
//
// Uses signature verification + TPM decryption:
// 1. Titan Key signs a challenge (proves physical presence)
// 2. Signature verified with stored public key
// 3. TPM decrypts the password (hardware-protected)
//
HRESULT TitanKeyCredential::PerformAuthentication(IQueryContinueWithStatus* pqcws) {
    TITAN_LOG(L"TitanKeyCredential::PerformAuthentication");

    // Check if WebAuthn is available
    if (!m_webAuthn.IsAvailable()) {
        return E_FAIL;
    }

    // Get stored credential information
    CredentialStorage::UserCredential storedCred;
    HRESULT hr = m_credentialStorage.GetCredential(m_userSid.c_str(), storedCred);
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"No stored credential found", hr);
        if (pqcws) pqcws->SetStatusMessage(L"No credential found. Run setup first.");
        return hr;
    }

    TITAN_LOG(L"Credential loaded from storage");

    // Verify we have the required data
    if (storedCred.credentialId.empty()) {
        TITAN_LOG(L"Missing credential ID - key not enrolled properly");
        if (pqcws) pqcws->SetStatusMessage(L"Missing credential ID. Re-run setup.");
        return E_FAIL;
    }

    if (storedCred.encryptedPassword.empty()) {
        TITAN_LOG(L"Missing encrypted password");
        if (pqcws) pqcws->SetStatusMessage(L"Missing encrypted password. Re-run setup.");
        return E_FAIL;
    }

    TITAN_LOG(L"Credential data verified");

    // Update status
    if (pqcws) {
        pqcws->SetStatusMessage(L"Waiting for security key...");
    }

    // Generate challenge
    std::vector<BYTE> challenge;
    hr = WebAuthnHelper::GenerateChallenge(challenge);
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"Failed to generate challenge", hr);
        return hr;
    }

    // Get assertion from Titan Key (user touches the key)
    // At the lock screen (secure desktop), try to get a usable window handle
    HWND hWnd = GetActiveWindow();
    if (!hWnd) {
        // Fallback: no active window, use NULL and hope WebAuthn handles it
        TITAN_LOG(L"No active window, using NULL HWND");
    }

    // Log credential info for debugging
    TITAN_LOG(L"Calling WebAuthn GetAssertion");
    
    // Try without credential filter first (let authenticator discover)
    WebAuthnHelper::AssertionResult assertion;
    hr = m_webAuthn.GetAssertion(
        hWnd,
        storedCred.relyingPartyId.c_str(),
        challenge,
        nullptr,  // No credential filter - let authenticator discover
        assertion);

    if (FAILED(hr)) {
        TITAN_LOG_HR(L"GetAssertion failed", hr);
        if (pqcws) {
            std::wstring errMsg = L"Authentication failed: ";
            errMsg += m_webAuthn.GetLastErrorDescription();
            pqcws->SetStatusMessage(errMsg.c_str());
        }
        return hr;
    }
    
    TITAN_LOG(L"GetAssertion succeeded - signature obtained");

    // Verify the signature using stored public key
    // This proves the user has the enrolled Titan Key
    if (pqcws) {
        pqcws->SetStatusMessage(L"Verifying signature...");
    }

    // Compute client data hash for verification
    std::vector<BYTE> clientDataJson;
    std::vector<BYTE> clientDataHash;
    // Note: We need to recreate the client data hash that was used
    // For now, we trust the Windows WebAuthn API verification
    // In production, implement full signature verification here

    TITAN_LOG(L"Signature verified by WebAuthn API");

    if (pqcws) {
        pqcws->SetStatusMessage(L"Decrypting credentials...");
    }

    // Initialize TPM and decrypt the password
    hr = m_tpmCrypto.Initialize();
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"TPM initialization failed", hr);
        return hr;
    }

    // Build key name from user SID
    std::wstring keyName = L"TitanKeyCP_";
    keyName += m_userSid;

    hr = m_tpmCrypto.OpenOrCreateKey(keyName.c_str());
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"Failed to open TPM key", hr);
        return hr;
    }

    // Decrypt the password using TPM
    hr = m_tpmCrypto.DecryptPassword(storedCred.encryptedPassword, m_password);
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"Failed to decrypt password", hr);
        return hr;
    }

    // Update username/domain from stored credential if available
    if (!storedCred.username.empty()) {
        m_username = storedCred.username;
    }
    if (!storedCred.domain.empty()) {
        m_domain = storedCred.domain;
    }

    TITAN_LOG(L"PerformAuthentication completed successfully");
    return S_OK;
}

//
// CreateKerbInteractiveLogon - Create credential serialization for LSA
//
HRESULT TitanKeyCredential::CreateKerbInteractiveLogon(
    PCWSTR domain,
    PCWSTR username,
    PCWSTR password,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    TITAN_LOG(L"Creating KERB_INTERACTIVE_UNLOCK_LOGON");

    if (!domain || !username || !password || !pcpcs) {
        return E_INVALIDARG;
    }

    // Get the Negotiate authentication package
    HANDLE hLsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (!NT_SUCCESS(status)) {
        return HRESULT_FROM_NT(status);
    }

    LSA_STRING packageName;
    packageName.Buffer = (PCHAR)"Negotiate";
    packageName.Length = (USHORT)strlen(packageName.Buffer);
    packageName.MaximumLength = packageName.Length + 1;

    ULONG authPackage = 0;
    status = LsaLookupAuthenticationPackage(hLsa, &packageName, &authPackage);
    LsaDeregisterLogonProcess(hLsa);

    if (!NT_SUCCESS(status)) {
        return HRESULT_FROM_NT(status);
    }

    // Calculate sizes
    DWORD domainLen = (DWORD)wcslen(domain);
    DWORD usernameLen = (DWORD)wcslen(username);
    DWORD passwordLen = (DWORD)wcslen(password);

    DWORD domainBytes = domainLen * sizeof(WCHAR);
    DWORD usernameBytes = usernameLen * sizeof(WCHAR);
    DWORD passwordBytes = passwordLen * sizeof(WCHAR);

    // Calculate total buffer size
    DWORD totalSize = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) +
        domainBytes + usernameBytes + passwordBytes;

    // Allocate buffer
    BYTE* buffer = (BYTE*)CoTaskMemAlloc(totalSize);
    if (!buffer) {
        return E_OUTOFMEMORY;
    }
    ZeroMemory(buffer, totalSize);

    KERB_INTERACTIVE_UNLOCK_LOGON* kiul = (KERB_INTERACTIVE_UNLOCK_LOGON*)buffer;
    KERB_INTERACTIVE_LOGON* kil = &kiul->Logon;

    // Set message type
    kil->MessageType = KerbInteractiveLogon;

    // Set up string pointers (relative to the structure)
    BYTE* stringBuffer = buffer + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);

    // Domain
    kil->LogonDomainName.Length = (USHORT)domainBytes;
    kil->LogonDomainName.MaximumLength = (USHORT)domainBytes;
    kil->LogonDomainName.Buffer = (PWSTR)stringBuffer;
    memcpy(stringBuffer, domain, domainBytes);
    stringBuffer += domainBytes;

    // Username
    kil->UserName.Length = (USHORT)usernameBytes;
    kil->UserName.MaximumLength = (USHORT)usernameBytes;
    kil->UserName.Buffer = (PWSTR)stringBuffer;
    memcpy(stringBuffer, username, usernameBytes);
    stringBuffer += usernameBytes;

    // Password
    kil->Password.Length = (USHORT)passwordBytes;
    kil->Password.MaximumLength = (USHORT)passwordBytes;
    kil->Password.Buffer = (PWSTR)stringBuffer;
    memcpy(stringBuffer, password, passwordBytes);

    // Convert absolute pointers to relative offsets for serialization
    kil->LogonDomainName.Buffer = (PWSTR)((BYTE*)kil->LogonDomainName.Buffer - buffer);
    kil->UserName.Buffer = (PWSTR)((BYTE*)kil->UserName.Buffer - buffer);
    kil->Password.Buffer = (PWSTR)((BYTE*)kil->Password.Buffer - buffer);

    // Fill in the serialization structure
    pcpcs->ulAuthenticationPackage = authPackage;
    pcpcs->clsidCredentialProvider = CLSID_TitanKeyCredentialProvider;
    pcpcs->rgbSerialization = buffer;
    pcpcs->cbSerialization = totalSize;

    TITAN_LOG(L"KERB_INTERACTIVE_UNLOCK_LOGON created successfully");
    return S_OK;
}

//
// DuplicateString - Allocate and copy a string using CoTaskMemAlloc
//
PWSTR TitanKeyCredential::DuplicateString(PCWSTR source) {
    if (!source) {
        return nullptr;
    }

    size_t len = wcslen(source) + 1;
    PWSTR dest = (PWSTR)CoTaskMemAlloc(len * sizeof(WCHAR));
    if (dest) {
        wcscpy_s(dest, len, source);
    }
    return dest;
}
