//
// TitanKeyCredentialProvider.cpp - Main credential provider implementation
//

#include "TitanKeyCredentialProvider.h"
#include "guid.h"

// External DLL reference counting
extern void DllAddRef();
extern void DllRelease();

// Field descriptors for the credential tiles
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_fieldDescriptors[] = {
    { TKFI_TILEIMAGE,     CPFT_TILE_IMAGE,    L"Image",              CPFG_CREDENTIAL_PROVIDER_LOGO },
    { TKFI_LABEL,         CPFT_LARGE_TEXT,    L"Titan Key Login",    CPFG_CREDENTIAL_PROVIDER_LABEL },
    { TKFI_USERNAME,      CPFT_LARGE_TEXT,    L"Username",           GUID_NULL },
    { TKFI_STATUS,        CPFT_SMALL_TEXT,    L"Status",             GUID_NULL },
    { TKFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit",             GUID_NULL },
};

TitanKeyCredentialProvider::TitanKeyCredentialProvider()
    : m_refCount(1)
    , m_cpus(CPUS_INVALID)
    , m_cpusFlags(0)
    , m_events(nullptr)
    , m_adviseContext(0)
{
    DllAddRef();
    TITAN_LOG(L"TitanKeyCredentialProvider created");
}

TitanKeyCredentialProvider::~TitanKeyCredentialProvider() {
    TITAN_LOG(L"TitanKeyCredentialProvider destroyed");

    ReleaseCredentials();

    if (m_events) {
        m_events->Release();
        m_events = nullptr;
    }

    DllRelease();
}

//
// IUnknown implementation
//

IFACEMETHODIMP TitanKeyCredentialProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) {
        return E_INVALIDARG;
    }

    *ppv = nullptr;

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ICredentialProvider)) {
        *ppv = static_cast<ICredentialProvider*>(this);
    } else if (IsEqualIID(riid, IID_ICredentialProviderSetUserArray)) {
        *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
    }

    if (*ppv) {
        AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) TitanKeyCredentialProvider::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

IFACEMETHODIMP_(ULONG) TitanKeyCredentialProvider::Release() {
    LONG count = InterlockedDecrement(&m_refCount);
    if (count == 0) {
        delete this;
    }
    return count;
}

//
// ICredentialProvider implementation
//

IFACEMETHODIMP TitanKeyCredentialProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags)
{
    TITAN_LOG(L"TitanKeyCredentialProvider::SetUsageScenario");

    HRESULT hr = S_OK;

    // Check if we support this scenario
    switch (cpus) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
    case CPUS_CREDUI:
    case CPUS_PLAP:
        m_cpus = cpus;
        m_cpusFlags = dwFlags;
        TITAN_LOG(L"Usage scenario accepted");
        break;

    case CPUS_CHANGE_PASSWORD:
        // We don't support password change
        hr = E_NOTIMPL;
        TITAN_LOG(L"Password change not supported");
        break;

    default:
        hr = E_INVALIDARG;
        TITAN_LOG(L"Invalid usage scenario");
        break;
    }

    return hr;
}

IFACEMETHODIMP TitanKeyCredentialProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* /*pcpcs*/)
{
    TITAN_LOG(L"TitanKeyCredentialProvider::SetSerialization");
    // We don't use incoming serialization
    return E_NOTIMPL;
}

IFACEMETHODIMP TitanKeyCredentialProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext)
{
    TITAN_LOG(L"TitanKeyCredentialProvider::Advise");

    if (m_events) {
        m_events->Release();
    }

    m_events = pcpe;
    if (m_events) {
        m_events->AddRef();
    }

    m_adviseContext = upAdviseContext;

    return S_OK;
}

IFACEMETHODIMP TitanKeyCredentialProvider::UnAdvise() {
    TITAN_LOG(L"TitanKeyCredentialProvider::UnAdvise");

    if (m_events) {
        m_events->Release();
        m_events = nullptr;
    }

    return S_OK;
}

IFACEMETHODIMP TitanKeyCredentialProvider::GetFieldDescriptorCount(DWORD* pdwCount) {
    if (!pdwCount) {
        return E_INVALIDARG;
    }

    *pdwCount = TKFI_NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP TitanKeyCredentialProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (!ppcpfd) {
        return E_INVALIDARG;
    }

    *ppcpfd = nullptr;

    if (dwIndex >= TKFI_NUM_FIELDS) {
        return E_INVALIDARG;
    }

    // Allocate and copy the field descriptor
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pfd = 
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));

    if (!pfd) {
        return E_OUTOFMEMORY;
    }

    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& source = s_fieldDescriptors[dwIndex];

    pfd->dwFieldID = source.dwFieldID;
    pfd->cpft = source.cpft;
    pfd->guidFieldType = source.guidFieldType;

    // Duplicate the label string
    if (source.pszLabel) {
        size_t len = wcslen(source.pszLabel) + 1;
        pfd->pszLabel = (PWSTR)CoTaskMemAlloc(len * sizeof(WCHAR));
        if (pfd->pszLabel) {
            wcscpy_s(pfd->pszLabel, len, source.pszLabel);
        } else {
            CoTaskMemFree(pfd);
            return E_OUTOFMEMORY;
        }
    } else {
        pfd->pszLabel = nullptr;
    }

    *ppcpfd = pfd;
    return S_OK;
}

IFACEMETHODIMP TitanKeyCredentialProvider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault)
{
    TITAN_LOG(L"TitanKeyCredentialProvider::GetCredentialCount");

    if (!pdwCount || !pdwDefault || !pbAutoLogonWithDefault) {
        return E_INVALIDARG;
    }

    *pdwCount = (DWORD)m_credentials.size();
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    TITAN_LOG(L"Credential count returned");
    return S_OK;
}

IFACEMETHODIMP TitanKeyCredentialProvider::GetCredentialAt(
    DWORD dwIndex,
    ICredentialProviderCredential** ppcpc)
{
    TITAN_LOG(L"TitanKeyCredentialProvider::GetCredentialAt");

    if (!ppcpc) {
        return E_INVALIDARG;
    }

    *ppcpc = nullptr;

    if (dwIndex >= m_credentials.size()) {
        return E_INVALIDARG;
    }

    TitanKeyCredential* credential = m_credentials[dwIndex];
    if (credential) {
        credential->AddRef();
        *ppcpc = static_cast<ICredentialProviderCredential*>(
            static_cast<ICredentialProviderCredential2*>(credential));
        return S_OK;
    }

    return E_FAIL;
}

//
// ICredentialProviderSetUserArray implementation
//

IFACEMETHODIMP TitanKeyCredentialProvider::SetUserArray(ICredentialProviderUserArray* users) {
    TITAN_LOG(L"TitanKeyCredentialProvider::SetUserArray");

    // Release existing credentials
    ReleaseCredentials();

    // Store the user array
    m_userArray.Reset();
    if (users) {
        m_userArray.Attach(users);
        users->AddRef();
    }

    // Create credentials for users
    return CreateCredentialsForUsers();
}

//
// CreateCredentialsForUsers - Create credential tiles for users with stored credentials
//
HRESULT TitanKeyCredentialProvider::CreateCredentialsForUsers() {
    TITAN_LOG(L"TitanKeyCredentialProvider::CreateCredentialsForUsers");

    if (!m_userArray.Get()) {
        TITAN_LOG(L"No user array available");
        return S_OK;
    }

    // Get the account options to understand what users are available
    CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS accountOptions;
    HRESULT hr = m_userArray->GetAccountOptions(&accountOptions);
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"GetAccountOptions failed", hr);
    }

    // Get the number of users
    DWORD userCount = 0;
    hr = m_userArray->GetCount(&userCount);
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"GetCount failed", hr);
        return hr;
    }

    TITAN_LOG(L"Processing users");

    // Iterate through users and create credentials for those with stored Titan Key data
    for (DWORD i = 0; i < userCount; i++) {
        ICredentialProviderUser* user = nullptr;
        hr = m_userArray->GetAt(i, &user);
        if (FAILED(hr) || !user) {
            continue;
        }

        // Get the user's SID
        PWSTR sid = nullptr;
        hr = user->GetSid(&sid);
        if (SUCCEEDED(hr) && sid) {
            // Check if this user has stored Titan Key credentials
            if (m_credentialStorage.HasCredential(sid)) {
                TITAN_LOG(L"Found stored credential for user");

                // Create a credential for this user
                TitanKeyCredential* credential = new (std::nothrow) TitanKeyCredential();
                if (credential) {
                    hr = credential->Initialize(this, user, m_cpus);
                    if (SUCCEEDED(hr)) {
                        m_credentials.push_back(credential);
                    } else {
                        credential->Release();
                    }
                }
            }
            CoTaskMemFree(sid);
        }

        user->Release();
    }

    TITAN_LOG(L"Credential creation complete");
    return S_OK;
}

//
// ReleaseCredentials - Release all credential objects
//
void TitanKeyCredentialProvider::ReleaseCredentials() {
    for (auto* credential : m_credentials) {
        if (credential) {
            credential->Release();
        }
    }
    m_credentials.clear();
}
