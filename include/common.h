#pragma once

// Windows headers
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <credentialprovider.h>
#include <propkey.h>
#include <webauthn.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <sddl.h>

// WebAuthn API version compatibility
// These may not be defined in older Windows SDKs
#ifndef WEBAUTHN_API_VERSION_1
#define WEBAUTHN_API_VERSION_1 1
#endif
#ifndef WEBAUTHN_API_VERSION_2
#define WEBAUTHN_API_VERSION_2 2
#endif
#ifndef WEBAUTHN_API_VERSION_3
#define WEBAUTHN_API_VERSION_3 3
#endif

// HRESULT_FROM_NT may not be defined
#ifndef HRESULT_FROM_NT
#define HRESULT_FROM_NT(x) ((HRESULT) ((x) | FACILITY_NT_BIT))
#endif
#ifndef FACILITY_NT_BIT
#define FACILITY_NT_BIT 0x10000000
#endif

// NTE error codes (from winerror.h, may not be defined in some SDKs)
#ifndef NTE_NOT_FOUND
#define NTE_NOT_FOUND ((HRESULT)0x80090011L)
#endif
#ifndef NTE_USER_CANCELLED
#define NTE_USER_CANCELLED ((HRESULT)0x80090036L)
#endif
#ifndef NTE_INVALID_PARAMETER
#define NTE_INVALID_PARAMETER ((HRESULT)0x80090027L)
#endif

// NTSTATUS codes (may not be defined in all SDKs)
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_LOGON_FAILURE
#define STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006DL)
#endif
#ifndef STATUS_ACCOUNT_DISABLED
#define STATUS_ACCOUNT_DISABLED ((NTSTATUS)0xC0000072L)
#endif
#ifndef STATUS_ACCOUNT_LOCKED_OUT
#define STATUS_ACCOUNT_LOCKED_OUT ((NTSTATUS)0xC0000234L)
#endif
#ifndef STATUS_PASSWORD_EXPIRED
#define STATUS_PASSWORD_EXPIRED ((NTSTATUS)0xC0000071L)
#endif

// NT_SUCCESS macro is defined in subauth.h (included via ntsecapi.h)
// Don't define it here to avoid redefinition warnings

// Standard library
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

// Utility macros
#define SAFE_RELEASE(p) if ((p)) { (p)->Release(); (p) = nullptr; }
#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

// Define credential provider field GUIDs if not available in SDK
// These are defined in newer Windows SDKs (1903+)
// Using inline const GUID to avoid initguid.h issues
#ifndef CPFG_CREDENTIAL_PROVIDER_LOGO
static const GUID CPFG_CREDENTIAL_PROVIDER_LOGO = 
    { 0x2d837775, 0xf6cd, 0x464e, { 0xa7, 0x45, 0x48, 0x2f, 0xd0, 0xb4, 0x74, 0x93 } };
#endif

#ifndef CPFG_CREDENTIAL_PROVIDER_LABEL
static const GUID CPFG_CREDENTIAL_PROVIDER_LABEL = 
    { 0x286bbff3, 0xbad4, 0x438f, { 0xb0, 0x07, 0x79, 0xb7, 0x26, 0x7c, 0x3d, 0x48 } };
#endif

// CREDENTIAL_PROVIDER_NO_DEFAULT may not be defined in older SDKs
#ifndef CREDENTIAL_PROVIDER_NO_DEFAULT
#define CREDENTIAL_PROVIDER_NO_DEFAULT ((DWORD)-1)
#endif

// Registry paths
#define TITAN_KEY_CP_REGISTRY_PATH L"SOFTWARE\\TitanKeyCP\\Credentials"
#define TITAN_KEY_CP_RELYING_PARTY_ID L"windows.local"

// Credential provider constants
#define TITAN_KEY_CP_TILE_IMAGE 100
#define MAX_USERNAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 256
#define MAX_DOMAIN_LENGTH 256

// Field IDs for credential tile
enum TITAN_KEY_FIELD_ID {
    TKFI_TILEIMAGE = 0,
    TKFI_LABEL = 1,
    TKFI_USERNAME = 2,
    TKFI_STATUS = 3,
    TKFI_SUBMIT_BUTTON = 4,
    TKFI_NUM_FIELDS = 5
};

// Debug logging (disabled in release)
#ifdef _DEBUG
#define TITAN_LOG(msg) OutputDebugStringW(L"[TitanKeyCP] " msg L"\n")
#define TITAN_LOG_HR(msg, hr) { \
    WCHAR _buf[512]; \
    swprintf_s(_buf, L"[TitanKeyCP] " msg L" HR=0x%08X\n", hr); \
    OutputDebugStringW(_buf); \
}
#else
#define TITAN_LOG(msg)
#define TITAN_LOG_HR(msg, hr)
#endif

// Helper class for COM reference counting
template<typename T>
class ComPtr {
public:
    ComPtr() : m_ptr(nullptr) {}
    ComPtr(T* ptr) : m_ptr(ptr) { if (m_ptr) m_ptr->AddRef(); }
    ComPtr(const ComPtr& other) : m_ptr(other.m_ptr) { if (m_ptr) m_ptr->AddRef(); }
    ComPtr(ComPtr&& other) noexcept : m_ptr(other.m_ptr) { other.m_ptr = nullptr; }
    ~ComPtr() { if (m_ptr) m_ptr->Release(); }

    ComPtr& operator=(const ComPtr& other) {
        if (this != &other) {
            if (m_ptr) m_ptr->Release();
            m_ptr = other.m_ptr;
            if (m_ptr) m_ptr->AddRef();
        }
        return *this;
    }

    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            if (m_ptr) m_ptr->Release();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }

    T* operator->() const { return m_ptr; }
    T** operator&() { return &m_ptr; }
    T* Get() const { return m_ptr; }
    void Reset() { if (m_ptr) { m_ptr->Release(); m_ptr = nullptr; } }

    void Attach(T* ptr) {
        if (m_ptr) m_ptr->Release();
        m_ptr = ptr;
    }

    T* Detach() {
        T* ptr = m_ptr;
        m_ptr = nullptr;
        return ptr;
    }

private:
    T* m_ptr;
};

// Secure string helper for password handling
class SecureString {
public:
    SecureString() = default;
    explicit SecureString(const std::wstring& str) : m_data(str) {}
    ~SecureString() { Clear(); }

    void Clear() {
        if (!m_data.empty()) {
            SecureZeroMemory(&m_data[0], m_data.size() * sizeof(wchar_t));
            m_data.clear();
        }
    }

    void Set(const wchar_t* str) {
        Clear();
        if (str) m_data = str;
    }

    const wchar_t* Get() const { return m_data.c_str(); }
    size_t Length() const { return m_data.length(); }
    bool Empty() const { return m_data.empty(); }

private:
    std::wstring m_data;
};
