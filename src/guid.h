#pragma once

#include <guiddef.h>

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
// CLSID for the Titan Key Credential Provider
DEFINE_GUID(CLSID_TitanKeyCredentialProvider,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

// String version of the CLSID for registry operations
#define CLSID_TitanKeyCredentialProvider_String L"{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"

// Credential Provider registry path
#define CREDENTIAL_PROVIDER_REGKEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\"
#define CREDENTIAL_PROVIDER_FILTER_REGKEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\"

// COM Class Factory declarations
class TitanKeyCredentialProviderFactory : public IClassFactory {
public:
    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // IClassFactory
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv);
    IFACEMETHODIMP LockServer(BOOL bLock);

    TitanKeyCredentialProviderFactory() : m_refCount(1) {}

private:
    ~TitanKeyCredentialProviderFactory() = default;
    LONG m_refCount;
};
