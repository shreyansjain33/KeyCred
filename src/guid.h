#pragma once

#include <guiddef.h>

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
// CLSID for the Titan Key Credential Provider
// Declared as extern - defined in dll.cpp
EXTERN_C const GUID CLSID_TitanKeyCredentialProvider;

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
