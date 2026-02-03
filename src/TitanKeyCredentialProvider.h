#pragma once

#include "common.h"
#include "TitanKeyCredential.h"
#include "CredentialStorage.h"

//
// TitanKeyCredentialProvider - Main credential provider implementation
//
// Implements ICredentialProvider and ICredentialProviderSetUserArray for
// the V2 credential provider model.
//
class TitanKeyCredentialProvider :
    public ICredentialProvider,
    public ICredentialProviderSetUserArray
{
public:
    TitanKeyCredentialProvider();
    virtual ~TitanKeyCredentialProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags) override;
    IFACEMETHODIMP SetSerialization(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;
    IFACEMETHODIMP Advise(
        ICredentialProviderEvents* pcpe,
        UINT_PTR upAdviseContext) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount) override;
    IFACEMETHODIMP GetFieldDescriptorAt(
        DWORD dwIndex,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;
    IFACEMETHODIMP GetCredentialCount(
        DWORD* pdwCount,
        DWORD* pdwDefault,
        BOOL* pbAutoLogonWithDefault) override;
    IFACEMETHODIMP GetCredentialAt(
        DWORD dwIndex,
        ICredentialProviderCredential** ppcpc) override;

    // ICredentialProviderSetUserArray
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override;

private:
    // Helper to create credentials for users with stored Titan Key credentials
    HRESULT CreateCredentialsForUsers();
    void ReleaseCredentials();

    // Reference counting
    LONG m_refCount;

    // Usage scenario
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    DWORD m_cpusFlags;

    // Provider events
    ICredentialProviderEvents* m_events;
    UINT_PTR m_adviseContext;

    // User array
    ComPtr<ICredentialProviderUserArray> m_userArray;

    // Credentials (one per user with stored credentials)
    std::vector<TitanKeyCredential*> m_credentials;

    // Credential storage
    CredentialStorage m_credentialStorage;
};
