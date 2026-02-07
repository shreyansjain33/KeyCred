#pragma once

//==============================================================================
// TitanKeyCredentialProvider.h - Main credential provider implementation
//==============================================================================
//
// This is the main entry point for the Windows Credential Provider.
// Windows LogonUI loads this COM object to enumerate available login options.
//
// RESPONSIBILITIES:
// - Enumerate users who have enrolled Titan Keys
// - Create TitanKeyCredential instances for each eligible user
// - Manage the lifecycle of credential tiles
// - Respond to Windows credential provider events
//
// COM REGISTRATION:
// - CLSID: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
// - Registered under: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
//                     Authentication\Credential Providers\{CLSID}
//
// SUPPORTED SCENARIOS:
// - CPUS_LOGON: Initial Windows logon
// - CPUS_UNLOCK_WORKSTATION: Unlocking a locked workstation
// - CPUS_CREDUI: Credential UI prompts (e.g., UAC)
// - CPUS_PLAP: Pre-logon access provider (network selection)
//
//==============================================================================

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

    // Notify LogonUI that credentials changed (e.g. after tile selection to trigger Connect)
    void NotifyCredentialsChanged();

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
