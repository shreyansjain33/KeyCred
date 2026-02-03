#pragma once

#include "common.h"
#include "CredentialStorage.h"
#include "WebAuthnHelper.h"

// Forward declarations
class TitanKeyCredentialProvider;

//
// TitanKeyCredential - Individual credential tile for a user
//
// Implements ICredentialProviderCredential2 for the V2 credential provider model,
// and IConnectableCredentialProviderCredential for async authentication.
//
class TitanKeyCredential : 
    public ICredentialProviderCredential2,
    public IConnectableCredentialProviderCredential
{
public:
    TitanKeyCredential();
    virtual ~TitanKeyCredential();

    // Initialize with user information
    HRESULT Initialize(
        TitanKeyCredentialProvider* provider,
        ICredentialProviderUser* user,
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus);

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(
        DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz) override;
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) override;
    IFACEMETHODIMP GetCheckboxValue(
        DWORD dwFieldID,
        BOOL* pbChecked,
        PWSTR* ppwszLabel) override;
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) override;
    IFACEMETHODIMP GetComboBoxValueCount(
        DWORD dwFieldID,
        DWORD* pcItems,
        DWORD* pdwSelectedItem) override;
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem) override;
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz) override;
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) override;
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) override;
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID) override;
    IFACEMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;
    IFACEMETHODIMP ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(PWSTR* ppwszSid) override;

    // IConnectableCredentialProviderCredential
    IFACEMETHODIMP Connect(IQueryContinueWithStatus* pqcws) override;
    IFACEMETHODIMP Disconnect() override;

private:
    // Helper methods
    HRESULT PerformAuthentication(IQueryContinueWithStatus* pqcws);
    HRESULT CreateKerbInteractiveLogon(
        PCWSTR domain,
        PCWSTR username,
        PCWSTR password,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    PWSTR DuplicateString(PCWSTR source);

    // Reference counting
    LONG m_refCount;

    // Provider back-reference
    TitanKeyCredentialProvider* m_provider;

    // Credential provider events
    ICredentialProviderCredentialEvents* m_events;

    // User information
    ComPtr<ICredentialProviderUser> m_user;
    std::wstring m_userSid;
    std::wstring m_username;
    std::wstring m_domain;
    std::wstring m_qualifiedUsername;

    // Usage scenario
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;

    // Field values
    std::wstring m_statusText;

    // Authentication state
    BOOL m_authenticated;
    SecureString m_password;

    // Helpers
    CredentialStorage m_credentialStorage;
    WebAuthnHelper m_webAuthn;
};
