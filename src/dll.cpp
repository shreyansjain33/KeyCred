//
// dll.cpp - DLL entry points and COM class factory implementation
//

#include "common.h"
#include "guid.h"
#include "TitanKeyCredentialProvider.h"

// Global module instance handle
HINSTANCE g_hInstance = nullptr;

// Global reference count for DLL
static LONG g_cRef = 0;

// DLL reference counting
void DllAddRef() {
    InterlockedIncrement(&g_cRef);
}

void DllRelease() {
    InterlockedDecrement(&g_cRef);
}

//
// DLL Entry Point
//
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID /*lpReserved*/) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        g_hInstance = hInstance;
        DisableThreadLibraryCalls(hInstance);
        TITAN_LOG(L"DllMain: DLL_PROCESS_ATTACH");
        break;

    case DLL_PROCESS_DETACH:
        TITAN_LOG(L"DllMain: DLL_PROCESS_DETACH");
        break;
    }
    return TRUE;
}

//
// DllCanUnloadNow - Called by COM to determine if the DLL can be unloaded
//
STDAPI DllCanUnloadNow() {
    TITAN_LOG(L"DllCanUnloadNow called");
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

//
// DllGetClassObject - Called by COM to get a class factory for the specified CLSID
//
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    TITAN_LOG(L"DllGetClassObject called");

    if (ppv == nullptr) {
        return E_INVALIDARG;
    }

    *ppv = nullptr;

    HRESULT hr = CLASS_E_CLASSNOTAVAILABLE;

    if (IsEqualCLSID(rclsid, CLSID_TitanKeyCredentialProvider)) {
        TitanKeyCredentialProviderFactory* factory = new (std::nothrow) TitanKeyCredentialProviderFactory();
        if (factory) {
            hr = factory->QueryInterface(riid, ppv);
            factory->Release();
        } else {
            hr = E_OUTOFMEMORY;
        }
    }

    TITAN_LOG_HR(L"DllGetClassObject", hr);
    return hr;
}

//
// DllRegisterServer - Registers the credential provider in the registry
//
STDAPI DllRegisterServer() {
    TITAN_LOG(L"DllRegisterServer called");

    HRESULT hr = S_OK;
    HKEY hKey = nullptr;
    HKEY hSubKey = nullptr;

    // Get the DLL path
    WCHAR szModulePath[MAX_PATH];
    if (GetModuleFileNameW(g_hInstance, szModulePath, ARRAYSIZE(szModulePath)) == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Register the COM class
    // Create HKCR\CLSID\{GUID}
    std::wstring clsidPath = L"CLSID\\";
    clsidPath += CLSID_TitanKeyCredentialProvider_String;

    LONG result = RegCreateKeyExW(
        HKEY_CLASSES_ROOT,
        clsidPath.c_str(),
        0, nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        nullptr);

    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    // Set the default value
    const WCHAR* providerName = L"Titan Key Credential Provider";
    result = RegSetValueExW(hKey, nullptr, 0, REG_SZ,
        (const BYTE*)providerName, (DWORD)((wcslen(providerName) + 1) * sizeof(WCHAR)));

    if (result != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return HRESULT_FROM_WIN32(result);
    }

    // Create InProcServer32 subkey
    result = RegCreateKeyExW(hKey, L"InProcServer32", 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hSubKey, nullptr);

    if (result != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return HRESULT_FROM_WIN32(result);
    }

    // Set the DLL path
    result = RegSetValueExW(hSubKey, nullptr, 0, REG_SZ,
        (const BYTE*)szModulePath, (DWORD)((wcslen(szModulePath) + 1) * sizeof(WCHAR)));

    if (result == ERROR_SUCCESS) {
        // Set the threading model
        const WCHAR* threadingModel = L"Apartment";
        result = RegSetValueExW(hSubKey, L"ThreadingModel", 0, REG_SZ,
            (const BYTE*)threadingModel, (DWORD)((wcslen(threadingModel) + 1) * sizeof(WCHAR)));
    }

    RegCloseKey(hSubKey);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    // Register as a Credential Provider
    std::wstring cpPath = CREDENTIAL_PROVIDER_REGKEY;
    cpPath += CLSID_TitanKeyCredentialProvider_String;

    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        cpPath.c_str(),
        0, nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        nullptr);

    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    result = RegSetValueExW(hKey, nullptr, 0, REG_SZ,
        (const BYTE*)providerName, (DWORD)((wcslen(providerName) + 1) * sizeof(WCHAR)));

    RegCloseKey(hKey);

    TITAN_LOG_HR(L"DllRegisterServer completed", hr);
    return HRESULT_FROM_WIN32(result);
}

//
// DllUnregisterServer - Removes credential provider registration from the registry
//
STDAPI DllUnregisterServer() {
    TITAN_LOG(L"DllUnregisterServer called");

    // Remove credential provider registration
    std::wstring cpPath = CREDENTIAL_PROVIDER_REGKEY;
    cpPath += CLSID_TitanKeyCredentialProvider_String;
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, cpPath.c_str());

    // Remove COM registration
    std::wstring clsidPath = L"CLSID\\";
    clsidPath += CLSID_TitanKeyCredentialProvider_String;
    clsidPath += L"\\InProcServer32";
    RegDeleteKeyW(HKEY_CLASSES_ROOT, clsidPath.c_str());

    clsidPath = L"CLSID\\";
    clsidPath += CLSID_TitanKeyCredentialProvider_String;
    RegDeleteKeyW(HKEY_CLASSES_ROOT, clsidPath.c_str());

    return S_OK;
}

//
// TitanKeyCredentialProviderFactory Implementation
//

IFACEMETHODIMP TitanKeyCredentialProviderFactory::QueryInterface(REFIID riid, void** ppv) {
    if (ppv == nullptr) {
        return E_INVALIDARG;
    }

    *ppv = nullptr;

    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) TitanKeyCredentialProviderFactory::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

IFACEMETHODIMP_(ULONG) TitanKeyCredentialProviderFactory::Release() {
    LONG count = InterlockedDecrement(&m_refCount);
    if (count == 0) {
        delete this;
    }
    return count;
}

IFACEMETHODIMP TitanKeyCredentialProviderFactory::CreateInstance(
    IUnknown* pUnkOuter,
    REFIID riid,
    void** ppv)
{
    TITAN_LOG(L"TitanKeyCredentialProviderFactory::CreateInstance");

    if (ppv == nullptr) {
        return E_INVALIDARG;
    }

    *ppv = nullptr;

    if (pUnkOuter != nullptr) {
        return CLASS_E_NOAGGREGATION;
    }

    TitanKeyCredentialProvider* provider = new (std::nothrow) TitanKeyCredentialProvider();
    if (provider == nullptr) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = provider->QueryInterface(riid, ppv);
    provider->Release();

    TITAN_LOG_HR(L"CreateInstance", hr);
    return hr;
}

IFACEMETHODIMP TitanKeyCredentialProviderFactory::LockServer(BOOL bLock) {
    if (bLock) {
        DllAddRef();
    } else {
        DllRelease();
    }
    return S_OK;
}
