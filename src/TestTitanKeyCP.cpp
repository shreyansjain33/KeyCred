//
// TestTitanKeyCP.cpp - Test console application for Titan Key Credential Provider
//
// This tool allows testing the credential provider components without
// locking the system or going through the Windows logon UI.
//

#include "common.h"
#include "CredentialStorage.h"
#include "WebAuthnHelper.h"

#include <iostream>
#include <string>
#include <sddl.h>

// Command line options
struct Options {
    bool showHelp = false;
    bool testAll = false;
    bool testStorage = false;
    bool testWebAuthn = false;
    bool testRegistration = false;
    bool setupCredential = false;
    bool listCredentials = false;
    std::wstring username;
    std::wstring password;
    std::wstring domain = L".";
};

void PrintBanner() {
    std::wcout << L"\n";
    std::wcout << L"==========================================\n";
    std::wcout << L" Titan Key Credential Provider Test Tool\n";
    std::wcout << L"==========================================\n";
    std::wcout << L"\n";
}

void PrintHelp() {
    std::wcout << L"Usage: TestTitanKeyCP.exe [options]\n\n";
    std::wcout << L"Options:\n";
    std::wcout << L"  --help, -h          Show this help message\n";
    std::wcout << L"  --test-all          Run all tests\n";
    std::wcout << L"  --test-storage      Test credential storage (DPAPI)\n";
    std::wcout << L"  --test-webauthn     Test WebAuthn with Titan Key\n";
    std::wcout << L"  --test-registration Check if DLL is properly registered\n";
    std::wcout << L"  --setup             Setup credentials for a user\n";
    std::wcout << L"  --list              List stored credentials\n";
    std::wcout << L"  --user <username>   Username for setup\n";
    std::wcout << L"  --password <pass>   Password for setup\n";
    std::wcout << L"  --domain <domain>   Domain (default: . for local)\n";
    std::wcout << L"\n";
    std::wcout << L"Examples:\n";
    std::wcout << L"  TestTitanKeyCP.exe --test-all\n";
    std::wcout << L"  TestTitanKeyCP.exe --setup --user TestUser --password 1234\n";
    std::wcout << L"  TestTitanKeyCP.exe --test-webauthn\n";
    std::wcout << L"\n";
}

Options ParseCommandLine(int argc, wchar_t* argv[]) {
    Options opts;
    
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        
        if (arg == L"--help" || arg == L"-h") {
            opts.showHelp = true;
        } else if (arg == L"--test-all") {
            opts.testAll = true;
        } else if (arg == L"--test-storage") {
            opts.testStorage = true;
        } else if (arg == L"--test-webauthn") {
            opts.testWebAuthn = true;
        } else if (arg == L"--test-registration") {
            opts.testRegistration = true;
        } else if (arg == L"--setup") {
            opts.setupCredential = true;
        } else if (arg == L"--list") {
            opts.listCredentials = true;
        } else if (arg == L"--user" && i + 1 < argc) {
            opts.username = argv[++i];
        } else if (arg == L"--password" && i + 1 < argc) {
            opts.password = argv[++i];
        } else if (arg == L"--domain" && i + 1 < argc) {
            opts.domain = argv[++i];
        }
    }
    
    return opts;
}

std::wstring GetCurrentUserSid() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return L"";
    }

    DWORD tokenInfoLen = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoLen);

    std::vector<BYTE> buffer(tokenInfoLen);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), tokenInfoLen, &tokenInfoLen)) {
        CloseHandle(hToken);
        return L"";
    }

    CloseHandle(hToken);

    TOKEN_USER* tokenUser = (TOKEN_USER*)buffer.data();
    LPWSTR sidString = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidString)) {
        return L"";
    }

    std::wstring result = sidString;
    LocalFree(sidString);
    return result;
}

std::wstring GetUserSid(const std::wstring& username, const std::wstring& domain) {
    std::wstring fullName = (domain == L"." || domain.empty()) ? username : domain + L"\\" + username;
    
    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sidBuffer);
    WCHAR domainBuffer[256];
    DWORD domainSize = 256;
    SID_NAME_USE sidUse;

    if (!LookupAccountNameW(nullptr, fullName.c_str(), sidBuffer, &sidSize, 
                           domainBuffer, &domainSize, &sidUse)) {
        // Try without domain
        sidSize = sizeof(sidBuffer);
        domainSize = 256;
        if (!LookupAccountNameW(nullptr, username.c_str(), sidBuffer, &sidSize,
                               domainBuffer, &domainSize, &sidUse)) {
            return L"";
        }
    }

    LPWSTR sidString = nullptr;
    if (!ConvertSidToStringSidW((PSID)sidBuffer, &sidString)) {
        return L"";
    }

    std::wstring result = sidString;
    LocalFree(sidString);
    return result;
}

//
// Test: Credential Storage
//
bool TestCredentialStorage() {
    std::wcout << L"\n--- Testing Credential Storage (DPAPI) ---\n\n";
    
    CredentialStorage storage;
    bool success = true;
    
    // Test password encryption
    std::wcout << L"[*] Testing password encryption...\n";
    std::vector<BYTE> encrypted;
    HRESULT hr = CredentialStorage::EncryptPassword(L"TestPassword123", encrypted);
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] Password encrypted (" << encrypted.size() << L" bytes)\n";
    } else {
        std::wcout << L"    [FAIL] Encryption failed: 0x" << std::hex << hr << std::dec << L"\n";
        success = false;
    }
    
    // Test decryption
    if (SUCCEEDED(hr)) {
        std::wcout << L"[*] Testing password decryption...\n";
        SecureString decrypted;
        hr = storage.DecryptPassword(encrypted, decrypted);
        
        if (SUCCEEDED(hr)) {
            if (wcscmp(decrypted.Get(), L"TestPassword123") == 0) {
                std::wcout << L"    [OK] Password decrypted and matches\n";
            } else {
                std::wcout << L"    [FAIL] Decrypted password doesn't match\n";
                success = false;
            }
        } else {
            std::wcout << L"    [FAIL] Decryption failed: 0x" << std::hex << hr << std::dec << L"\n";
            success = false;
        }
    }
    
    // Test full storage cycle with current user
    std::wcout << L"[*] Testing credential store/retrieve...\n";
    std::wstring testSid = L"S-1-5-21-TEST-USER-12345";  // Fake SID for testing
    
    hr = storage.StoreCredential(
        testSid.c_str(),
        L"TestUser",
        L".",
        L"1234",
        nullptr, 0,   // No credential ID
        nullptr, 0,   // No public key
        TITAN_KEY_CP_RELYING_PARTY_ID);
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] Credential stored\n";
        
        // Retrieve it
        CredentialStorage::UserCredential cred;
        hr = storage.GetCredential(testSid.c_str(), cred);
        
        if (SUCCEEDED(hr)) {
            std::wcout << L"    [OK] Credential retrieved\n";
            std::wcout << L"         Username: " << cred.username << L"\n";
            std::wcout << L"         Domain: " << cred.domain << L"\n";
            
            // Decrypt and verify
            SecureString password;
            hr = storage.DecryptPassword(cred.encryptedPassword, password);
            if (SUCCEEDED(hr) && wcscmp(password.Get(), L"1234") == 0) {
                std::wcout << L"    [OK] Password verified\n";
            } else {
                std::wcout << L"    [FAIL] Password verification failed\n";
                success = false;
            }
        } else {
            std::wcout << L"    [FAIL] Credential retrieve failed: 0x" << std::hex << hr << std::dec << L"\n";
            success = false;
        }
        
        // Clean up test credential
        storage.DeleteCredential(testSid.c_str());
    } else {
        std::wcout << L"    [FAIL] Credential store failed: 0x" << std::hex << hr << std::dec << L"\n";
        std::wcout << L"         (This may fail without admin privileges)\n";
        success = false;
    }
    
    return success;
}

//
// Test: WebAuthn
//
bool TestWebAuthn() {
    std::wcout << L"\n--- Testing WebAuthn (Titan Key) ---\n\n";
    
    WebAuthnHelper webauthn;
    bool success = true;
    
    // Initialize
    std::wcout << L"[*] Initializing WebAuthn...\n";
    HRESULT hr = webauthn.Initialize();
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] WebAuthn initialized\n";
        std::wcout << L"         API Version: " << webauthn.GetApiVersion() << L"\n";
        std::wcout << L"         Available: " << (webauthn.IsAvailable() ? L"Yes" : L"No") << L"\n";
    } else {
        std::wcout << L"    [FAIL] WebAuthn initialization failed: 0x" << std::hex << hr << std::dec << L"\n";
        return false;
    }
    
    // Test challenge generation
    std::wcout << L"[*] Testing challenge generation...\n";
    std::vector<BYTE> challenge;
    hr = WebAuthnHelper::GenerateChallenge(challenge, 32);
    
    if (SUCCEEDED(hr) && challenge.size() == 32) {
        std::wcout << L"    [OK] Challenge generated (32 bytes)\n";
    } else {
        std::wcout << L"    [FAIL] Challenge generation failed\n";
        success = false;
    }
    
    // Test actual key interaction (requires user action)
    std::wcout << L"\n[*] Ready to test Titan Key authentication\n";
    std::wcout << L"    This will prompt you to touch your security key.\n";
    std::wcout << L"\n    Press Enter to continue (or Ctrl+C to skip)...\n";
    
    std::wstring dummy;
    std::getline(std::wcin, dummy);
    
    std::wcout << L"[*] Requesting assertion from Titan Key...\n";
    std::wcout << L"    Please touch your security key when it blinks...\n\n";
    
    WebAuthnHelper::AssertionResult assertion;
    hr = webauthn.GetAssertion(
        GetConsoleWindow(),
        TITAN_KEY_CP_RELYING_PARTY_ID,
        challenge,
        nullptr,  // Allow any credential
        assertion);
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] Assertion received!\n";
        std::wcout << L"         Credential ID: " << assertion.credentialId.size() << L" bytes\n";
        std::wcout << L"         Signature: " << assertion.signature.size() << L" bytes\n";
        std::wcout << L"         Authenticator Data: " << assertion.authenticatorData.size() << L" bytes\n";
    } else {
        std::wcout << L"    [FAIL] Assertion failed: 0x" << std::hex << hr << std::dec << L"\n";
        std::wcout << L"         " << webauthn.GetLastErrorDescription() << L"\n";
        success = false;
    }
    
    return success;
}

//
// Test: DLL Registration
//
bool TestRegistration() {
    std::wcout << L"\n--- Testing DLL Registration ---\n\n";
    
    bool success = true;
    HKEY hKey = nullptr;
    
    // Check Credential Provider registration
    std::wcout << L"[*] Checking Credential Provider registration...\n";
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
        0,
        KEY_READ,
        &hKey);
    
    if (result == ERROR_SUCCESS) {
        std::wcout << L"    [OK] Credential Provider is registered\n";
        RegCloseKey(hKey);
    } else {
        std::wcout << L"    [FAIL] Credential Provider is NOT registered\n";
        std::wcout << L"         Run Register.bat as Administrator\n";
        success = false;
    }
    
    // Check COM registration
    std::wcout << L"[*] Checking COM registration...\n";
    result = RegOpenKeyExW(
        HKEY_CLASSES_ROOT,
        L"CLSID\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}\\InProcServer32",
        0,
        KEY_READ,
        &hKey);
    
    if (result == ERROR_SUCCESS) {
        WCHAR dllPath[MAX_PATH] = {0};
        DWORD pathSize = sizeof(dllPath);
        result = RegQueryValueExW(hKey, nullptr, nullptr, nullptr, (LPBYTE)dllPath, &pathSize);
        
        if (result == ERROR_SUCCESS) {
            std::wcout << L"    [OK] COM class registered\n";
            std::wcout << L"         DLL Path: " << dllPath << L"\n";
            
            // Check if DLL exists
            if (GetFileAttributesW(dllPath) != INVALID_FILE_ATTRIBUTES) {
                std::wcout << L"    [OK] DLL file exists\n";
            } else {
                std::wcout << L"    [WARN] DLL file not found at registered path\n";
            }
        }
        RegCloseKey(hKey);
    } else {
        std::wcout << L"    [FAIL] COM class is NOT registered\n";
        success = false;
    }
    
    return success;
}

//
// Setup Credential
//
bool SetupCredential(const std::wstring& username, const std::wstring& password, const std::wstring& domain) {
    std::wcout << L"\n--- Setting Up Credential ---\n\n";
    
    if (username.empty() || password.empty()) {
        std::wcout << L"[FAIL] Username and password are required\n";
        return false;
    }
    
    // Get user SID
    std::wcout << L"[*] Looking up user SID for: " << username << L"\n";
    std::wstring userSid = GetUserSid(username, domain);
    
    if (userSid.empty()) {
        std::wcout << L"    [FAIL] Could not resolve user SID\n";
        std::wcout << L"         Make sure the username is correct\n";
        return false;
    }
    
    std::wcout << L"    [OK] User SID: " << userSid << L"\n";
    
    // Store credential
    std::wcout << L"[*] Storing encrypted credential...\n";
    
    CredentialStorage storage;
    HRESULT hr = storage.StoreCredential(
        userSid.c_str(),
        username.c_str(),
        domain.c_str(),
        password.c_str(),
        nullptr, 0,   // No credential ID yet
        nullptr, 0,   // No public key yet
        TITAN_KEY_CP_RELYING_PARTY_ID);
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] Credential stored successfully\n";
        std::wcout << L"\n";
        std::wcout << L"Setup complete! The user can now authenticate using Titan Key.\n";
        std::wcout << L"\n";
        std::wcout << L"To test:\n";
        std::wcout << L"  1. Make sure the DLL is registered (run Register.bat)\n";
        std::wcout << L"  2. Lock your workstation (Win+L)\n";
        std::wcout << L"  3. Select the 'Titan Key' tile\n";
        std::wcout << L"  4. Touch your Titan Key when prompted\n";
        return true;
    } else {
        std::wcout << L"    [FAIL] Failed to store credential: 0x" << std::hex << hr << std::dec << L"\n";
        std::wcout << L"         Make sure you're running as Administrator\n";
        return false;
    }
}

//
// List Stored Credentials
//
void ListCredentials() {
    std::wcout << L"\n--- Stored Credentials ---\n\n";
    
    CredentialStorage storage;
    std::vector<std::wstring> userSids;
    
    HRESULT hr = storage.EnumerateUsers(userSids);
    if (FAILED(hr)) {
        std::wcout << L"[FAIL] Could not enumerate credentials: 0x" << std::hex << hr << std::dec << L"\n";
        return;
    }
    
    if (userSids.empty()) {
        std::wcout << L"No credentials stored.\n";
        std::wcout << L"Use --setup to add credentials.\n";
        return;
    }
    
    std::wcout << L"Found " << userSids.size() << L" stored credential(s):\n\n";
    
    for (const auto& sid : userSids) {
        CredentialStorage::UserCredential cred;
        hr = storage.GetCredential(sid.c_str(), cred);
        
        if (SUCCEEDED(hr)) {
            std::wcout << L"  User: " << cred.username << L"\n";
            std::wcout << L"  Domain: " << cred.domain << L"\n";
            std::wcout << L"  SID: " << sid << L"\n";
            std::wcout << L"  Credential ID: " << (cred.credentialId.empty() ? L"Not enrolled" : L"Enrolled") << L"\n";
            std::wcout << L"\n";
        }
    }
}

//
// Main
//
int wmain(int argc, wchar_t* argv[]) {
    PrintBanner();
    
    Options opts = ParseCommandLine(argc, argv);
    
    if (opts.showHelp || argc == 1) {
        PrintHelp();
        return 0;
    }
    
    bool allPassed = true;
    
    if (opts.listCredentials) {
        ListCredentials();
    }
    
    if (opts.setupCredential) {
        if (opts.username.empty()) {
            std::wcout << L"[*] Enter username: ";
            std::getline(std::wcin, opts.username);
        }
        if (opts.password.empty()) {
            std::wcout << L"[*] Enter password: ";
            std::getline(std::wcin, opts.password);
        }
        
        if (!SetupCredential(opts.username, opts.password, opts.domain)) {
            allPassed = false;
        }
    }
    
    if (opts.testAll || opts.testRegistration) {
        if (!TestRegistration()) {
            allPassed = false;
        }
    }
    
    if (opts.testAll || opts.testStorage) {
        if (!TestCredentialStorage()) {
            allPassed = false;
        }
    }
    
    if (opts.testAll || opts.testWebAuthn) {
        if (!TestWebAuthn()) {
            allPassed = false;
        }
    }
    
    std::wcout << L"\n==========================================\n";
    if (allPassed) {
        std::wcout << L" All tests PASSED\n";
    } else {
        std::wcout << L" Some tests FAILED\n";
    }
    std::wcout << L"==========================================\n\n";
    
    return allPassed ? 0 : 1;
}
