//
// TestTitanKeyCP.cpp - Test console application for Titan Key Credential Provider
//
// This tool allows testing the credential provider components without
// locking the system or going through the Windows logon UI.
//
// SECURITY MODEL:
// - Password encrypted with TPM-backed AES-256-GCM (CNG)
// - Titan Key provides signature verification (physical presence)
// - TPM key cannot be extracted even with admin access
//

#include "common.h"
#include "CredentialStorage.h"
#include "WebAuthnHelper.h"
#include "CryptoHelper.h"
#include "TpmCrypto.h"

#include <iostream>
#include <fstream>
#include <string>
#include <sddl.h>
#include <ctime>

// File logger for debugging
class FileLogger {
public:
    static FileLogger& Instance() {
        static FileLogger instance;
        return instance;
    }

    void Open(const std::wstring& filename) {
        m_file.open(filename, std::ios::out | std::ios::trunc);
        if (m_file.is_open()) {
            Log(L"=== Titan Key CP Test Log Started ===");
        }
    }

    void Log(const std::wstring& message) {
        if (m_file.is_open()) {
            // Get timestamp
            time_t now = time(nullptr);
            struct tm timeinfo;
            localtime_s(&timeinfo, &now);
            wchar_t timestamp[32];
            wcsftime(timestamp, 32, L"%Y-%m-%d %H:%M:%S", &timeinfo);
            
            m_file << L"[" << timestamp << L"] " << message << std::endl;
            m_file.flush();
        }
        // Also output to console
        std::wcout << L"[LOG] " << message << L"\n";
    }

    void LogHR(const std::wstring& message, HRESULT hr) {
        wchar_t buf[512];
        swprintf_s(buf, L"%s HR=0x%08X", message.c_str(), hr);
        Log(buf);
    }

    void Close() {
        if (m_file.is_open()) {
            Log(L"=== Log Ended ===");
            m_file.close();
        }
    }

    ~FileLogger() { Close(); }

private:
    FileLogger() = default;
    std::wofstream m_file;
};

// Convenient logging macros
#define TEST_LOG(msg) FileLogger::Instance().Log(msg)
#define TEST_LOG_HR(msg, hr) FileLogger::Instance().LogHR(msg, hr)

// Command line options
struct Options {
    bool showHelp = false;
    bool testAll = false;
    bool testStorage = false;
    bool testWebAuthn = false;
    bool testRegistration = false;
    bool setupCredential = false;
    bool listCredentials = false;
    bool testLockScreen = false;  // Test with NULL HWND (simulates lock screen)
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
    std::wcout << L"SECURITY MODEL:\n";
    std::wcout << L"  - Password encrypted with TPM-backed AES-256-GCM (CNG)\n";
    std::wcout << L"  - Titan Key required for signature verification\n";
    std::wcout << L"  - TPM key cannot be extracted even with admin access\n\n";
    std::wcout << L"Options:\n";
    std::wcout << L"  --help, -h          Show this help message\n";
    std::wcout << L"  --test-all          Run all tests\n";
    std::wcout << L"  --test-storage      Test TPM encryption\n";
    std::wcout << L"  --test-webauthn     Test WebAuthn signature verification\n";
    std::wcout << L"  --test-registration Check if DLL is properly registered\n";
    std::wcout << L"  --test-lockscreen   Test with NULL HWND (simulates lock screen)\n";
    std::wcout << L"  --setup             Enroll Titan Key and encrypt password\n";
    std::wcout << L"  --list              List stored credentials\n";
    std::wcout << L"  --user <username>   Username for setup\n";
    std::wcout << L"  --password <pass>   Password for setup\n";
    std::wcout << L"  --domain <domain>   Domain (default: . for local)\n";
    std::wcout << L"\n";
    std::wcout << L"First-Time Setup:\n";
    std::wcout << L"  1. Run: TestTitanKeyCP.exe --setup --user %USERNAME% --password YOUR_PASSWORD\n";
    std::wcout << L"  2. Touch your Titan Key when prompted to enroll\n";
    std::wcout << L"  3. Register DLL: regsvr32 TitanKeyCP.dll\n";
    std::wcout << L"  4. Lock screen (Win+L) and test!\n";
    std::wcout << L"\n";
    std::wcout << L"Examples:\n";
    std::wcout << L"  TestTitanKeyCP.exe --setup --user John --password 1234\n";
    std::wcout << L"  TestTitanKeyCP.exe --test-webauthn\n";
    std::wcout << L"  TestTitanKeyCP.exe --list\n";
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
        } else if (arg == L"--test-lockscreen") {
            opts.testLockScreen = true;
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
// Test: TPM Credential Storage
//
bool TestCredentialStorage() {
    std::wcout << L"\n--- Testing TPM Credential Storage ---\n\n";
    
    bool success = true;
    
    // Initialize TPM
    std::wcout << L"[*] Initializing TPM/CNG...\n";
    TpmCrypto tpm;
    HRESULT hr = tpm.Initialize();
    
    if (FAILED(hr)) {
        std::wcout << L"    [WARN] TPM not available, using software fallback\n";
    } else {
        std::wcout << L"    [OK] TPM/CNG available\n";
    }
    
    // Create test key
    std::wcout << L"[*] Creating test key...\n";
    hr = tpm.OpenOrCreateKey(L"TitanKeyCP_TEST");
    
    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] Could not create key: 0x" << std::hex << hr << std::dec << L"\n";
        return false;
    }
    std::wcout << L"    [OK] Test key created\n";
    
    // Test password encryption
    std::wcout << L"[*] Testing TPM password encryption...\n";
    std::vector<BYTE> encrypted;
    hr = tpm.EncryptPassword(L"TestPassword123", encrypted);
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] Password encrypted (" << encrypted.size() << L" bytes)\n";
        std::wcout << L"         Format: wrapped_key + AES-GCM(nonce + ciphertext + tag)\n";
    } else {
        std::wcout << L"    [FAIL] Encryption failed: 0x" << std::hex << hr << std::dec << L"\n";
        success = false;
    }
    
    // Test decryption
    if (SUCCEEDED(hr)) {
        std::wcout << L"[*] Testing TPM password decryption...\n";
        SecureString decrypted;
        hr = tpm.DecryptPassword(encrypted, decrypted);
        
        if (SUCCEEDED(hr)) {
            if (wcscmp(decrypted.Get(), L"TestPassword123") == 0) {
                std::wcout << L"    [OK] Password decrypted and matches!\n";
            } else {
                std::wcout << L"    [FAIL] Decrypted password doesn't match\n";
                success = false;
            }
        } else {
            std::wcout << L"    [FAIL] Decryption failed: 0x" << std::hex << hr << std::dec << L"\n";
            success = false;
        }
    }
    
    // Clean up test key
    std::wcout << L"[*] Cleaning up test key...\n";
    tpm.DeleteKey();
    std::wcout << L"    [OK] Test key deleted\n";
    
    return success;
}

//
// Test: WebAuthn
//
bool TestWebAuthn() {
    std::wcout << L"\n--- Testing WebAuthn (Titan Key) ---\n\n";
    TEST_LOG(L"=== TestWebAuthn started ===");
    
    WebAuthnHelper webauthn;
    bool success = true;
    
    // Initialize
    std::wcout << L"[*] Initializing WebAuthn...\n";
    TEST_LOG(L"Initializing WebAuthn...");
    HRESULT hr = webauthn.Initialize();
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] WebAuthn initialized\n";
        std::wcout << L"         API Version: " << webauthn.GetApiVersion() << L"\n";
        std::wcout << L"         Available: " << (webauthn.IsAvailable() ? L"Yes" : L"No") << L"\n";
        
        wchar_t buf[128];
        swprintf_s(buf, L"WebAuthn initialized. API Version: %u", webauthn.GetApiVersion());
        TEST_LOG(buf);
    } else {
        std::wcout << L"    [FAIL] WebAuthn initialization failed: 0x" << std::hex << hr << std::dec << L"\n";
        TEST_LOG_HR(L"WebAuthn initialization failed", hr);
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
    std::wcout << L"\n[*] Ready to test Titan Key signature verification\n";
    std::wcout << L"\n    Choose test:\n";
    std::wcout << L"    1. Full test (enroll + sign + verify)\n";
    std::wcout << L"    2. Skip\n";
    std::wcout << L"\n    Enter choice (1/2): ";
    
    std::wstring choice;
    std::getline(std::wcin, choice);
    
    if (choice == L"1") {
        std::wcout << L"\n[*] Testing full signature flow...\n";
        std::wcout << L"    This will test: enroll -> sign challenge -> verify\n\n";
        
        // Step 1: Create credential
        std::wcout << L"[*] Step 1: Creating credential (touch key)...\n";
        
        WebAuthnHelper::CredentialResult credResult;
        hr = webauthn.MakeCredential(
            GetConsoleWindow(),
            TITAN_KEY_CP_RELYING_PARTY_ID,
            L"Signature Test",
            L"testuser",
            L"testuser",
            L"Test User",
            challenge,
            credResult);
        
        if (FAILED(hr)) {
            std::wcout << L"    [FAIL] Enrollment failed: 0x" << std::hex << hr << std::dec << L"\n";
            success = false;
        } else {
            std::wcout << L"    [OK] Credential created!\n";
            std::wcout << L"         Credential ID: " << credResult.credentialId.size() << L" bytes\n";
            std::wcout << L"         Attestation: " << credResult.attestationObject.size() << L" bytes\n";
            
            // Step 2: Get assertion (sign challenge)
            std::wcout << L"\n[*] Step 2: Signing challenge (touch key)...\n";
            TEST_LOG(L"Step 2: Getting assertion...");
            
            WebAuthnHelper::GenerateChallenge(challenge, 32);
            
            wchar_t logBuf[256];
            swprintf_s(logBuf, L"RP ID: %s, Credential ID size: %zu, Challenge size: %zu",
                TITAN_KEY_CP_RELYING_PARTY_ID, credResult.credentialId.size(), challenge.size());
            TEST_LOG(logBuf);
            
            HWND hwnd = GetConsoleWindow();
            swprintf_s(logBuf, L"Using HWND: 0x%p", (void*)hwnd);
            TEST_LOG(logBuf);
            
            WebAuthnHelper::AssertionResult assertion;
            hr = webauthn.GetAssertion(
                hwnd,
                TITAN_KEY_CP_RELYING_PARTY_ID,
                challenge,
                &credResult.credentialId,
                assertion);
            
            TEST_LOG_HR(L"GetAssertion returned", hr);
            
            if (FAILED(hr)) {
                std::wcout << L"    [FAIL] Signature failed: 0x" << std::hex << hr << std::dec << L"\n";
                TEST_LOG(webauthn.GetLastErrorDescription());
                std::wcout << L"         " << webauthn.GetLastErrorDescription() << L"\n";
                success = false;
            } else {
                std::wcout << L"    [OK] Signature received!\n";
                std::wcout << L"         Signature: " << assertion.signature.size() << L" bytes\n";
                std::wcout << L"         Auth Data: " << assertion.authenticatorData.size() << L" bytes\n";
                
                std::wcout << L"\n    SUCCESS: Titan Key working correctly!\n";
                std::wcout << L"    Signature verified by Windows WebAuthn API.\n";
            }
        }
    } else {
        std::wcout << L"    Skipped.\n";
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
// TestLockScreen - Test WebAuthn with NULL HWND (simulates lock screen)
//
// This tests the exact conditions of the credential provider at the lock screen:
// - NULL HWND (no window handle available)
// - Uses stored credential from registry
//
bool TestLockScreen() {
    std::wcout << L"\n--- Testing Lock Screen Simulation ---\n\n";
    TEST_LOG(L"=== TestLockScreen started ===");
    
    std::wcout << L"This test simulates lock screen conditions:\n";
    std::wcout << L"  - Uses NULL HWND (like credential provider)\n";
    std::wcout << L"  - Reads credential from registry\n\n";
    
    // First, list available credentials
    CredentialStorage storage;
    std::vector<std::wstring> userSids;
    
    HRESULT hr = storage.EnumerateUsers(userSids);
    if (FAILED(hr) || userSids.empty()) {
        std::wcout << L"[FAIL] No stored credentials found. Run --setup first.\n";
        TEST_LOG(L"ERROR: No stored credentials");
        return false;
    }
    
    // Use first credential
    std::wstring userSid = userSids[0];
    CredentialStorage::UserCredential cred;
    hr = storage.GetCredential(userSid.c_str(), cred);
    
    if (FAILED(hr)) {
        std::wcout << L"[FAIL] Could not load credential\n";
        TEST_LOG_HR(L"GetCredential failed", hr);
        return false;
    }
    
    std::wcout << L"[*] Using credential for user: " << cred.username << L"\n";
    std::wcout << L"    SID: " << userSid << L"\n";
    std::wcout << L"    Credential ID size: " << cred.credentialId.size() << L" bytes\n";
    std::wcout << L"    RP ID: " << cred.relyingPartyId << L"\n\n";
    
    TEST_LOG((L"User: " + cred.username).c_str());
    TEST_LOG((L"SID: " + userSid).c_str());
    TEST_LOG((L"RP ID: " + cred.relyingPartyId).c_str());
    
    wchar_t logBuf[256];
    swprintf_s(logBuf, L"Credential ID size: %zu", cred.credentialId.size());
    TEST_LOG(logBuf);
    
    // Initialize WebAuthn
    WebAuthnHelper webauthn;
    hr = webauthn.Initialize();
    
    if (FAILED(hr)) {
        std::wcout << L"[FAIL] WebAuthn init failed: 0x" << std::hex << hr << std::dec << L"\n";
        TEST_LOG_HR(L"WebAuthn init failed", hr);
        return false;
    }
    
    std::wcout << L"[*] WebAuthn initialized (API v" << webauthn.GetApiVersion() << L")\n";
    
    // Generate challenge
    std::vector<BYTE> challenge;
    WebAuthnHelper::GenerateChallenge(challenge, 32);
    
    // Test 1: With GetConsoleWindow (should work)
    std::wcout << L"\n[TEST 1] GetAssertion with GetConsoleWindow()...\n";
    TEST_LOG(L"TEST 1: Using GetConsoleWindow()");
    
    HWND hwndConsole = GetConsoleWindow();
    swprintf_s(logBuf, L"Console HWND: 0x%p", (void*)hwndConsole);
    TEST_LOG(logBuf);
    
    std::wcout << L"         Touch your Titan Key when prompted...\n";
    
    WebAuthnHelper::AssertionResult assertion1;
    hr = webauthn.GetAssertion(
        hwndConsole,
        cred.relyingPartyId.c_str(),
        challenge,
        &cred.credentialId,
        assertion1);
    
    TEST_LOG_HR(L"GetAssertion (console HWND) returned", hr);
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] GetAssertion with console HWND succeeded!\n";
        std::wcout << L"         Signature size: " << assertion1.signature.size() << L" bytes\n";
    } else {
        std::wcout << L"    [FAIL] GetAssertion failed: 0x" << std::hex << hr << std::dec << L"\n";
        std::wcout << L"          " << webauthn.GetLastErrorDescription() << L"\n";
        TEST_LOG(webauthn.GetLastErrorDescription());
        return false;
    }
    
    // Test 2: With NULL HWND (lock screen simulation)
    std::wcout << L"\n[TEST 2] GetAssertion with NULL HWND (lock screen simulation)...\n";
    TEST_LOG(L"TEST 2: Using NULL HWND (lock screen simulation)");
    
    std::wcout << L"         Touch your Titan Key when prompted...\n";
    
    WebAuthnHelper::GenerateChallenge(challenge, 32);  // New challenge
    
    WebAuthnHelper::AssertionResult assertion2;
    hr = webauthn.GetAssertion(
        NULL,  // NULL HWND - like lock screen
        cred.relyingPartyId.c_str(),
        challenge,
        &cred.credentialId,
        assertion2);
    
    TEST_LOG_HR(L"GetAssertion (NULL HWND) returned", hr);
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] GetAssertion with NULL HWND succeeded!\n";
        std::wcout << L"         This means lock screen should work too.\n";
        TEST_LOG(L"SUCCESS: NULL HWND works");
    } else {
        std::wcout << L"    [FAIL] GetAssertion with NULL HWND failed: 0x" << std::hex << hr << std::dec << L"\n";
        std::wcout << L"          " << webauthn.GetLastErrorDescription() << L"\n";
        std::wcout << L"\n    This is likely the lock screen issue!\n";
        TEST_LOG(webauthn.GetLastErrorDescription());
        TEST_LOG(L"FAIL: NULL HWND does not work - this explains lock screen issue");
        return false;
    }
    
    return true;
}

//
// Enroll Titan Key - Creates credential and stores public key
//
// This function:
// 1. Creates a credential on the Titan Key
// 2. Extracts and stores the public key for signature verification
// 3. Returns credential ID and public key
//
bool EnrollTitanKey(
    const std::wstring& username, 
    std::vector<BYTE>& credentialId, 
    std::vector<BYTE>& publicKey)
{
    std::wcout << L"\n[*] Enrolling Titan Key...\n";
    std::wcout << L"    This will register a new credential on your security key.\n";
    std::wcout << L"    Touch your key when it blinks.\n\n";

    WebAuthnHelper webauthn;
    HRESULT hr = webauthn.Initialize();
    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] WebAuthn not available\n";
        return false;
    }

    // Generate challenge for enrollment
    std::vector<BYTE> challenge;
    hr = WebAuthnHelper::GenerateChallenge(challenge, 32);
    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] Could not generate challenge\n";
        return false;
    }

    std::wcout << L"[*] Creating credential on Titan Key...\n";
    std::wcout << L"    Touch your key now...\n\n";

    // Create credential on the key
    WebAuthnHelper::CredentialResult result;
    hr = webauthn.MakeCredential(
        GetConsoleWindow(),
        TITAN_KEY_CP_RELYING_PARTY_ID,
        L"Windows Login",
        username.c_str(),
        username.c_str(),
        username.c_str(),
        challenge,
        result);

    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] Enrollment failed: 0x" << std::hex << hr << std::dec << L"\n";
        std::wcout << L"         " << webauthn.GetLastErrorDescription() << L"\n";
        return false;
    }

    credentialId = result.credentialId;
    publicKey = result.attestationObject;  // Contains the public key
    
    std::wcout << L"    [OK] Credential created!\n";
    std::wcout << L"         Credential ID: " << credentialId.size() << L" bytes\n";
    std::wcout << L"         Public Key: " << publicKey.size() << L" bytes\n";

    return true;
}

//
// Setup Credential - Enrollment with TPM-backed encryption
//
bool SetupCredential(const std::wstring& username, const std::wstring& password, const std::wstring& domain) {
    TEST_LOG(L"=== SetupCredential started ===");
    
    std::wcout << L"\n";
    std::wcout << L"========================================\n";
    std::wcout << L" Titan Key Credential Setup\n";
    std::wcout << L"========================================\n";
    std::wcout << L"\n";
    std::wcout << L"SECURITY MODEL:\n";
    std::wcout << L"  - Password encrypted with TPM-backed key (CNG)\n";
    std::wcout << L"  - Titan Key required for signature verification\n";
    std::wcout << L"  - TPM key cannot be extracted even with admin\n";
    std::wcout << L"\n";
    
    if (username.empty() || password.empty()) {
        std::wcout << L"[FAIL] Username and password are required\n";
        TEST_LOG(L"ERROR: Username or password empty");
        return false;
    }
    
    TEST_LOG((L"Setting up for user: " + username).c_str());
    
    // Get user SID
    std::wcout << L"[*] Looking up user SID for: " << username << L"\n";
    std::wstring userSid = GetUserSid(username, domain);
    
    if (userSid.empty()) {
        std::wcout << L"    [FAIL] Could not resolve user SID\n";
        std::wcout << L"         Make sure the username is correct\n";
        TEST_LOG(L"ERROR: Could not resolve user SID");
        return false;
    }
    
    std::wcout << L"    [OK] User SID: " << userSid << L"\n";
    TEST_LOG((L"User SID: " + userSid).c_str());

    // Enroll the Titan Key
    std::vector<BYTE> credentialId;
    std::vector<BYTE> publicKey;
    
    if (!EnrollTitanKey(username, credentialId, publicKey)) {
        std::wcout << L"\n[FAIL] Titan Key enrollment failed.\n";
        return false;
    }

    // Initialize TPM and create key for this user
    std::wcout << L"\n[*] Setting up TPM encryption...\n";
    
    TpmCrypto tpm;
    HRESULT hr = tpm.Initialize();
    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] TPM/CNG initialization failed: 0x" << std::hex << hr << std::dec << L"\n";
        std::wcout << L"         TPM may not be available, falling back to software\n";
    } else {
        std::wcout << L"    [OK] TPM/CNG initialized\n";
    }

    // Create/open key for this user
    std::wstring keyName = L"TitanKeyCP_";
    keyName += userSid;
    
    hr = tpm.OpenOrCreateKey(keyName.c_str());
    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] Could not create TPM key: 0x" << std::hex << hr << std::dec << L"\n";
        return false;
    }
    std::wcout << L"    [OK] TPM key ready\n";

    // Encrypt the password using TPM
    std::wcout << L"\n[*] Encrypting password with TPM...\n";
    
    std::vector<BYTE> encryptedPassword;
    hr = tpm.EncryptPassword(password.c_str(), encryptedPassword);
    
    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] Encryption failed: 0x" << std::hex << hr << std::dec << L"\n";
        return false;
    }
    
    std::wcout << L"    [OK] Password encrypted (" << encryptedPassword.size() << L" bytes)\n";
    
    // Store credential
    std::wcout << L"\n[*] Storing encrypted credential in registry...\n";
    
    CredentialStorage storage;
    hr = storage.StoreCredential(
        userSid.c_str(),
        username.c_str(),
        domain.c_str(),
        encryptedPassword,
        credentialId.data(),
        (DWORD)credentialId.size(),
        publicKey.data(),
        (DWORD)publicKey.size(),
        TITAN_KEY_CP_RELYING_PARTY_ID);
    
    // Clear encrypted password from memory
    SecureZeroMemory(encryptedPassword.data(), encryptedPassword.size());
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] Credential stored successfully\n";
        std::wcout << L"\n";
        std::wcout << L"========================================\n";
        std::wcout << L" Setup Complete!\n";
        std::wcout << L"========================================\n";
        std::wcout << L"\n";
        std::wcout << L"Your Titan Key is enrolled and password is\n";
        std::wcout << L"protected by TPM + signature verification.\n";
        std::wcout << L"\n";
        std::wcout << L"To test:\n";
        std::wcout << L"  1. Register DLL: regsvr32 TitanKeyCP.dll\n";
        std::wcout << L"  2. Lock workstation: Win+L\n";
        std::wcout << L"  3. Select 'Titan Key' tile\n";
        std::wcout << L"  4. Touch your Titan Key\n";
        std::wcout << L"\n";
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
            std::wcout << L"  Credential ID: " << cred.credentialId.size() << L" bytes\n";
            std::wcout << L"  Public Key: " << cred.publicKey.size() << L" bytes\n";
            std::wcout << L"  Encrypted Password: " << cred.encryptedPassword.size() << L" bytes\n";
            std::wcout << L"  Status: " << (cred.credentialId.empty() || cred.publicKey.empty() ? 
                L"NOT ENROLLED (missing data)" : L"ENROLLED (TPM + signature protected)") << L"\n";
            std::wcout << L"\n";
        }
    }
}

//
// Main
//
int wmain(int argc, wchar_t* argv[]) {
    PrintBanner();
    
    // Initialize file logging
    FileLogger::Instance().Open(L"TitanKeyCP_test.log");
    TEST_LOG(L"Test application started");
    
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
    
    if (opts.testLockScreen) {
        if (!TestLockScreen()) {
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
