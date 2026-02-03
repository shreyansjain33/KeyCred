//
// TestTitanKeyCP.cpp - Test console application for Titan Key Credential Provider
//
// This tool allows testing the credential provider components without
// locking the system or going through the Windows logon UI.
//
// SECURITY MODEL:
// - Password is encrypted with AES-256-GCM
// - Encryption key is derived from Titan Key's hmac-secret extension
// - Only the SAME physical key can decrypt the password
//

#include "common.h"
#include "CredentialStorage.h"
#include "WebAuthnHelper.h"
#include "CryptoHelper.h"

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
    std::wcout << L"SECURITY MODEL:\n";
    std::wcout << L"  Your password is encrypted with AES-256-GCM using a key derived\n";
    std::wcout << L"  from your Titan Key's hmac-secret extension. ONLY the same\n";
    std::wcout << L"  physical key can decrypt your password - no other key will work.\n\n";
    std::wcout << L"Options:\n";
    std::wcout << L"  --help, -h          Show this help message\n";
    std::wcout << L"  --test-all          Run all tests\n";
    std::wcout << L"  --test-storage      Test AES-256-GCM encryption\n";
    std::wcout << L"  --test-webauthn     Test WebAuthn hmac-secret extension\n";
    std::wcout << L"  --test-registration Check if DLL is properly registered\n";
    std::wcout << L"  --setup             Enroll Titan Key and encrypt password\n";
    std::wcout << L"  --list              List stored credentials\n";
    std::wcout << L"  --user <username>   Username for setup\n";
    std::wcout << L"  --password <pass>   Password for setup\n";
    std::wcout << L"  --domain <domain>   Domain (default: . for local)\n";
    std::wcout << L"\n";
    std::wcout << L"First-Time Setup:\n";
    std::wcout << L"  1. Run: TestTitanKeyCP.exe --setup --user %USERNAME% --password YOUR_PASSWORD\n";
    std::wcout << L"  2. Touch your Titan Key TWICE when prompted:\n";
    std::wcout << L"     - First touch: Creates credential on key\n";
    std::wcout << L"     - Second touch: Derives encryption key\n";
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
// Test: Credential Storage (AES-256-GCM)
//
bool TestCredentialStorage() {
    std::wcout << L"\n--- Testing Credential Storage (AES-256-GCM) ---\n\n";
    
    bool success = true;
    
    // Generate a test encryption key (simulating hmac-secret output)
    std::wcout << L"[*] Generating test encryption key (32 bytes)...\n";
    std::vector<BYTE> testKey;
    HRESULT hr = CryptoHelper::GenerateSalt(testKey);  // Use salt generator for random key
    
    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] Could not generate test key\n";
        return false;
    }
    std::wcout << L"    [OK] Test key generated\n";
    
    // Test password encryption
    std::wcout << L"[*] Testing AES-256-GCM password encryption...\n";
    std::vector<BYTE> encrypted;
    hr = CredentialStorage::EncryptPassword(L"TestPassword123", testKey, encrypted);
    
    if (SUCCEEDED(hr)) {
        std::wcout << L"    [OK] Password encrypted (" << encrypted.size() << L" bytes)\n";
        std::wcout << L"         Format: nonce(12) + ciphertext + tag(16)\n";
    } else {
        std::wcout << L"    [FAIL] Encryption failed: 0x" << std::hex << hr << std::dec << L"\n";
        success = false;
    }
    
    // Test decryption with correct key
    if (SUCCEEDED(hr)) {
        std::wcout << L"[*] Testing decryption with correct key...\n";
        SecureString decrypted;
        hr = CredentialStorage::DecryptPassword(encrypted, testKey, decrypted);
        
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
    
    // Test decryption with WRONG key (should fail - this proves security)
    if (SUCCEEDED(hr)) {
        std::wcout << L"[*] Testing decryption with WRONG key (should fail)...\n";
        std::vector<BYTE> wrongKey;
        CryptoHelper::GenerateSalt(wrongKey);  // Different random key
        
        SecureString decrypted;
        hr = CredentialStorage::DecryptPassword(encrypted, wrongKey, decrypted);
        
        if (FAILED(hr)) {
            std::wcout << L"    [OK] Decryption correctly FAILED with wrong key!\n";
            std::wcout << L"         This proves only the correct Titan Key can decrypt.\n";
        } else {
            std::wcout << L"    [FAIL] Decryption should have failed with wrong key!\n";
            success = false;
        }
    }
    
    // Clear sensitive data
    SecureZeroMemory(testKey.data(), testKey.size());
    
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
    std::wcout << L"\n[*] Ready to test Titan Key with hmac-secret\n";
    std::wcout << L"\n    Choose test:\n";
    std::wcout << L"    1. Full hmac-secret test (enroll + derive key)\n";
    std::wcout << L"    2. Skip\n";
    std::wcout << L"\n    Enter choice (1/2): ";
    
    std::wstring choice;
    std::getline(std::wcin, choice);
    
    if (choice == L"1") {
        std::wcout << L"\n[*] Testing full hmac-secret flow...\n";
        std::wcout << L"    This will test: enroll -> derive key -> verify key derivation\n\n";
        
        // Step 1: Create credential
        std::wcout << L"[*] Step 1: Creating credential (touch key)...\n";
        
        WebAuthnHelper::CredentialResult credResult;
        hr = webauthn.MakeCredential(
            GetConsoleWindow(),
            TITAN_KEY_CP_RELYING_PARTY_ID,
            L"hmac-secret Test",
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
            
            // Step 2: Generate salt
            std::vector<BYTE> salt;
            CryptoHelper::GenerateSalt(salt);
            std::wcout << L"\n[*] Step 2: Salt generated (32 bytes)\n";
            
            // Step 3: Get hmac-secret (first derivation)
            std::wcout << L"\n[*] Step 3: Deriving key with hmac-secret (touch key)...\n";
            
            WebAuthnHelper::GenerateChallenge(challenge, 32);
            WebAuthnHelper::AssertionResult assertion1;
            hr = webauthn.GetAssertion(
                GetConsoleWindow(),
                TITAN_KEY_CP_RELYING_PARTY_ID,
                challenge,
                &credResult.credentialId,
                &salt,
                assertion1);
            
            if (FAILED(hr) || assertion1.hmacSecret.empty()) {
                std::wcout << L"    [FAIL] hmac-secret not returned\n";
                std::wcout << L"         Your key may not support hmac-secret extension.\n";
                success = false;
            } else {
                std::wcout << L"    [OK] hmac-secret received: " << assertion1.hmacSecret.size() << L" bytes\n";
                
                // Step 4: Verify same salt gives same secret
                std::wcout << L"\n[*] Step 4: Verifying key derivation consistency (touch key)...\n";
                
                WebAuthnHelper::GenerateChallenge(challenge, 32);
                WebAuthnHelper::AssertionResult assertion2;
                hr = webauthn.GetAssertion(
                    GetConsoleWindow(),
                    TITAN_KEY_CP_RELYING_PARTY_ID,
                    challenge,
                    &credResult.credentialId,
                    &salt,  // Same salt
                    assertion2);
                
                if (SUCCEEDED(hr) && assertion2.hmacSecret.size() == 32) {
                    if (assertion1.hmacSecret == assertion2.hmacSecret) {
                        std::wcout << L"    [OK] Same salt produces same key - VERIFIED!\n";
                        std::wcout << L"\n    SUCCESS: hmac-secret is working correctly.\n";
                        std::wcout << L"    This key can be used for secure credential storage.\n";
                    } else {
                        std::wcout << L"    [FAIL] Keys don't match - hmac-secret inconsistent\n";
                        success = false;
                    }
                } else {
                    std::wcout << L"    [FAIL] Second assertion failed\n";
                    success = false;
                }
                
                // Clear sensitive data
                SecureZeroMemory(assertion1.hmacSecret.data(), assertion1.hmacSecret.size());
                SecureZeroMemory(assertion2.hmacSecret.data(), assertion2.hmacSecret.size());
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
// Enroll Titan Key and get hmac-secret for encryption
//
// This function:
// 1. Creates a credential on the Titan Key
// 2. Generates a random salt
// 3. Uses hmac-secret to derive the encryption key
// 4. Returns credential ID, salt, and the 32-byte encryption key
//
bool EnrollTitanKey(
    const std::wstring& username, 
    std::vector<BYTE>& credentialId, 
    std::vector<BYTE>& salt,
    std::vector<BYTE>& encryptionKey)
{
    std::wcout << L"\n[*] Enrolling Titan Key with hmac-secret...\n";
    std::wcout << L"    This will register a new credential on your security key.\n";
    std::wcout << L"    You will need to touch your key TWICE:\n";
    std::wcout << L"    1. First touch: Create credential\n";
    std::wcout << L"    2. Second touch: Derive encryption key\n\n";

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

    std::wcout << L"[*] Step 1: Creating credential on Titan Key...\n";
    std::wcout << L"    Touch your key now...\n\n";

    // Create credential on the key (with hmac-secret extension enabled)
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
    std::wcout << L"    [OK] Credential created!\n";
    std::wcout << L"         Credential ID: " << credentialId.size() << L" bytes\n";

    // Generate a random salt for hmac-secret
    hr = CryptoHelper::GenerateSalt(salt);
    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] Could not generate salt\n";
        return false;
    }

    std::wcout << L"\n[*] Step 2: Deriving encryption key using hmac-secret...\n";
    std::wcout << L"    Touch your key again...\n\n";

    // Generate new challenge for assertion
    hr = WebAuthnHelper::GenerateChallenge(challenge, 32);
    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] Could not generate challenge\n";
        return false;
    }

    // Get assertion with hmac-secret to derive the encryption key
    WebAuthnHelper::AssertionResult assertion;
    hr = webauthn.GetAssertion(
        GetConsoleWindow(),
        TITAN_KEY_CP_RELYING_PARTY_ID,
        challenge,
        &credentialId,
        &salt,  // Pass salt to hmac-secret extension
        assertion);

    if (FAILED(hr)) {
        std::wcout << L"    [FAIL] Could not get hmac-secret: 0x" << std::hex << hr << std::dec << L"\n";
        std::wcout << L"         " << webauthn.GetLastErrorDescription() << L"\n";
        return false;
    }

    // Check if we got the hmac-secret
    if (assertion.hmacSecret.empty() || assertion.hmacSecret.size() != 32) {
        std::wcout << L"    [FAIL] Titan Key did not return hmac-secret\n";
        std::wcout << L"         Your key may not support the hmac-secret extension.\n";
        return false;
    }

    encryptionKey = assertion.hmacSecret;
    std::wcout << L"    [OK] Encryption key derived!\n";
    std::wcout << L"         Key size: 32 bytes (256 bits)\n";

    return true;
}

//
// Setup Credential - Full enrollment with hmac-secret based encryption
//
bool SetupCredential(const std::wstring& username, const std::wstring& password, const std::wstring& domain) {
    std::wcout << L"\n";
    std::wcout << L"========================================\n";
    std::wcout << L" Titan Key Credential Setup\n";
    std::wcout << L"========================================\n";
    std::wcout << L"\n";
    std::wcout << L"SECURITY: Your password will be encrypted with a key\n";
    std::wcout << L"derived from your Titan Key. ONLY this specific key\n";
    std::wcout << L"can decrypt your password - no other key will work.\n";
    std::wcout << L"\n";
    
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

    // Enroll the Titan Key and get encryption key via hmac-secret
    std::vector<BYTE> credentialId;
    std::vector<BYTE> salt;
    std::vector<BYTE> encryptionKey;
    
    if (!EnrollTitanKey(username, credentialId, salt, encryptionKey)) {
        std::wcout << L"\n[FAIL] Titan Key enrollment failed.\n";
        std::wcout << L"       Cannot proceed without hmac-secret support.\n";
        return false;
    }

    // Encrypt the password using the key derived from the Titan Key
    std::wcout << L"\n[*] Encrypting password with Titan Key derived key...\n";
    
    std::vector<BYTE> encryptedPassword;
    HRESULT hr = CredentialStorage::EncryptPassword(password.c_str(), encryptionKey, encryptedPassword);
    
    // Immediately clear the encryption key from memory
    SecureZeroMemory(encryptionKey.data(), encryptionKey.size());
    
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
        salt.data(),
        (DWORD)salt.size(),
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
        std::wcout << L"Your Titan Key is now enrolled.\n";
        std::wcout << L"Your password is encrypted and can ONLY be\n";
        std::wcout << L"decrypted by this specific Titan Key.\n";
        std::wcout << L"\n";
        std::wcout << L"To test:\n";
        std::wcout << L"  1. Register DLL: regsvr32 TitanKeyCP.dll\n";
        std::wcout << L"  2. Lock workstation: Win+L\n";
        std::wcout << L"  3. Select 'Titan Key' tile\n";
        std::wcout << L"  4. Touch your Titan Key\n";
        std::wcout << L"\n";
        std::wcout << L"WARNING: If you lose this Titan Key, you will\n";
        std::wcout << L"need your password to log in normally.\n";
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
            std::wcout << L"  Salt: " << cred.salt.size() << L" bytes\n";
            std::wcout << L"  Encrypted Password: " << cred.encryptedPassword.size() << L" bytes\n";
            std::wcout << L"  Status: " << (cred.credentialId.empty() || cred.salt.empty() ? 
                L"NOT ENROLLED (missing data)" : L"ENROLLED (hmac-secret secured)") << L"\n";
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
