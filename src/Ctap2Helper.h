#pragma once

#include "common.h"
#include <hidsdi.h>
#include <SetupAPI.h>

#pragma comment(lib, "hid.lib")
#pragma comment(lib, "setupapi.lib")

//
// Ctap2Helper - Direct CTAP2/HID communication with FIDO2 security keys
//
// This bypasses the Windows WebAuthn service and talks directly to the
// USB HID device, allowing it to work on the secure desktop (lock screen).
//

// CTAP2 command codes
#define CTAP2_CMD_MAKE_CREDENTIAL       0x01
#define CTAP2_CMD_GET_ASSERTION         0x02
#define CTAP2_CMD_GET_INFO              0x04
#define CTAP2_CMD_CLIENT_PIN            0x06
#define CTAP2_CMD_RESET                 0x07
#define CTAP2_CMD_GET_NEXT_ASSERTION    0x08

// CTAP2 status codes
#define CTAP2_OK                        0x00
#define CTAP2_ERR_INVALID_COMMAND       0x01
#define CTAP2_ERR_INVALID_PARAMETER     0x02
#define CTAP2_ERR_INVALID_LENGTH        0x03
#define CTAP2_ERR_INVALID_SEQ           0x04
#define CTAP2_ERR_TIMEOUT               0x05
#define CTAP2_ERR_CHANNEL_BUSY          0x06
#define CTAP2_ERR_LOCK_REQUIRED         0x0A
#define CTAP2_ERR_INVALID_CHANNEL       0x0B
#define CTAP2_ERR_CBOR_PARSING          0x10
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE  0x11
#define CTAP2_ERR_INVALID_CBOR          0x12
#define CTAP2_ERR_MISSING_PARAMETER     0x14
#define CTAP2_ERR_LIMIT_EXCEEDED        0x15
#define CTAP2_ERR_CREDENTIAL_EXCLUDED   0x19
#define CTAP2_ERR_PROCESSING            0x21
#define CTAP2_ERR_INVALID_CREDENTIAL    0x22
#define CTAP2_ERR_USER_ACTION_PENDING   0x23
#define CTAP2_ERR_OPERATION_PENDING     0x24
#define CTAP2_ERR_NO_OPERATIONS         0x25
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define CTAP2_ERR_OPERATION_DENIED      0x27
#define CTAP2_ERR_KEY_STORE_FULL        0x28
#define CTAP2_ERR_NO_CREDENTIALS        0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT   0x2F
#define CTAP2_ERR_NOT_ALLOWED           0x30
#define CTAP2_ERR_PIN_INVALID           0x31
#define CTAP2_ERR_PIN_BLOCKED           0x32
#define CTAP2_ERR_PIN_AUTH_INVALID      0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED      0x34
#define CTAP2_ERR_PIN_NOT_SET           0x35
#define CTAP2_ERR_PIN_REQUIRED          0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION  0x37
#define CTAP2_ERR_PIN_TOKEN_EXPIRED     0x38
#define CTAP2_ERR_REQUEST_TOO_LARGE     0x39
#define CTAP2_ERR_ACTION_TIMEOUT        0x3A
#define CTAP2_ERR_UP_REQUIRED           0x3B
#define CTAP2_ERR_KEEPALIVE_CANCEL      0x2D

// CTAPHID constants
#define CTAPHID_BROADCAST_CID           0xFFFFFFFF
#define CTAPHID_INIT                    0x06
#define CTAPHID_MSG                     0x03
#define CTAPHID_CBOR                    0x10
#define CTAPHID_CANCEL                  0x11
#define CTAPHID_ERROR                   0x3F
#define CTAPHID_KEEPALIVE               0x3B

// HID report sizes
#define HID_REPORT_SIZE                 64
#define HID_INIT_PACKET_DATA_SIZE       (HID_REPORT_SIZE - 7)
#define HID_CONT_PACKET_DATA_SIZE       (HID_REPORT_SIZE - 5)

// FIDO2 HID usage page and usage
#define FIDO_USAGE_PAGE                 0xF1D0
#define FIDO_USAGE                      0x01

class Ctap2Helper {
public:
    Ctap2Helper();
    ~Ctap2Helper();

    // Initialize - find and open FIDO2 device
    HRESULT Initialize();
    
    // Close device
    void Close();

    // Check if device is available
    BOOL IsAvailable() const { return m_deviceHandle != INVALID_HANDLE_VALUE; }

    // Get device info (authenticatorGetInfo)
    HRESULT GetInfo(std::vector<BYTE>& info);

    // Get assertion (authenticatorGetAssertion)
    // Returns signature, authenticator data, etc.
    struct AssertionResult {
        std::vector<BYTE> credentialId;
        std::vector<BYTE> authenticatorData;
        std::vector<BYTE> signature;
        std::vector<BYTE> userId;
    };

    HRESULT GetAssertion(
        const std::wstring& relyingPartyId,
        const std::vector<BYTE>& clientDataHash,
        const std::vector<BYTE>* allowCredentialId,
        DWORD timeoutMs,
        AssertionResult& result);

    // Make credential (authenticatorMakeCredential)
    struct CredentialResult {
        std::vector<BYTE> credentialId;
        std::vector<BYTE> attestationObject;
        std::vector<BYTE> publicKey;  // COSE key
    };

    HRESULT MakeCredential(
        const std::wstring& relyingPartyId,
        const std::wstring& relyingPartyName,
        const std::vector<BYTE>& userId,
        const std::wstring& userName,
        const std::vector<BYTE>& clientDataHash,
        DWORD timeoutMs,
        CredentialResult& result);

    // Cancel ongoing operation
    void Cancel();

    // Get last error description
    std::wstring GetLastErrorDescription() const { return m_lastError; }

    // Generate random challenge
    static HRESULT GenerateChallenge(std::vector<BYTE>& challenge, DWORD size = 32);

    // Compute SHA-256 hash
    static HRESULT ComputeSHA256(const std::vector<BYTE>& data, std::vector<BYTE>& hash);

private:
    // Find FIDO2 HID device
    HRESULT FindFidoDevice();

    // CTAPHID protocol
    HRESULT CtapHidInit();
    HRESULT CtapHidSend(BYTE cmd, const std::vector<BYTE>& data);
    HRESULT CtapHidRecv(BYTE& cmd, std::vector<BYTE>& data, DWORD timeoutMs);

    // CBOR encoding helpers
    void CborEncodeMap(std::vector<BYTE>& buffer, size_t numPairs);
    void CborEncodeUint(std::vector<BYTE>& buffer, UINT64 value);
    void CborEncodeNegInt(std::vector<BYTE>& buffer, INT64 value);
    void CborEncodeBytes(std::vector<BYTE>& buffer, const BYTE* data, size_t len);
    void CborEncodeString(std::vector<BYTE>& buffer, const char* str);
    void CborEncodeArray(std::vector<BYTE>& buffer, size_t numItems);
    void CborEncodeBool(std::vector<BYTE>& buffer, bool value);

    // CBOR decoding helpers
    bool CborDecodeMap(const BYTE*& ptr, const BYTE* end, size_t& numPairs);
    bool CborDecodeUint(const BYTE*& ptr, const BYTE* end, UINT64& value);
    bool CborDecodeBytes(const BYTE*& ptr, const BYTE* end, std::vector<BYTE>& data);
    bool CborDecodeString(const BYTE*& ptr, const BYTE* end, std::string& str);
    bool CborSkipValue(const BYTE*& ptr, const BYTE* end);

    // Device handle
    HANDLE m_deviceHandle;
    
    // Channel ID (assigned by device)
    DWORD m_channelId;

    // Cancel flag
    volatile BOOL m_cancelled;

    // Overlapped I/O event for cancellable reads
    HANDLE m_readEvent;

    // Last error
    std::wstring m_lastError;
};
