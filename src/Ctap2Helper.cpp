//
// Ctap2Helper.cpp - Direct CTAP2/HID communication with FIDO2 security keys
//
// This implementation bypasses Windows WebAuthn and talks directly to the
// USB HID device using the CTAPHID protocol over FIDO2.
//

#include "Ctap2Helper.h"
#include <initguid.h>

// FIDO2 HID GUID
DEFINE_GUID(GUID_DEVINTERFACE_FIDO, 
    0xf1d0, 0x0001, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

Ctap2Helper::Ctap2Helper()
    : m_deviceHandle(INVALID_HANDLE_VALUE)
    , m_channelId(CTAPHID_BROADCAST_CID)
    , m_cancelled(FALSE)
    , m_readEvent(NULL)
{
    TITAN_LOG(L"Ctap2Helper created");
}

Ctap2Helper::~Ctap2Helper() {
    Close();
    TITAN_LOG(L"Ctap2Helper destroyed");
}

void Ctap2Helper::Close() {
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        // Cancel any pending I/O
        CancelIo(m_deviceHandle);
        CloseHandle(m_deviceHandle);
        m_deviceHandle = INVALID_HANDLE_VALUE;
    }
    if (m_readEvent != NULL) {
        CloseHandle(m_readEvent);
        m_readEvent = NULL;
    }
    m_channelId = CTAPHID_BROADCAST_CID;
}

//
// Initialize - Find and open FIDO2 device, establish channel
//
HRESULT Ctap2Helper::Initialize() {
    TITAN_LOG(L"Ctap2Helper::Initialize");

    Close();
    m_cancelled = FALSE;

    HRESULT hr = FindFidoDevice();
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"FindFidoDevice failed", hr);
        return hr;
    }

    // Initialize CTAPHID channel
    hr = CtapHidInit();
    if (FAILED(hr)) {
        TITAN_LOG_HR(L"CtapHidInit failed", hr);
        Close();
        return hr;
    }

    TITAN_LOG(L"Ctap2Helper initialized successfully");
    return S_OK;
}

//
// FindFidoDevice - Enumerate HID devices and find FIDO2 authenticator
//
HRESULT Ctap2Helper::FindFidoDevice() {
    TITAN_LOG(L"Finding FIDO2 device...");

    // Create event for overlapped I/O
    m_readEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (m_readEvent == NULL) {
        m_lastError = L"Failed to create I/O event";
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Get HID GUID
    GUID hidGuid;
    HidD_GetHidGuid(&hidGuid);

    // Get device information set
    HDEVINFO deviceInfoSet = SetupDiGetClassDevs(
        &hidGuid,
        nullptr,
        nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        m_lastError = L"Failed to get HID device list";
        return HRESULT_FROM_WIN32(GetLastError());
    }

    SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
    deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    BOOL found = FALSE;
    std::wstring devicePath;

    for (DWORD i = 0; !found; i++) {
        if (!SetupDiEnumDeviceInterfaces(deviceInfoSet, nullptr, &hidGuid, i, &deviceInterfaceData)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) {
                break;
            }
            continue;
        }

        // Get required size
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetail(deviceInfoSet, &deviceInterfaceData, nullptr, 0, &requiredSize, nullptr);

        if (requiredSize == 0) continue;

        // Allocate buffer
        std::vector<BYTE> buffer(requiredSize);
        PSP_DEVICE_INTERFACE_DETAIL_DATA detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)buffer.data();
        detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        if (!SetupDiGetDeviceInterfaceDetail(deviceInfoSet, &deviceInterfaceData, detailData, requiredSize, nullptr, nullptr)) {
            continue;
        }

        // Open device (without overlapped flag first to check capabilities)
        HANDLE hDevice = CreateFile(
            detailData->DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);

        if (hDevice == INVALID_HANDLE_VALUE) {
            continue;
        }

        // Get preparsed data
        PHIDP_PREPARSED_DATA preparsedData = nullptr;
        if (!HidD_GetPreparsedData(hDevice, &preparsedData)) {
            CloseHandle(hDevice);
            continue;
        }

        // Get capabilities
        HIDP_CAPS caps;
        NTSTATUS status = HidP_GetCaps(preparsedData, &caps);
        HidD_FreePreparsedData(preparsedData);
        CloseHandle(hDevice);

        if (status != HIDP_STATUS_SUCCESS) {
            continue;
        }

        // Check for FIDO usage page (0xF1D0) and usage (0x01)
        if (caps.UsagePage == FIDO_USAGE_PAGE && caps.Usage == FIDO_USAGE) {
            TITAN_LOG(L"Found FIDO2 device!");
            devicePath = detailData->DevicePath;
            found = TRUE;
        }
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);

    if (!found) {
        m_lastError = L"No FIDO2 security key found. Please insert your Titan Key.";
        return HRESULT_FROM_WIN32(ERROR_DEVICE_NOT_CONNECTED);
    }

    // Re-open device with FILE_FLAG_OVERLAPPED for cancellable I/O
    m_deviceHandle = CreateFile(
        devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,  // Enable overlapped I/O for cancellation
        nullptr);

    if (m_deviceHandle == INVALID_HANDLE_VALUE) {
        m_lastError = L"Failed to open FIDO2 device for I/O";
        return HRESULT_FROM_WIN32(GetLastError());
    }

    TITAN_LOG(L"FIDO2 device opened with overlapped I/O");
    return S_OK;
}

//
// CtapHidInit - Initialize CTAPHID channel
//
HRESULT Ctap2Helper::CtapHidInit() {
    TITAN_LOG(L"CTAPHID Init");

    // Generate 8 random bytes for nonce
    BYTE nonce[8];
    NTSTATUS status = BCryptGenRandom(nullptr, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        m_lastError = L"Failed to generate nonce";
        return HRESULT_FROM_NT(status);
    }

    // Send CTAPHID_INIT with broadcast channel
    m_channelId = CTAPHID_BROADCAST_CID;
    std::vector<BYTE> initData(nonce, nonce + 8);

    HRESULT hr = CtapHidSend(CTAPHID_INIT, initData);
    if (FAILED(hr)) {
        return hr;
    }

    // Receive response
    BYTE respCmd;
    std::vector<BYTE> respData;
    hr = CtapHidRecv(respCmd, respData, 5000);
    if (FAILED(hr)) {
        return hr;
    }

    if (respCmd != CTAPHID_INIT || respData.size() < 17) {
        m_lastError = L"Invalid CTAPHID_INIT response";
        return E_FAIL;
    }

    // Verify nonce
    if (memcmp(respData.data(), nonce, 8) != 0) {
        m_lastError = L"Nonce mismatch in CTAPHID_INIT";
        return E_FAIL;
    }

    // Extract channel ID (bytes 8-11, big-endian)
    m_channelId = (respData[8] << 24) | (respData[9] << 16) | (respData[10] << 8) | respData[11];

    {
        WCHAR buf[64];
        swprintf_s(buf, L"Assigned channel ID: 0x%08X", m_channelId);
        TitanLogToFile(buf);
    }

    return S_OK;
}

//
// CtapHidSend - Send CTAPHID packet (with overlapped I/O)
//
HRESULT Ctap2Helper::CtapHidSend(BYTE cmd, const std::vector<BYTE>& data) {
    if (m_deviceHandle == INVALID_HANDLE_VALUE) {
        return E_HANDLE;
    }

    size_t totalLen = data.size();
    size_t offset = 0;
    BYTE seq = 0;

    // Send initialization packet
    BYTE packet[HID_REPORT_SIZE + 1] = { 0 };  // +1 for report ID
    packet[0] = 0;  // Report ID

    // Channel ID (big-endian)
    packet[1] = (BYTE)(m_channelId >> 24);
    packet[2] = (BYTE)(m_channelId >> 16);
    packet[3] = (BYTE)(m_channelId >> 8);
    packet[4] = (BYTE)(m_channelId);

    // Command with init flag
    packet[5] = cmd | 0x80;

    // Length (big-endian)
    packet[6] = (BYTE)(totalLen >> 8);
    packet[7] = (BYTE)(totalLen);

    // Data
    size_t copyLen = min(totalLen, (size_t)HID_INIT_PACKET_DATA_SIZE);
    if (copyLen > 0) {
        memcpy(packet + 8, data.data(), copyLen);
    }
    offset = copyLen;

    // Use overlapped I/O for writes
    OVERLAPPED ov = { 0 };
    ov.hEvent = m_readEvent;
    ResetEvent(m_readEvent);

    DWORD written = 0;
    if (!WriteFile(m_deviceHandle, packet, sizeof(packet), &written, &ov)) {
        if (GetLastError() == ERROR_IO_PENDING) {
            // Wait for completion (short timeout for writes)
            DWORD result = WaitForSingleObject(m_readEvent, 5000);
            if (result != WAIT_OBJECT_0) {
                CancelIo(m_deviceHandle);
                m_lastError = L"Write timeout";
                return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
            }
            GetOverlappedResult(m_deviceHandle, &ov, &written, FALSE);
        } else {
            m_lastError = L"Failed to write to HID device";
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }

    // Send continuation packets if needed
    while (offset < totalLen) {
        if (m_cancelled) {
            m_lastError = L"Operation cancelled";
            return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        }

        ZeroMemory(packet, sizeof(packet));
        packet[0] = 0;  // Report ID

        // Channel ID
        packet[1] = (BYTE)(m_channelId >> 24);
        packet[2] = (BYTE)(m_channelId >> 16);
        packet[3] = (BYTE)(m_channelId >> 8);
        packet[4] = (BYTE)(m_channelId);

        // Sequence number
        packet[5] = seq++;

        // Data
        copyLen = min(totalLen - offset, (size_t)HID_CONT_PACKET_DATA_SIZE);
        memcpy(packet + 6, data.data() + offset, copyLen);
        offset += copyLen;

        ResetEvent(m_readEvent);
        written = 0;
        if (!WriteFile(m_deviceHandle, packet, sizeof(packet), &written, &ov)) {
            if (GetLastError() == ERROR_IO_PENDING) {
                DWORD result = WaitForSingleObject(m_readEvent, 5000);
                if (result != WAIT_OBJECT_0) {
                    CancelIo(m_deviceHandle);
                    m_lastError = L"Write timeout";
                    return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
                }
                GetOverlappedResult(m_deviceHandle, &ov, &written, FALSE);
            } else {
                m_lastError = L"Failed to write continuation packet";
                return HRESULT_FROM_WIN32(GetLastError());
            }
        }
    }

    return S_OK;
}

//
// CtapHidRecv - Receive CTAPHID packet (with overlapped I/O for cancellation)
//
HRESULT Ctap2Helper::CtapHidRecv(BYTE& cmd, std::vector<BYTE>& data, DWORD timeoutMs) {
    if (m_deviceHandle == INVALID_HANDLE_VALUE) {
        return E_HANDLE;
    }

    data.clear();
    BYTE packet[HID_REPORT_SIZE + 1] = { 0 };
    DWORD read;

    DWORD startTime = GetTickCount();
    BYTE expectedSeq = 0;
    size_t totalLen = 0;
    BOOL gotInit = FALSE;

    // Use short wait intervals so we can check for cancellation
    const DWORD POLL_INTERVAL_MS = 100;

    while (TRUE) {
        // Check timeout
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed > timeoutMs) {
            m_lastError = L"Timeout waiting for device response";
            return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        }

        // Check cancellation FIRST
        if (m_cancelled) {
            TITAN_LOG(L"Cancellation detected in CtapHidRecv");
            CancelIo(m_deviceHandle);
            m_lastError = L"Operation cancelled";
            return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        }

        // Set up overlapped read
        OVERLAPPED ov = { 0 };
        ov.hEvent = m_readEvent;
        ResetEvent(m_readEvent);

        read = 0;
        ZeroMemory(packet, sizeof(packet));

        BOOL readResult = ReadFile(m_deviceHandle, packet, sizeof(packet), &read, &ov);
        
        if (!readResult) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                // Wait with short timeout so we can check for cancellation
                DWORD waitTime = min(POLL_INTERVAL_MS, timeoutMs - elapsed);
                DWORD waitResult = WaitForSingleObject(m_readEvent, waitTime);

                if (waitResult == WAIT_TIMEOUT) {
                    // Check cancellation again before continuing
                    if (m_cancelled) {
                        CancelIo(m_deviceHandle);
                        m_lastError = L"Operation cancelled";
                        return HRESULT_FROM_WIN32(ERROR_CANCELLED);
                    }
                    // No data yet, continue polling
                    CancelIo(m_deviceHandle);
                    continue;
                } else if (waitResult != WAIT_OBJECT_0) {
                    CancelIo(m_deviceHandle);
                    m_lastError = L"Wait failed";
                    return E_FAIL;
                }

                // Get the result
                if (!GetOverlappedResult(m_deviceHandle, &ov, &read, FALSE)) {
                    DWORD overlappedErr = GetLastError();
                    if (overlappedErr == ERROR_OPERATION_ABORTED) {
                        m_lastError = L"Operation cancelled";
                        return HRESULT_FROM_WIN32(ERROR_CANCELLED);
                    }
                    // Retry on other errors
                    continue;
                }
            } else {
                m_lastError = L"Failed to read from HID device";
                return HRESULT_FROM_WIN32(err);
            }
        }

        if (read < HID_REPORT_SIZE) {
            continue;
        }

        // Parse packet (skip report ID at packet[0])
        DWORD packetCid = (packet[1] << 24) | (packet[2] << 16) | (packet[3] << 8) | packet[4];

        // Check channel ID
        if (packetCid != m_channelId && m_channelId != CTAPHID_BROADCAST_CID) {
            continue;
        }

        BYTE cmdOrSeq = packet[5];

        if (cmdOrSeq & 0x80) {
            // Initialization packet
            cmd = cmdOrSeq & 0x7F;
            totalLen = (packet[6] << 8) | packet[7];

            // Handle keepalive
            if (cmd == CTAPHID_KEEPALIVE) {
                BYTE status = packet[8];
                if (status == 1) {
                    // Processing - continue waiting
                    TITAN_LOG(L"Device processing...");
                } else if (status == 2) {
                    // User presence needed
                    TITAN_LOG(L"Touch your security key!");
                }
                continue;
            }

            // Handle error
            if (cmd == CTAPHID_ERROR) {
                BYTE errorCode = packet[8];
                WCHAR buf[64];
                swprintf_s(buf, L"CTAPHID error: 0x%02X", errorCode);
                m_lastError = buf;
                return E_FAIL;
            }

            gotInit = TRUE;
            size_t copyLen = min(totalLen, (size_t)HID_INIT_PACKET_DATA_SIZE);
            data.assign(packet + 8, packet + 8 + copyLen);
            expectedSeq = 0;

            if (data.size() >= totalLen) {
                data.resize(totalLen);
                return S_OK;
            }
        } else if (gotInit) {
            // Continuation packet
            BYTE seq = cmdOrSeq;
            if (seq != expectedSeq) {
                m_lastError = L"Sequence mismatch";
                return E_FAIL;
            }
            expectedSeq++;

            size_t remaining = totalLen - data.size();
            size_t copyLen = min(remaining, (size_t)HID_CONT_PACKET_DATA_SIZE);
            data.insert(data.end(), packet + 6, packet + 6 + copyLen);

            if (data.size() >= totalLen) {
                data.resize(totalLen);
                return S_OK;
            }
        }
    }
}

//
// Cancel - Cancel ongoing operation
//
void Ctap2Helper::Cancel() {
    TITAN_LOG(L"Ctap2Helper::Cancel called");
    
    // Set flag first - this will be checked in the polling loop
    m_cancelled = TRUE;

    // Cancel any pending I/O operations
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        CancelIo(m_deviceHandle);
        
        // Also try to send CTAPHID_CANCEL to the device
        if (m_channelId != CTAPHID_BROADCAST_CID) {
            // Don't wait for response, just fire and forget
            BYTE packet[HID_REPORT_SIZE + 1] = { 0 };
            packet[0] = 0;  // Report ID
            packet[1] = (BYTE)(m_channelId >> 24);
            packet[2] = (BYTE)(m_channelId >> 16);
            packet[3] = (BYTE)(m_channelId >> 8);
            packet[4] = (BYTE)(m_channelId);
            packet[5] = CTAPHID_CANCEL | 0x80;
            packet[6] = 0;
            packet[7] = 0;
            
            OVERLAPPED ov = { 0 };
            ov.hEvent = m_readEvent;
            if (m_readEvent) {
                ResetEvent(m_readEvent);
                DWORD written;
                WriteFile(m_deviceHandle, packet, sizeof(packet), &written, &ov);
                // Don't wait, just try
            }
        }
    }
    
    TITAN_LOG(L"Ctap2Helper::Cancel completed");
}

//
// GetInfo - CTAP2 authenticatorGetInfo
//
HRESULT Ctap2Helper::GetInfo(std::vector<BYTE>& info) {
    TITAN_LOG(L"Ctap2Helper::GetInfo");

    if (!IsAvailable()) {
        return E_FAIL;
    }

    // Send authenticatorGetInfo (no parameters)
    std::vector<BYTE> request;
    request.push_back(CTAP2_CMD_GET_INFO);

    HRESULT hr = CtapHidSend(CTAPHID_CBOR, request);
    if (FAILED(hr)) {
        return hr;
    }

    BYTE respCmd;
    std::vector<BYTE> response;
    hr = CtapHidRecv(respCmd, response, 5000);
    if (FAILED(hr)) {
        return hr;
    }

    if (respCmd != CTAPHID_CBOR || response.empty()) {
        m_lastError = L"Invalid GetInfo response";
        return E_FAIL;
    }

    // First byte is status
    BYTE status = response[0];
    if (status != CTAP2_OK) {
        WCHAR buf[64];
        swprintf_s(buf, L"GetInfo failed with status 0x%02X", status);
        m_lastError = buf;
        return E_FAIL;
    }

    // Rest is CBOR data
    info.assign(response.begin() + 1, response.end());
    return S_OK;
}

//
// CBOR encoding helpers
//
void Ctap2Helper::CborEncodeMap(std::vector<BYTE>& buffer, size_t numPairs) {
    if (numPairs < 24) {
        buffer.push_back(0xA0 | (BYTE)numPairs);
    } else if (numPairs < 256) {
        buffer.push_back(0xB8);
        buffer.push_back((BYTE)numPairs);
    } else {
        buffer.push_back(0xB9);
        buffer.push_back((BYTE)(numPairs >> 8));
        buffer.push_back((BYTE)numPairs);
    }
}

void Ctap2Helper::CborEncodeUint(std::vector<BYTE>& buffer, UINT64 value) {
    if (value < 24) {
        buffer.push_back((BYTE)value);
    } else if (value < 256) {
        buffer.push_back(0x18);
        buffer.push_back((BYTE)value);
    } else if (value < 65536) {
        buffer.push_back(0x19);
        buffer.push_back((BYTE)(value >> 8));
        buffer.push_back((BYTE)value);
    } else if (value < 0x100000000ULL) {
        buffer.push_back(0x1A);
        buffer.push_back((BYTE)(value >> 24));
        buffer.push_back((BYTE)(value >> 16));
        buffer.push_back((BYTE)(value >> 8));
        buffer.push_back((BYTE)value);
    } else {
        buffer.push_back(0x1B);
        buffer.push_back((BYTE)(value >> 56));
        buffer.push_back((BYTE)(value >> 48));
        buffer.push_back((BYTE)(value >> 40));
        buffer.push_back((BYTE)(value >> 32));
        buffer.push_back((BYTE)(value >> 24));
        buffer.push_back((BYTE)(value >> 16));
        buffer.push_back((BYTE)(value >> 8));
        buffer.push_back((BYTE)value);
    }
}

void Ctap2Helper::CborEncodeNegInt(std::vector<BYTE>& buffer, INT64 value) {
    // Negative integers are encoded as -1 - n
    UINT64 encoded = (UINT64)(-1 - value);
    if (encoded < 24) {
        buffer.push_back(0x20 | (BYTE)encoded);
    } else if (encoded < 256) {
        buffer.push_back(0x38);
        buffer.push_back((BYTE)encoded);
    } else if (encoded < 65536) {
        buffer.push_back(0x39);
        buffer.push_back((BYTE)(encoded >> 8));
        buffer.push_back((BYTE)encoded);
    } else {
        buffer.push_back(0x3A);
        buffer.push_back((BYTE)(encoded >> 24));
        buffer.push_back((BYTE)(encoded >> 16));
        buffer.push_back((BYTE)(encoded >> 8));
        buffer.push_back((BYTE)encoded);
    }
}

void Ctap2Helper::CborEncodeBytes(std::vector<BYTE>& buffer, const BYTE* data, size_t len) {
    if (len < 24) {
        buffer.push_back(0x40 | (BYTE)len);
    } else if (len < 256) {
        buffer.push_back(0x58);
        buffer.push_back((BYTE)len);
    } else if (len < 65536) {
        buffer.push_back(0x59);
        buffer.push_back((BYTE)(len >> 8));
        buffer.push_back((BYTE)len);
    } else {
        buffer.push_back(0x5A);
        buffer.push_back((BYTE)(len >> 24));
        buffer.push_back((BYTE)(len >> 16));
        buffer.push_back((BYTE)(len >> 8));
        buffer.push_back((BYTE)len);
    }
    buffer.insert(buffer.end(), data, data + len);
}

void Ctap2Helper::CborEncodeString(std::vector<BYTE>& buffer, const char* str) {
    size_t len = strlen(str);
    if (len < 24) {
        buffer.push_back(0x60 | (BYTE)len);
    } else if (len < 256) {
        buffer.push_back(0x78);
        buffer.push_back((BYTE)len);
    } else if (len < 65536) {
        buffer.push_back(0x79);
        buffer.push_back((BYTE)(len >> 8));
        buffer.push_back((BYTE)len);
    } else {
        buffer.push_back(0x7A);
        buffer.push_back((BYTE)(len >> 24));
        buffer.push_back((BYTE)(len >> 16));
        buffer.push_back((BYTE)(len >> 8));
        buffer.push_back((BYTE)len);
    }
    buffer.insert(buffer.end(), (BYTE*)str, (BYTE*)str + len);
}

void Ctap2Helper::CborEncodeArray(std::vector<BYTE>& buffer, size_t numItems) {
    if (numItems < 24) {
        buffer.push_back(0x80 | (BYTE)numItems);
    } else if (numItems < 256) {
        buffer.push_back(0x98);
        buffer.push_back((BYTE)numItems);
    } else {
        buffer.push_back(0x99);
        buffer.push_back((BYTE)(numItems >> 8));
        buffer.push_back((BYTE)numItems);
    }
}

void Ctap2Helper::CborEncodeBool(std::vector<BYTE>& buffer, bool value) {
    buffer.push_back(value ? 0xF5 : 0xF4);
}

//
// CBOR decoding helpers
//
bool Ctap2Helper::CborDecodeMap(const BYTE*& ptr, const BYTE* end, size_t& numPairs) {
    if (ptr >= end) return false;
    BYTE b = *ptr++;
    BYTE major = b >> 5;
    BYTE info = b & 0x1F;
    if (major != 5) return false;

    if (info < 24) {
        numPairs = info;
    } else if (info == 24 && ptr < end) {
        numPairs = *ptr++;
    } else if (info == 25 && ptr + 1 < end) {
        numPairs = (ptr[0] << 8) | ptr[1];
        ptr += 2;
    } else {
        return false;
    }
    return true;
}

bool Ctap2Helper::CborDecodeUint(const BYTE*& ptr, const BYTE* end, UINT64& value) {
    if (ptr >= end) return false;
    BYTE b = *ptr++;
    BYTE major = b >> 5;
    BYTE info = b & 0x1F;
    if (major != 0) return false;

    if (info < 24) {
        value = info;
    } else if (info == 24 && ptr < end) {
        value = *ptr++;
    } else if (info == 25 && ptr + 1 < end) {
        value = (ptr[0] << 8) | ptr[1];
        ptr += 2;
    } else if (info == 26 && ptr + 3 < end) {
        value = ((UINT64)ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
        ptr += 4;
    } else if (info == 27 && ptr + 7 < end) {
        value = ((UINT64)ptr[0] << 56) | ((UINT64)ptr[1] << 48) |
                ((UINT64)ptr[2] << 40) | ((UINT64)ptr[3] << 32) |
                ((UINT64)ptr[4] << 24) | (ptr[5] << 16) | (ptr[6] << 8) | ptr[7];
        ptr += 8;
    } else {
        return false;
    }
    return true;
}

bool Ctap2Helper::CborDecodeBytes(const BYTE*& ptr, const BYTE* end, std::vector<BYTE>& data) {
    if (ptr >= end) return false;
    BYTE b = *ptr++;
    BYTE major = b >> 5;
    BYTE info = b & 0x1F;
    if (major != 2) return false;

    size_t len;
    if (info < 24) {
        len = info;
    } else if (info == 24 && ptr < end) {
        len = *ptr++;
    } else if (info == 25 && ptr + 1 < end) {
        len = (ptr[0] << 8) | ptr[1];
        ptr += 2;
    } else if (info == 26 && ptr + 3 < end) {
        len = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
        ptr += 4;
    } else {
        return false;
    }

    if (ptr + len > end) return false;
    data.assign(ptr, ptr + len);
    ptr += len;
    return true;
}

bool Ctap2Helper::CborDecodeString(const BYTE*& ptr, const BYTE* end, std::string& str) {
    if (ptr >= end) return false;
    BYTE b = *ptr++;
    BYTE major = b >> 5;
    BYTE info = b & 0x1F;
    if (major != 3) return false;

    size_t len;
    if (info < 24) {
        len = info;
    } else if (info == 24 && ptr < end) {
        len = *ptr++;
    } else if (info == 25 && ptr + 1 < end) {
        len = (ptr[0] << 8) | ptr[1];
        ptr += 2;
    } else if (info == 26 && ptr + 3 < end) {
        len = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
        ptr += 4;
    } else {
        return false;
    }

    if (ptr + len > end) return false;
    str.assign((char*)ptr, len);
    ptr += len;
    return true;
}

bool Ctap2Helper::CborSkipValue(const BYTE*& ptr, const BYTE* end) {
    if (ptr >= end) return false;
    BYTE b = *ptr++;
    BYTE major = b >> 5;
    BYTE info = b & 0x1F;

    size_t len = 0;
    size_t count = 0;

    // Get length/count
    if (info < 24) {
        len = info;
    } else if (info == 24 && ptr < end) {
        len = *ptr++;
    } else if (info == 25 && ptr + 1 < end) {
        len = (ptr[0] << 8) | ptr[1];
        ptr += 2;
    } else if (info == 26 && ptr + 3 < end) {
        len = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
        ptr += 4;
    } else if (info == 27 && ptr + 7 < end) {
        // 8-byte length - just skip 8 bytes and use lower 32 bits
        ptr += 4;
        len = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
        ptr += 4;
    } else if (info == 31) {
        // Indefinite length - not supported for simplicity
        return false;
    } else {
        return false;
    }

    switch (major) {
    case 0: // Unsigned int - length already consumed
    case 1: // Negative int
        return true;
    case 2: // Byte string
    case 3: // Text string
        if (ptr + len > end) return false;
        ptr += len;
        return true;
    case 4: // Array
        for (size_t i = 0; i < len; i++) {
            if (!CborSkipValue(ptr, end)) return false;
        }
        return true;
    case 5: // Map
        for (size_t i = 0; i < len; i++) {
            if (!CborSkipValue(ptr, end)) return false;  // Key
            if (!CborSkipValue(ptr, end)) return false;  // Value
        }
        return true;
    case 6: // Tag
        return CborSkipValue(ptr, end);
    case 7: // Simple/float
        return true;
    default:
        return false;
    }
}

//
// GetAssertion - CTAP2 authenticatorGetAssertion
//
HRESULT Ctap2Helper::GetAssertion(
    const std::wstring& relyingPartyId,
    const std::vector<BYTE>& clientDataHash,
    const std::vector<BYTE>* allowCredentialId,
    DWORD timeoutMs,
    AssertionResult& result)
{
    TITAN_LOG(L"Ctap2Helper::GetAssertion");

    if (!IsAvailable()) {
        m_lastError = L"Device not available";
        return E_FAIL;
    }

    m_cancelled = FALSE;

    // Convert RP ID to UTF-8
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, relyingPartyId.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string rpIdUtf8(utf8Len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, relyingPartyId.c_str(), -1, &rpIdUtf8[0], utf8Len, nullptr, nullptr);

    // Build CBOR request
    std::vector<BYTE> request;
    request.push_back(CTAP2_CMD_GET_ASSERTION);

    // Map with parameters
    // 0x01 = rpId (string)
    // 0x02 = clientDataHash (bytes)
    // 0x03 = allowList (array, optional)
    // 0x05 = options (map, optional)

    int numParams = 2;  // rpId, clientDataHash
    if (allowCredentialId && !allowCredentialId->empty()) {
        numParams++;  // allowList
    }
    numParams++;  // options (for up=true)

    CborEncodeMap(request, numParams);

    // 0x01: rpId
    CborEncodeUint(request, 1);
    CborEncodeString(request, rpIdUtf8.c_str());

    // 0x02: clientDataHash
    CborEncodeUint(request, 2);
    CborEncodeBytes(request, clientDataHash.data(), clientDataHash.size());

    // 0x03: allowList (if credential ID provided)
    if (allowCredentialId && !allowCredentialId->empty()) {
        CborEncodeUint(request, 3);
        CborEncodeArray(request, 1);  // Array of 1 credential
        
        // PublicKeyCredentialDescriptor
        CborEncodeMap(request, 2);
        
        // "type": "public-key"
        CborEncodeString(request, "type");
        CborEncodeString(request, "public-key");
        
        // "id": <credential ID bytes>
        CborEncodeString(request, "id");
        CborEncodeBytes(request, allowCredentialId->data(), allowCredentialId->size());
    }

    // 0x05: options - request user presence
    CborEncodeUint(request, 5);
    CborEncodeMap(request, 1);
    CborEncodeString(request, "up");
    CborEncodeBool(request, true);

    TITAN_LOG(L"Sending GetAssertion request...");

    // Send request
    HRESULT hr = CtapHidSend(CTAPHID_CBOR, request);
    if (FAILED(hr)) {
        return hr;
    }

    TITAN_LOG(L"Waiting for response (touch your key)...");

    // Receive response (with extended timeout for user interaction)
    BYTE respCmd;
    std::vector<BYTE> response;
    hr = CtapHidRecv(respCmd, response, timeoutMs);
    if (FAILED(hr)) {
        return hr;
    }

    if (respCmd != CTAPHID_CBOR || response.empty()) {
        m_lastError = L"Invalid GetAssertion response";
        return E_FAIL;
    }

    // Check status
    BYTE status = response[0];
    if (status != CTAP2_OK) {
        switch (status) {
        case CTAP2_ERR_NO_CREDENTIALS:
            m_lastError = L"No matching credential on this key";
            break;
        case CTAP2_ERR_OPERATION_DENIED:
            m_lastError = L"Operation denied";
            break;
        case CTAP2_ERR_USER_ACTION_TIMEOUT:
        case CTAP2_ERR_ACTION_TIMEOUT:
            m_lastError = L"Timeout - key not touched";
            break;
        case CTAP2_ERR_KEEPALIVE_CANCEL:
            m_lastError = L"Operation cancelled";
            break;
        case CTAP2_ERR_UP_REQUIRED:
            m_lastError = L"User presence required - touch the key";
            break;
        default:
            WCHAR buf[64];
            swprintf_s(buf, L"GetAssertion failed: 0x%02X", status);
            m_lastError = buf;
        }
        return E_FAIL;
    }

    TITAN_LOG(L"GetAssertion succeeded, parsing response...");

    // Parse CBOR response
    const BYTE* ptr = response.data() + 1;  // Skip status
    const BYTE* end = response.data() + response.size();

    size_t numPairs;
    if (!CborDecodeMap(ptr, end, numPairs)) {
        m_lastError = L"Invalid response format";
        return E_FAIL;
    }

    // Parse response map
    // 0x01 = credential
    // 0x02 = authData
    // 0x03 = signature
    // 0x04 = user (optional)

    for (size_t i = 0; i < numPairs; i++) {
        UINT64 key;
        if (!CborDecodeUint(ptr, end, key)) {
            CborSkipValue(ptr, end);  // Try to skip non-integer key
            CborSkipValue(ptr, end);
            continue;
        }

        switch (key) {
        case 1: {  // credential
            size_t credMapPairs;
            if (!CborDecodeMap(ptr, end, credMapPairs)) {
                CborSkipValue(ptr, end);
                break;
            }
            for (size_t j = 0; j < credMapPairs; j++) {
                std::string fieldName;
                if (!CborDecodeString(ptr, end, fieldName)) {
                    CborSkipValue(ptr, end);
                    CborSkipValue(ptr, end);
                    continue;
                }
                if (fieldName == "id") {
                    CborDecodeBytes(ptr, end, result.credentialId);
                } else {
                    CborSkipValue(ptr, end);
                }
            }
            break;
        }
        case 2:  // authData
            if (!CborDecodeBytes(ptr, end, result.authenticatorData)) {
                m_lastError = L"Failed to parse authData";
                return E_FAIL;
            }
            break;
        case 3:  // signature
            if (!CborDecodeBytes(ptr, end, result.signature)) {
                m_lastError = L"Failed to parse signature";
                return E_FAIL;
            }
            break;
        case 4: {  // user (optional)
            size_t userMapPairs;
            if (!CborDecodeMap(ptr, end, userMapPairs)) {
                CborSkipValue(ptr, end);
                break;
            }
            for (size_t j = 0; j < userMapPairs; j++) {
                std::string fieldName;
                if (!CborDecodeString(ptr, end, fieldName)) {
                    CborSkipValue(ptr, end);
                    CborSkipValue(ptr, end);
                    continue;
                }
                if (fieldName == "id") {
                    CborDecodeBytes(ptr, end, result.userId);
                } else {
                    CborSkipValue(ptr, end);
                }
            }
            break;
        }
        default:
            CborSkipValue(ptr, end);
            break;
        }
    }

    TITAN_LOG(L"GetAssertion completed successfully");
    return S_OK;
}

//
// MakeCredential - CTAP2 authenticatorMakeCredential
//
HRESULT Ctap2Helper::MakeCredential(
    const std::wstring& relyingPartyId,
    const std::wstring& relyingPartyName,
    const std::vector<BYTE>& userId,
    const std::wstring& userName,
    const std::vector<BYTE>& clientDataHash,
    DWORD timeoutMs,
    CredentialResult& result)
{
    TITAN_LOG(L"Ctap2Helper::MakeCredential");

    if (!IsAvailable()) {
        m_lastError = L"Device not available";
        return E_FAIL;
    }

    m_cancelled = FALSE;

    // Convert strings to UTF-8
    auto toUtf8 = [](const std::wstring& ws) -> std::string {
        if (ws.empty()) return "";
        int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &s[0], len, nullptr, nullptr);
        return s;
    };

    std::string rpIdUtf8 = toUtf8(relyingPartyId);
    std::string rpNameUtf8 = toUtf8(relyingPartyName);
    std::string userNameUtf8 = toUtf8(userName);

    // Build CBOR request
    std::vector<BYTE> request;
    request.push_back(CTAP2_CMD_MAKE_CREDENTIAL);

    // Map with 4 parameters:
    // 0x01 = clientDataHash
    // 0x02 = rp
    // 0x03 = user
    // 0x04 = pubKeyCredParams
    CborEncodeMap(request, 4);

    // 0x01: clientDataHash
    CborEncodeUint(request, 1);
    CborEncodeBytes(request, clientDataHash.data(), clientDataHash.size());

    // 0x02: rp (relying party)
    CborEncodeUint(request, 2);
    CborEncodeMap(request, 2);
    CborEncodeString(request, "id");
    CborEncodeString(request, rpIdUtf8.c_str());
    CborEncodeString(request, "name");
    CborEncodeString(request, rpNameUtf8.c_str());

    // 0x03: user
    CborEncodeUint(request, 3);
    CborEncodeMap(request, 3);
    CborEncodeString(request, "id");
    CborEncodeBytes(request, userId.data(), userId.size());
    CborEncodeString(request, "name");
    CborEncodeString(request, userNameUtf8.c_str());
    CborEncodeString(request, "displayName");
    CborEncodeString(request, userNameUtf8.c_str());

    // 0x04: pubKeyCredParams - ES256 (ECDSA with P-256 and SHA-256)
    CborEncodeUint(request, 4);
    CborEncodeArray(request, 1);
    CborEncodeMap(request, 2);
    CborEncodeString(request, "type");
    CborEncodeString(request, "public-key");
    CborEncodeString(request, "alg");
    CborEncodeNegInt(request, -7);  // ES256 = -7

    TITAN_LOG(L"Sending MakeCredential request...");

    // Send request
    HRESULT hr = CtapHidSend(CTAPHID_CBOR, request);
    if (FAILED(hr)) {
        return hr;
    }

    TITAN_LOG(L"Waiting for response (touch your key)...");

    // Receive response
    BYTE respCmd;
    std::vector<BYTE> response;
    hr = CtapHidRecv(respCmd, response, timeoutMs);
    if (FAILED(hr)) {
        return hr;
    }

    if (respCmd != CTAPHID_CBOR || response.empty()) {
        m_lastError = L"Invalid MakeCredential response";
        return E_FAIL;
    }

    // Check status
    BYTE status = response[0];
    if (status != CTAP2_OK) {
        switch (status) {
        case CTAP2_ERR_CREDENTIAL_EXCLUDED:
            m_lastError = L"Credential already exists on this key";
            break;
        case CTAP2_ERR_USER_ACTION_TIMEOUT:
        case CTAP2_ERR_ACTION_TIMEOUT:
            m_lastError = L"Timeout - key not touched";
            break;
        default:
            WCHAR buf[64];
            swprintf_s(buf, L"MakeCredential failed: 0x%02X", status);
            m_lastError = buf;
        }
        return E_FAIL;
    }

    TITAN_LOG(L"MakeCredential succeeded, parsing response...");

    // Parse CBOR response
    const BYTE* ptr = response.data() + 1;  // Skip status
    const BYTE* end = response.data() + response.size();

    size_t numPairs;
    if (!CborDecodeMap(ptr, end, numPairs)) {
        m_lastError = L"Invalid response format";
        return E_FAIL;
    }

    // Response format:
    // 0x01 = fmt (string)
    // 0x02 = authData (bytes) - contains credential ID and public key
    // 0x03 = attStmt (map)

    std::vector<BYTE> authData;
    
    for (size_t i = 0; i < numPairs; i++) {
        UINT64 key;
        if (!CborDecodeUint(ptr, end, key)) {
            CborSkipValue(ptr, end);
            CborSkipValue(ptr, end);
            continue;
        }

        switch (key) {
        case 1:  // fmt
            CborSkipValue(ptr, end);
            break;
        case 2:  // authData
            if (!CborDecodeBytes(ptr, end, authData)) {
                m_lastError = L"Failed to parse authData";
                return E_FAIL;
            }
            break;
        case 3:  // attStmt
            CborSkipValue(ptr, end);
            break;
        default:
            CborSkipValue(ptr, end);
            break;
        }
    }

    if (authData.size() < 55) {  // Minimum: 32 (rpIdHash) + 1 (flags) + 4 (counter) + 16 (AAGUID) + 2 (credIdLen)
        m_lastError = L"AuthData too short";
        return E_FAIL;
    }

    // Parse authData to extract credential ID and public key
    // Format: rpIdHash (32) + flags (1) + counter (4) + attestedCredData
    // attestedCredData: AAGUID (16) + credIdLen (2, big-endian) + credId + COSE key

    size_t offset = 32 + 1 + 4;  // Skip rpIdHash, flags, counter
    offset += 16;  // Skip AAGUID

    if (offset + 2 > authData.size()) {
        m_lastError = L"AuthData truncated";
        return E_FAIL;
    }

    WORD credIdLen = (authData[offset] << 8) | authData[offset + 1];
    offset += 2;

    if (offset + credIdLen > authData.size()) {
        m_lastError = L"Credential ID truncated";
        return E_FAIL;
    }

    result.credentialId.assign(authData.begin() + offset, authData.begin() + offset + credIdLen);
    offset += credIdLen;

    // Remaining bytes are the COSE public key
    if (offset < authData.size()) {
        result.publicKey.assign(authData.begin() + offset, authData.end());
    }

    // Store full attestation object for storage
    result.attestationObject.assign(response.begin() + 1, response.end());

    TITAN_LOG(L"MakeCredential completed successfully");
    return S_OK;
}

//
// GenerateChallenge - Generate random bytes
//
HRESULT Ctap2Helper::GenerateChallenge(std::vector<BYTE>& challenge, DWORD size) {
    challenge.resize(size);
    NTSTATUS status = BCryptGenRandom(nullptr, challenge.data(), size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        challenge.clear();
        return HRESULT_FROM_NT(status);
    }
    return S_OK;
}

//
// ComputeSHA256 - Hash data
//
HRESULT Ctap2Helper::ComputeSHA256(const std::vector<BYTE>& data, std::vector<BYTE>& hash) {
    hash.resize(32);
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        hash.clear();
        return HRESULT_FROM_NT(status);
    }

    status = BCryptHash(hAlg, nullptr, 0, const_cast<BYTE*>(data.data()), (ULONG)data.size(), hash.data(), 32);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        hash.clear();
        return HRESULT_FROM_NT(status);
    }

    return S_OK;
}
