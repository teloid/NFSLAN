#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{

constexpr wchar_t kWindowClassName[] = L"NFSLANRelayWindowClass";
constexpr wchar_t kBuildTag[] = L"2026-02-11-relay-ui-4";

constexpr UINT WM_APP_RELAY_LOG = WM_APP + 20;
constexpr UINT WM_APP_RELAY_STATUS = WM_APP + 21;
constexpr UINT WM_APP_RELAY_STOPPED = WM_APP + 22;
constexpr UINT WM_APP_CAPTURE_DONE = WM_APP + 23;
constexpr int kDefaultCaptureTimeoutMs = 60000;
constexpr size_t kBeaconFieldIdentOffset = 0x08;
constexpr size_t kBeaconFieldIdentMax = 0x08;
constexpr size_t kBeaconFieldNameOffset = 0x28;
constexpr size_t kBeaconFieldNameMax = 0x20;
constexpr size_t kBeaconFieldStatsOffset = 0x48;
constexpr size_t kBeaconFieldStatsMax = 0xC0;
constexpr size_t kBeaconFieldTransportOffset = 0x108;
constexpr size_t kBeaconFieldTransportMax = 0x40;

enum ControlId : int
{
    kIdModeCombo = 1100,
    kIdListenPortEdit,
    kIdTargetPortEdit,
    kIdFixedSourceEdit,
    kIdPeersEdit,
    kIdStartButton,
    kIdStopButton,
    kIdClearLogButton,
    kIdCaptureInGameButton,
    kIdCaptureStandaloneButton,
    kIdGenerateDiffButton,
    kIdCopyDiffButton,
    kIdSaveDiffButton,
    kIdResetSamplesButton,
    kIdLogEdit,
    kIdStatusStatic,
    kIdCaptureStatusStatic
};

enum class RelayMode
{
    TransparentSpoof = 0,
    FixedSourceSpoof = 1,
    NoSpoof = 2
};

struct RelayConfig
{
    RelayMode mode = RelayMode::TransparentSpoof;
    uint16_t listenPort = 9999;
    uint16_t targetPort = 9999;
    uint32_t fixedSourceAddress = 0;
    std::vector<uint32_t> peerAddresses;
};

struct RelayRuntime
{
    std::atomic<bool> running{ false };
    std::atomic<bool> stopRequested{ false };
    std::thread worker;
};

enum class CaptureTarget
{
    InGame,
    Standalone
};

struct CaptureRuntime
{
    std::atomic<bool> running{ false };
    std::atomic<bool> stopRequested{ false };
    std::thread worker;
};

struct BeaconSample
{
    std::vector<uint8_t> payload;
    uint32_t sourceIp = 0;
    uint16_t sourcePort = 0;
    std::wstring capturedAt;
};

struct CaptureResultMessage
{
    CaptureTarget target = CaptureTarget::InGame;
    bool success = false;
    std::wstring info;
    BeaconSample sample;
};

struct AppState
{
    HWND window = nullptr;
    HWND modeCombo = nullptr;
    HWND listenPortEdit = nullptr;
    HWND targetPortEdit = nullptr;
    HWND fixedSourceEdit = nullptr;
    HWND peersEdit = nullptr;
    HWND startButton = nullptr;
    HWND stopButton = nullptr;
    HWND clearLogButton = nullptr;
    HWND captureInGameButton = nullptr;
    HWND captureStandaloneButton = nullptr;
    HWND generateDiffButton = nullptr;
    HWND copyDiffButton = nullptr;
    HWND saveDiffButton = nullptr;
    HWND resetSamplesButton = nullptr;
    HWND logEdit = nullptr;
    HWND statusStatic = nullptr;
    HWND captureStatusStatic = nullptr;
    RelayRuntime runtime;
    CaptureRuntime capture;
    std::optional<BeaconSample> inGameSample;
    std::optional<BeaconSample> standaloneSample;
    std::wstring lastDiffReport;
};

AppState g_app;

void showValidationError(const std::wstring& message);

#pragma pack(push, 1)
struct Ipv4Header
{
    uint8_t versionIhl;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t id;
    uint16_t fragmentOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t sourceAddress;
    uint32_t destinationAddress;
};

struct UdpHeader
{
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint16_t length;
    uint16_t checksum;
};

struct UdpPseudoHeader
{
    uint32_t sourceAddress;
    uint32_t destinationAddress;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udpLength;
};
#pragma pack(pop)

std::wstring trim(const std::wstring& input)
{
    size_t first = 0;
    while (first < input.size() && iswspace(input[first]))
    {
        ++first;
    }
    if (first == input.size())
    {
        return L"";
    }

    size_t last = input.size();
    while (last > first && iswspace(input[last - 1]))
    {
        --last;
    }
    return input.substr(first, last - first);
}

std::wstring nowTimestamp()
{
    SYSTEMTIME st{};
    GetLocalTime(&st);

    wchar_t buffer[64] = {};
    swprintf_s(
        buffer,
        L"%04u-%02u-%02u %02u:%02u:%02u",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond);
    return buffer;
}

std::wstring getWindowTextString(HWND window)
{
    const int length = GetWindowTextLengthW(window);
    if (length <= 0)
    {
        return L"";
    }

    std::wstring value(static_cast<size_t>(length) + 1, L'\0');
    GetWindowTextW(window, value.data(), length + 1);
    value.resize(wcslen(value.c_str()));
    return value;
}

void setWindowTextString(HWND window, const std::wstring& value)
{
    SetWindowTextW(window, value.c_str());
}

void appendRawToEdit(HWND edit, const std::wstring& value)
{
    SendMessageW(edit, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(value.c_str()));
}

void appendLogLine(const std::wstring& line)
{
    if (!g_app.logEdit)
    {
        return;
    }

    appendRawToEdit(g_app.logEdit, L"[" + nowTimestamp() + L"] " + line + L"\r\n");
}

void postLog(const std::wstring& line)
{
    if (!g_app.window)
    {
        return;
    }

    auto* copy = new std::wstring(line);
    PostMessageW(g_app.window, WM_APP_RELAY_LOG, 0, reinterpret_cast<LPARAM>(copy));
}

void postStatus(const std::wstring& text)
{
    if (!g_app.window)
    {
        return;
    }

    auto* copy = new std::wstring(text);
    PostMessageW(g_app.window, WM_APP_RELAY_STATUS, 0, reinterpret_cast<LPARAM>(copy));
}

std::wstring relayModeLabel(RelayMode mode)
{
    switch (mode)
    {
    case RelayMode::TransparentSpoof:
        return L"Transparent spoof (VPN/LAN, admin)";
    case RelayMode::FixedSourceSpoof:
        return L"Fixed source spoof (-e style, admin)";
    case RelayMode::NoSpoof:
        return L"No spoof (compat mode, no admin)";
    default:
        return L"Unknown";
    }
}

bool parsePort(const std::wstring& text, uint16_t* portOut)
{
    const std::wstring normalized = trim(text);
    if (normalized.empty())
    {
        return false;
    }

    wchar_t* end = nullptr;
    const long value = wcstol(normalized.c_str(), &end, 10);
    if (!end || *end != L'\0')
    {
        return false;
    }

    if (value < 1 || value > 65535)
    {
        return false;
    }

    *portOut = static_cast<uint16_t>(value);
    return true;
}

bool parseIpv4Address(const std::wstring& text, uint32_t* addressOut)
{
    in_addr addr{};
    const int parsed = InetPtonW(AF_INET, trim(text).c_str(), &addr);
    if (parsed != 1)
    {
        return false;
    }

    *addressOut = addr.s_addr;
    return true;
}

std::wstring formatIpv4Address(uint32_t address)
{
    in_addr addr{};
    addr.s_addr = address;

    wchar_t buffer[64] = {};
    if (!InetNtopW(AF_INET, &addr, buffer, static_cast<DWORD>(_countof(buffer))))
    {
        return L"<invalid>";
    }
    return buffer;
}

uint32_t ipv4HostOrder(uint32_t address)
{
    return ntohl(address);
}

bool isIpv4Loopback(uint32_t address)
{
    const uint32_t host = ipv4HostOrder(address);
    return (host & 0xFF000000u) == 0x7F000000u;
}

bool isIpv4PrivateOrLocal(uint32_t address)
{
    const uint32_t host = ipv4HostOrder(address);
    const uint8_t a = static_cast<uint8_t>((host >> 24) & 0xFFu);
    const uint8_t b = static_cast<uint8_t>((host >> 16) & 0xFFu);

    if (a == 10u)
    {
        return true;
    }
    if (a == 172u && b >= 16u && b <= 31u)
    {
        return true;
    }
    if (a == 192u && b == 168u)
    {
        return true;
    }
    if (a == 169u && b == 254u)
    {
        return true;
    }
    if (a == 127u)
    {
        return true;
    }
    return false;
}

RelayMode currentRelayMode()
{
    const LRESULT selected = SendMessageW(g_app.modeCombo, CB_GETCURSEL, 0, 0);
    if (selected == 1)
    {
        return RelayMode::FixedSourceSpoof;
    }
    if (selected == 2)
    {
        return RelayMode::NoSpoof;
    }
    return RelayMode::TransparentSpoof;
}

void refreshModeDependentUi()
{
    const RelayMode mode = currentRelayMode();
    const bool fixedMode = (mode == RelayMode::FixedSourceSpoof);
    EnableWindow(g_app.fixedSourceEdit, fixedMode ? TRUE : FALSE);
}

void setUiRunningState(bool running)
{
    const bool capturing = g_app.capture.running.load();

    EnableWindow(g_app.modeCombo, running ? FALSE : TRUE);
    EnableWindow(g_app.listenPortEdit, running ? FALSE : TRUE);
    EnableWindow(g_app.targetPortEdit, running ? FALSE : TRUE);
    EnableWindow(g_app.peersEdit, running ? FALSE : TRUE);
    EnableWindow(g_app.fixedSourceEdit, (!running && currentRelayMode() == RelayMode::FixedSourceSpoof) ? TRUE : FALSE);

    EnableWindow(g_app.startButton, (running || capturing) ? FALSE : TRUE);
    EnableWindow(g_app.stopButton, (running || capturing) ? TRUE : FALSE);
    EnableWindow(g_app.captureInGameButton, (running || capturing) ? FALSE : TRUE);
    EnableWindow(g_app.captureStandaloneButton, (running || capturing) ? FALSE : TRUE);
    EnableWindow(g_app.generateDiffButton, (running || capturing) ? FALSE : TRUE);
    EnableWindow(g_app.resetSamplesButton, (running || capturing) ? FALSE : TRUE);
    EnableWindow(g_app.copyDiffButton, (capturing || g_app.lastDiffReport.empty()) ? FALSE : TRUE);
    EnableWindow(g_app.saveDiffButton, (capturing || g_app.lastDiffReport.empty()) ? FALSE : TRUE);
}

char printableAsciiByte(uint8_t b)
{
    return (b >= 32 && b <= 126) ? static_cast<char>(b) : '.';
}

std::wstring wideFromAscii(const std::string& text)
{
    std::wstring out;
    out.reserve(text.size());
    for (unsigned char ch : text)
    {
        out.push_back(static_cast<wchar_t>(ch));
    }
    return out;
}

std::string readPrintableField(const std::vector<uint8_t>& payload, size_t offset, size_t maxLen)
{
    if (offset >= payload.size() || maxLen == 0)
    {
        return {};
    }

    const size_t limit = (std::min)(payload.size(), offset + maxLen);
    std::string out;
    out.reserve(limit - offset);
    for (size_t i = offset; i < limit; ++i)
    {
        const char ch = static_cast<char>(payload[i]);
        if (ch == '\0')
        {
            break;
        }
        if (static_cast<unsigned char>(ch) < 32 || static_cast<unsigned char>(ch) > 126)
        {
            break;
        }
        out.push_back(ch);
    }
    return out;
}

bool looksLikeLanDiscoveryPayload(const std::vector<uint8_t>& payload)
{
    if (payload.size() < 9)
    {
        return false;
    }
    if (!(payload[0] == static_cast<uint8_t>('g')
        && payload[1] == static_cast<uint8_t>('E')
        && payload[2] == static_cast<uint8_t>('A')))
    {
        return false;
    }
    if (payload[3] != static_cast<uint8_t>(0x03))
    {
        return false;
    }
    if (payload[8] == static_cast<uint8_t>('?'))
    {
        return false;
    }
    return true;
}

bool isLoopbackIpv4(uint32_t addressNetworkOrder)
{
    const uint32_t host = ntohl(addressNetworkOrder);
    return ((host >> 24) & 0xFFu) == 127u;
}

int scoreBeaconSample(const BeaconSample& sample, uint16_t listenPort)
{
    int score = 0;
    if (!isLoopbackIpv4(sample.sourceIp))
    {
        score += 100;
    }
    if (sample.sourcePort == listenPort)
    {
        score += 20;
    }
    if (sample.payload.size() == 384)
    {
        score += 5;
    }

    const std::string ident = readPrintableField(sample.payload, kBeaconFieldIdentOffset, kBeaconFieldIdentMax);
    if (ident == "NFSU2NA" || ident == "NFSMWNA")
    {
        score += 10;
    }

    return score;
}

bool pickPrimaryIpv4Address(uint32_t* addressOut)
{
    char hostname[256] = {};
    if (gethostname(hostname, static_cast<int>(sizeof(hostname))) == SOCKET_ERROR)
    {
        return false;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* result = nullptr;
    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0 || !result)
    {
        return false;
    }

    uint32_t fallbackAddress = 0;
    for (addrinfo* current = result; current; current = current->ai_next)
    {
        if (!current->ai_addr || current->ai_addrlen < static_cast<int>(sizeof(sockaddr_in)))
        {
            continue;
        }

        const auto* address = reinterpret_cast<const sockaddr_in*>(current->ai_addr);
        if (address->sin_addr.s_addr == 0)
        {
            continue;
        }

        if (fallbackAddress == 0)
        {
            fallbackAddress = address->sin_addr.s_addr;
        }

        if (address->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
        {
            *addressOut = address->sin_addr.s_addr;
            freeaddrinfo(result);
            return true;
        }
    }

    freeaddrinfo(result);
    if (fallbackAddress == 0)
    {
        return false;
    }

    *addressOut = fallbackAddress;
    return true;
}

bool tryExtractLanDiscoveryFromRawIp(
    const uint8_t* frame,
    int frameLength,
    uint16_t listenPort,
    BeaconSample* sampleOut)
{
    if (!frame || frameLength < 28)
    {
        return false;
    }

    const uint8_t version = static_cast<uint8_t>(frame[0] >> 4);
    const size_t ipHeaderLength = static_cast<size_t>(frame[0] & 0x0F) * 4u;
    if (version != 4 || ipHeaderLength < 20 || frameLength < static_cast<int>(ipHeaderLength + sizeof(UdpHeader)))
    {
        return false;
    }

    if (frame[9] != static_cast<uint8_t>(IPPROTO_UDP))
    {
        return false;
    }

    const auto* ip = reinterpret_cast<const Ipv4Header*>(frame);
    const auto* udp = reinterpret_cast<const UdpHeader*>(frame + ipHeaderLength);
    const uint16_t sourcePort = ntohs(udp->sourcePort);
    const uint16_t destinationPort = ntohs(udp->destinationPort);
    if (sourcePort != listenPort && destinationPort != listenPort)
    {
        return false;
    }

    int udpLength = static_cast<int>(ntohs(udp->length));
    if (udpLength < static_cast<int>(sizeof(UdpHeader)))
    {
        return false;
    }

    int payloadLength = udpLength - static_cast<int>(sizeof(UdpHeader));
    const int framePayloadMax = frameLength - static_cast<int>(ipHeaderLength + sizeof(UdpHeader));
    if (payloadLength > framePayloadMax)
    {
        payloadLength = framePayloadMax;
    }
    if (payloadLength <= 0)
    {
        return false;
    }

    std::vector<uint8_t> payload(payloadLength);
    std::memcpy(payload.data(), frame + ipHeaderLength + sizeof(UdpHeader), static_cast<size_t>(payloadLength));
    if (!looksLikeLanDiscoveryPayload(payload))
    {
        return false;
    }

    sampleOut->payload = std::move(payload);
    sampleOut->sourceIp = ip->sourceAddress;
    sampleOut->sourcePort = sourcePort;
    sampleOut->capturedAt = nowTimestamp();
    return true;
}

std::wstring formatSampleSummary(const std::optional<BeaconSample>& sample)
{
    if (!sample.has_value())
    {
        return L"<missing>";
    }

    std::wostringstream stream;
    stream << L"src=" << formatIpv4Address(sample->sourceIp)
           << L":" << sample->sourcePort
           << L", bytes=" << sample->payload.size()
           << L", at=" << sample->capturedAt;
    return stream.str();
}

std::wstring formatSampleSummary(const BeaconSample& sample)
{
    std::wostringstream stream;
    stream << L"src=" << formatIpv4Address(sample.sourceIp)
           << L":" << sample.sourcePort
           << L", bytes=" << sample.payload.size()
           << L", at=" << sample.capturedAt;
    return stream.str();
}

void updateCaptureStatusLabel()
{
    if (!g_app.captureStatusStatic)
    {
        return;
    }

    std::wstring status = L"In-game: " + formatSampleSummary(g_app.inGameSample)
        + L" | Standalone: " + formatSampleSummary(g_app.standaloneSample);
    setWindowTextString(g_app.captureStatusStatic, status);
}

std::wstring buildHexDump(const std::vector<uint8_t>& payload)
{
    std::wostringstream stream;
    stream << std::hex << std::setfill(L'0');

    for (size_t offset = 0; offset < payload.size(); offset += 16)
    {
        stream << L"0x" << std::setw(3) << offset << L": ";

        std::array<char, 16> ascii{};
        ascii.fill(' ');
        for (size_t i = 0; i < 16; ++i)
        {
            if (offset + i < payload.size())
            {
                const uint8_t b = payload[offset + i];
                stream << std::setw(2) << static_cast<unsigned int>(b) << L' ';
                ascii[i] = printableAsciiByte(b);
            }
            else
            {
                stream << L"   ";
                ascii[i] = ' ';
            }
        }

        stream << L" |";
        for (char ch : ascii)
        {
            stream << static_cast<wchar_t>(ch);
        }
        stream << L"|\n";
    }

    return stream.str();
}

std::wstring buildFieldDiffLine(const wchar_t* label, const std::string& inGameValue, const std::string& standaloneValue)
{
    std::wostringstream line;
    line << label << L": in-game='" << wideFromAscii(inGameValue)
         << L"' standalone='" << wideFromAscii(standaloneValue) << L"'";
    if (inGameValue == standaloneValue)
    {
        line << L" [same]";
    }
    else
    {
        line << L" [DIFF]";
    }
    return line.str();
}

std::wstring buildBeaconDiffReport(const BeaconSample& inGame, const BeaconSample& standalone)
{
    std::wostringstream report;
    report << L"===== NFSLAN RELAY BEACON DIFF REPORT =====\n";
    report << L"Build tag: " << kBuildTag << L"\n";
    report << L"Generated: " << nowTimestamp() << L"\n\n";
    report << L"[In-game sample] " << formatSampleSummary(inGame) << L"\n";
    report << L"[Standalone sample] " << formatSampleSummary(standalone) << L"\n\n";

    const std::string inIdent = readPrintableField(inGame.payload, kBeaconFieldIdentOffset, kBeaconFieldIdentMax);
    const std::string stIdent = readPrintableField(standalone.payload, kBeaconFieldIdentOffset, kBeaconFieldIdentMax);
    const std::string inName = readPrintableField(inGame.payload, kBeaconFieldNameOffset, kBeaconFieldNameMax);
    const std::string stName = readPrintableField(standalone.payload, kBeaconFieldNameOffset, kBeaconFieldNameMax);
    const std::string inStats = readPrintableField(inGame.payload, kBeaconFieldStatsOffset, kBeaconFieldStatsMax);
    const std::string stStats = readPrintableField(standalone.payload, kBeaconFieldStatsOffset, kBeaconFieldStatsMax);
    const std::string inTransport = readPrintableField(inGame.payload, kBeaconFieldTransportOffset, kBeaconFieldTransportMax);
    const std::string stTransport = readPrintableField(standalone.payload, kBeaconFieldTransportOffset, kBeaconFieldTransportMax);

    report << L"[Field comparison]\n";
    report << buildFieldDiffLine(L"ident@0x008", inIdent, stIdent) << L"\n";
    report << buildFieldDiffLine(L"name@0x028", inName, stName) << L"\n";
    report << buildFieldDiffLine(L"stats@0x048", inStats, stStats) << L"\n";
    report << buildFieldDiffLine(L"transport@0x108", inTransport, stTransport) << L"\n\n";

    const size_t commonLength = (std::min)(inGame.payload.size(), standalone.payload.size());
    std::vector<size_t> diffOffsets;
    diffOffsets.reserve(commonLength);
    for (size_t i = 0; i < commonLength; ++i)
    {
        if (inGame.payload[i] != standalone.payload[i])
        {
            diffOffsets.push_back(i);
        }
    }

    report << L"[Byte diff summary]\n";
    report << L"Common bytes compared: " << commonLength << L"\n";
    report << L"Changed offsets: " << diffOffsets.size() << L"\n";
    if (inGame.payload.size() != standalone.payload.size())
    {
        report << L"Payload sizes differ: in-game=" << inGame.payload.size()
               << L", standalone=" << standalone.payload.size() << L"\n";
    }

    const bool onlyStatsBitFlip =
        (diffOffsets.size() == 1 && diffOffsets.front() == 0x4D);
    const bool payloadMostlySame = diffOffsets.size() <= 4;
    const bool standaloneSourceLooksLocal =
        isIpv4Loopback(standalone.sourceIp) || isIpv4PrivateOrLocal(standalone.sourceIp);
    const bool inGameSourceLooksLocal =
        isIpv4Loopback(inGame.sourceIp) || isIpv4PrivateOrLocal(inGame.sourceIp);
    const bool sourceEndpointsDiffer =
        (inGame.sourceIp != standalone.sourceIp) || (inGame.sourcePort != standalone.sourcePort);

    report << L"\n[Heuristic diagnosis]\n";
    if (payloadMostlySame && sourceEndpointsDiffer)
    {
        report << L"- Beacon payload is almost identical; issue is likely client-side filtering, not packet format.\n";
    }
    if (onlyStatsBitFlip)
    {
        report << L"- Only stats byte changed (typically '|0' vs '|1'); this is usually NOT enough to explain invisibility.\n";
    }
    if (standaloneSourceLooksLocal)
    {
        report << L"- Standalone source endpoint is local/private; UG2 client self-filter is a high-probability cause.\n";
    }
    if (inGameSourceLooksLocal && standaloneSourceLooksLocal)
    {
        report << L"- Both captures came from local/private space; if standalone still hidden, patch speed2.exe self-filter path.\n";
    }
    report << L"- Recommended next step: run NFSLAN-U2-Patcher while hosting+playing on the same PC.\n";

    if (!diffOffsets.empty())
    {
        report << L"\n[Byte diff ranges]\n";
        size_t rangeStart = diffOffsets[0];
        size_t previous = diffOffsets[0];
        for (size_t i = 1; i < diffOffsets.size(); ++i)
        {
            const size_t current = diffOffsets[i];
            if (current == previous + 1)
            {
                previous = current;
                continue;
            }

            report << L"0x" << std::hex << rangeStart << L"-0x" << previous
                   << std::dec << L" (" << (previous - rangeStart + 1) << L" bytes)\n";
            rangeStart = current;
            previous = current;
        }
        report << L"0x" << std::hex << rangeStart << L"-0x" << previous
               << std::dec << L" (" << (previous - rangeStart + 1) << L" bytes)\n";

        report << L"\n[Byte-by-byte diff]\n";
        report << std::hex << std::setfill(L'0');
        for (size_t offset : diffOffsets)
        {
            const uint8_t inByte = inGame.payload[offset];
            const uint8_t stByte = standalone.payload[offset];
            report << L"0x" << std::setw(3) << offset
                   << L": " << std::setw(2) << static_cast<unsigned int>(inByte)
                   << L"('" << static_cast<wchar_t>(printableAsciiByte(inByte)) << L"')"
                   << L" -> "
                   << std::setw(2) << static_cast<unsigned int>(stByte)
                   << L"('" << static_cast<wchar_t>(printableAsciiByte(stByte)) << L"')\n";
        }
        report << std::dec;
    }

    report << L"\n[Hex dump: in-game]\n" << buildHexDump(inGame.payload);
    report << L"\n[Hex dump: standalone]\n" << buildHexDump(standalone.payload);
    report << L"\n===== END REPORT =====\n";
    return report.str();
}

bool copyTextToClipboard(const std::wstring& text)
{
    if (!OpenClipboard(g_app.window))
    {
        return false;
    }

    EmptyClipboard();
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory)
    {
        CloseClipboard();
        return false;
    }

    void* lock = GlobalLock(memory);
    if (!lock)
    {
        GlobalFree(memory);
        CloseClipboard();
        return false;
    }

    std::memcpy(lock, text.c_str(), bytes);
    GlobalUnlock(memory);

    if (!SetClipboardData(CF_UNICODETEXT, memory))
    {
        GlobalFree(memory);
        CloseClipboard();
        return false;
    }

    CloseClipboard();
    return true;
}

bool parsePeerList(const std::wstring& peersText, std::vector<uint32_t>* peersOut, std::wstring* errorOut)
{
    std::vector<uint32_t> peers;
    std::wistringstream stream(peersText);
    std::wstring line;
    int lineNumber = 0;
    while (std::getline(stream, line))
    {
        ++lineNumber;
        const size_t commentPos = line.find(L'#');
        if (commentPos != std::wstring::npos)
        {
            line = line.substr(0, commentPos);
        }

        const std::wstring item = trim(line);
        if (item.empty())
        {
            continue;
        }

        uint32_t addr = 0;
        if (!parseIpv4Address(item, &addr))
        {
            std::wostringstream error;
            error << L"Invalid peer IPv4 on line " << lineNumber << L": '" << item << L"'.";
            *errorOut = error.str();
            return false;
        }
        peers.push_back(addr);
    }

    std::sort(peers.begin(), peers.end());
    peers.erase(std::unique(peers.begin(), peers.end()), peers.end());
    if (peers.empty())
    {
        *errorOut = L"At least one peer IPv4 address is required.";
        return false;
    }

    *peersOut = peers;
    return true;
}

uint16_t computeChecksum(const uint8_t* data, size_t length)
{
    uint32_t sum = 0;

    while (length > 1)
    {
        sum += (static_cast<uint32_t>(data[0]) << 8) | static_cast<uint32_t>(data[1]);
        data += 2;
        length -= 2;
    }

    if (length == 1)
    {
        sum += (static_cast<uint32_t>(data[0]) << 8);
    }

    while ((sum >> 16) != 0)
    {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

bool sendRawUdpPacket(
    SOCKET rawSocket,
    uint32_t sourceAddress,
    uint32_t destinationAddress,
    uint16_t sourcePort,
    uint16_t destinationPort,
    const char* payload,
    int payloadLength,
    int* wsaErrorOut)
{
    if (payloadLength < 0 || payloadLength > 65507)
    {
        if (wsaErrorOut)
        {
            *wsaErrorOut = WSAEMSGSIZE;
        }
        return false;
    }

    const size_t udpLength = sizeof(UdpHeader) + static_cast<size_t>(payloadLength);
    const size_t packetLength = sizeof(Ipv4Header) + udpLength;
    std::vector<uint8_t> packet(packetLength, 0);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data());
    auto* udp = reinterpret_cast<UdpHeader*>(packet.data() + sizeof(Ipv4Header));
    uint8_t* udpPayload = packet.data() + sizeof(Ipv4Header) + sizeof(UdpHeader);
    if (payloadLength > 0)
    {
        std::memcpy(udpPayload, payload, static_cast<size_t>(payloadLength));
    }

    static std::atomic<uint16_t> packetId{ 0x4000 };
    ip->versionIhl = static_cast<uint8_t>((4u << 4) | 5u);
    ip->tos = 0x10;
    ip->totalLength = htons(static_cast<uint16_t>(packetLength));
    ip->id = htons(packetId.fetch_add(1));
    ip->fragmentOffset = htons(0);
    ip->ttl = 69;
    ip->protocol = IPPROTO_UDP;
    ip->checksum = 0;
    ip->sourceAddress = sourceAddress;
    ip->destinationAddress = destinationAddress;
    ip->checksum = computeChecksum(packet.data(), sizeof(Ipv4Header));

    udp->sourcePort = htons(sourcePort);
    udp->destinationPort = htons(destinationPort);
    udp->length = htons(static_cast<uint16_t>(udpLength));
    udp->checksum = 0;

    std::vector<uint8_t> checksumBuffer(sizeof(UdpPseudoHeader) + udpLength, 0);
    auto* pseudo = reinterpret_cast<UdpPseudoHeader*>(checksumBuffer.data());
    pseudo->sourceAddress = sourceAddress;
    pseudo->destinationAddress = destinationAddress;
    pseudo->zero = 0;
    pseudo->protocol = IPPROTO_UDP;
    pseudo->udpLength = udp->length;
    std::memcpy(
        checksumBuffer.data() + sizeof(UdpPseudoHeader),
        packet.data() + sizeof(Ipv4Header),
        udpLength);
    udp->checksum = computeChecksum(checksumBuffer.data(), checksumBuffer.size());
    if (udp->checksum == 0)
    {
        udp->checksum = 0xFFFF;
    }

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(destinationPort);
    destination.sin_addr.s_addr = destinationAddress;

    const int sent = sendto(
        rawSocket,
        reinterpret_cast<const char*>(packet.data()),
        static_cast<int>(packet.size()),
        0,
        reinterpret_cast<const sockaddr*>(&destination),
        sizeof(destination));
    if (sent == SOCKET_ERROR)
    {
        if (wsaErrorOut)
        {
            *wsaErrorOut = WSAGetLastError();
        }
        return false;
    }

    return true;
}

std::optional<RelayConfig> buildRelayConfigFromUi(std::wstring* errorOut)
{
    RelayConfig config;
    config.mode = currentRelayMode();

    if (!parsePort(getWindowTextString(g_app.listenPortEdit), &config.listenPort))
    {
        *errorOut = L"Listen port must be in range 1..65535.";
        return std::nullopt;
    }

    if (!parsePort(getWindowTextString(g_app.targetPortEdit), &config.targetPort))
    {
        *errorOut = L"Target port must be in range 1..65535.";
        return std::nullopt;
    }

    if (!parsePeerList(getWindowTextString(g_app.peersEdit), &config.peerAddresses, errorOut))
    {
        return std::nullopt;
    }

    if (config.mode == RelayMode::FixedSourceSpoof)
    {
        if (!parseIpv4Address(getWindowTextString(g_app.fixedSourceEdit), &config.fixedSourceAddress))
        {
            *errorOut = L"Fixed source IP must be a valid IPv4 address in fixed-source mode.";
            return std::nullopt;
        }
    }

    return config;
}

void runRelayWorker(RelayConfig config)
{
    WSADATA wsadata{};
    const int startup = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (startup != 0)
    {
        std::wostringstream msg;
        msg << L"WSAStartup failed: " << startup;
        postLog(msg.str());
        return;
    }

    SOCKET receiveSocket = INVALID_SOCKET;
    SOCKET sendSocket = INVALID_SOCKET;
    SOCKET rawSocket = INVALID_SOCKET;

    auto closeSockets = [&]()
    {
        if (receiveSocket != INVALID_SOCKET)
        {
            closesocket(receiveSocket);
            receiveSocket = INVALID_SOCKET;
        }
        if (sendSocket != INVALID_SOCKET)
        {
            closesocket(sendSocket);
            sendSocket = INVALID_SOCKET;
        }
        if (rawSocket != INVALID_SOCKET)
        {
            closesocket(rawSocket);
            rawSocket = INVALID_SOCKET;
        }
    };

    receiveSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (receiveSocket == INVALID_SOCKET)
    {
        const int err = WSAGetLastError();
        std::wostringstream msg;
        msg << L"Failed to create receive socket. WSA error " << err;
        postLog(msg.str());
        closeSockets();
        WSACleanup();
        return;
    }

    int reuse = 1;
    setsockopt(receiveSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in bindAddress{};
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_port = htons(config.listenPort);
    bindAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(receiveSocket, reinterpret_cast<const sockaddr*>(&bindAddress), sizeof(bindAddress)) == SOCKET_ERROR)
    {
        const int err = WSAGetLastError();
        std::wostringstream msg;
        msg << L"Failed to bind receive socket on UDP " << config.listenPort << L". WSA error " << err;
        postLog(msg.str());
        closeSockets();
        WSACleanup();
        return;
    }

    if (config.mode == RelayMode::NoSpoof)
    {
        sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sendSocket == INVALID_SOCKET)
        {
            const int err = WSAGetLastError();
            std::wostringstream msg;
            msg << L"Failed to create send socket. WSA error " << err;
            postLog(msg.str());
            closeSockets();
            WSACleanup();
            return;
        }
    }
    else
    {
        rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (rawSocket == INVALID_SOCKET)
        {
            const int err = WSAGetLastError();
            std::wostringstream msg;
            msg << L"Failed to create raw socket. WSA error " << err
                << L" (try running as Administrator).";
            postLog(msg.str());
            closeSockets();
            WSACleanup();
            return;
        }

        int includeHeaders = 1;
        if (setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, reinterpret_cast<const char*>(&includeHeaders), sizeof(includeHeaders))
            == SOCKET_ERROR)
        {
            const int err = WSAGetLastError();
            std::wostringstream msg;
            msg << L"Failed to enable IP_HDRINCL. WSA error " << err
                << L" (try running as Administrator).";
            postLog(msg.str());
            closeSockets();
            WSACleanup();
            return;
        }
    }

    std::wostringstream startupMessage;
    startupMessage << L"Relay started. mode=" << relayModeLabel(config.mode)
                   << L", listen=" << config.listenPort
                   << L", target=" << config.targetPort
                   << L", peers=" << config.peerAddresses.size();
    if (config.mode == RelayMode::FixedSourceSpoof)
    {
        startupMessage << L", fixedSource=" << formatIpv4Address(config.fixedSourceAddress);
    }
    postLog(startupMessage.str());
    postStatus(L"Running");

    std::vector<char> buffer(2048, 0);
    uint64_t receivedPackets = 0;
    uint64_t forwardedPackets = 0;

    while (!g_app.runtime.stopRequested.load())
    {
        fd_set readSet{};
        FD_ZERO(&readSet);
        FD_SET(receiveSocket, &readSet);

        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = 250000;

        const int selectResult = select(0, &readSet, nullptr, nullptr, &timeout);
        if (selectResult == SOCKET_ERROR)
        {
            const int err = WSAGetLastError();
            std::wostringstream msg;
            msg << L"select() failed. WSA error " << err;
            postLog(msg.str());
            break;
        }
        if (selectResult == 0)
        {
            continue;
        }

        sockaddr_in sourceAddress{};
        int sourceLength = sizeof(sourceAddress);
        const int received = recvfrom(
            receiveSocket,
            buffer.data(),
            static_cast<int>(buffer.size()),
            0,
            reinterpret_cast<sockaddr*>(&sourceAddress),
            &sourceLength);
        if (received == SOCKET_ERROR)
        {
            const int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != WSAETIMEDOUT)
            {
                std::wostringstream msg;
                msg << L"recvfrom() failed. WSA error " << err;
                postLog(msg.str());
            }
            continue;
        }
        if (received <= 0)
        {
            continue;
        }

        ++receivedPackets;
        const uint32_t sourceIp = sourceAddress.sin_addr.s_addr;
        int forwardedThisPacket = 0;

        for (const uint32_t peerAddress : config.peerAddresses)
        {
            if (peerAddress == sourceIp)
            {
                continue;
            }

            bool sentOk = false;
            int sendErr = 0;
            if (config.mode == RelayMode::NoSpoof)
            {
                sockaddr_in destination{};
                destination.sin_family = AF_INET;
                destination.sin_port = htons(config.targetPort);
                destination.sin_addr.s_addr = peerAddress;
                const int sent = sendto(
                    sendSocket,
                    buffer.data(),
                    received,
                    0,
                    reinterpret_cast<const sockaddr*>(&destination),
                    sizeof(destination));
                if (sent != SOCKET_ERROR)
                {
                    sentOk = true;
                }
                else
                {
                    sendErr = WSAGetLastError();
                }
            }
            else
            {
                const uint32_t spoofSource =
                    (config.mode == RelayMode::FixedSourceSpoof) ? config.fixedSourceAddress : sourceIp;
                sentOk = sendRawUdpPacket(
                    rawSocket,
                    spoofSource,
                    peerAddress,
                    config.listenPort,
                    config.targetPort,
                    buffer.data(),
                    received,
                    &sendErr);
            }

            if (sentOk)
            {
                ++forwardedPackets;
                ++forwardedThisPacket;
            }
            else
            {
                std::wostringstream msg;
                msg << L"Forward failed to " << formatIpv4Address(peerAddress)
                    << L" (WSA error " << sendErr << L").";
                postLog(msg.str());
            }
        }

        if (receivedPackets <= 20 || (receivedPackets % 100) == 0)
        {
            std::wostringstream msg;
            msg << L"packet " << receivedPackets
                << L": src=" << formatIpv4Address(sourceIp)
                << L", bytes=" << received
                << L", forwarded=" << forwardedThisPacket;
            postLog(msg.str());
        }
    }

    std::wostringstream summary;
    summary << L"Relay stopped. received=" << receivedPackets << L", forwarded=" << forwardedPackets;
    postLog(summary.str());
    postStatus(L"Stopped");

    closeSockets();
    WSACleanup();
}

std::string toUtf8(const std::wstring& text)
{
    if (text.empty())
    {
        return {};
    }

    const int length = WideCharToMultiByte(
        CP_UTF8,
        0,
        text.c_str(),
        static_cast<int>(text.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (length <= 0)
    {
        return {};
    }

    std::string out(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        text.c_str(),
        static_cast<int>(text.size()),
        out.data(),
        length,
        nullptr,
        nullptr);
    return out;
}

std::wstring relayDiffReportPath()
{
    wchar_t modulePath[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, modulePath, static_cast<DWORD>(_countof(modulePath))) <= 0)
    {
        return L"relay-beacon-diff.txt";
    }

    std::wstring path(modulePath);
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
    {
        return L"relay-beacon-diff.txt";
    }
    return path.substr(0, slash + 1) + L"relay-beacon-diff.txt";
}

void finalizeCaptureThread()
{
    if (g_app.capture.worker.joinable())
    {
        g_app.capture.worker.join();
    }
    g_app.capture.running.store(false);
    g_app.capture.stopRequested.store(false);
    setUiRunningState(g_app.runtime.running.load());
}

void postCaptureDone(CaptureResultMessage* message)
{
    if (!g_app.window)
    {
        delete message;
        return;
    }
    PostMessageW(g_app.window, WM_APP_CAPTURE_DONE, 0, reinterpret_cast<LPARAM>(message));
}

void runCaptureWorker(CaptureTarget target, uint16_t listenPort)
{
    auto* result = new CaptureResultMessage();
    result->target = target;

    WSADATA wsadata{};
    const int startup = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (startup != 0)
    {
        result->success = false;
        result->info = L"Capture failed: WSAStartup error " + std::to_wstring(startup) + L".";
        postCaptureDone(result);
        return;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kDefaultCaptureTimeoutMs);
    auto finalizeResult = [&]()
    {
        WSACleanup();
        if (g_app.capture.stopRequested.load())
        {
            delete result;
            return;
        }
        postCaptureDone(result);
    };

    auto fillSuccessMessage = [&]()
    {
        std::wostringstream msg;
        msg << L"Captured "
            << ((target == CaptureTarget::InGame) ? L"in-game" : L"standalone")
            << L" sample from " << formatIpv4Address(result->sample.sourceIp)
            << L":" << result->sample.sourcePort
            << L" bytes=" << result->sample.payload.size() << L".";
        result->info = msg.str();
    };

    auto captureViaUdpBoundSocket = [&](SOCKET socketHandle) -> bool
    {
        std::vector<uint8_t> buffer(2048);
        bool haveSample = false;
        BeaconSample bestSample;
        int bestScore = -1;

        while (!g_app.capture.stopRequested.load() && std::chrono::steady_clock::now() < deadline)
        {
            sockaddr_in from{};
            int fromLen = sizeof(from);
            const int received = recvfrom(
                socketHandle,
                reinterpret_cast<char*>(buffer.data()),
                static_cast<int>(buffer.size()),
                0,
                reinterpret_cast<sockaddr*>(&from),
                &fromLen);
            if (received <= 0)
            {
                continue;
            }

            std::vector<uint8_t> payload(buffer.begin(), buffer.begin() + received);
            if (!looksLikeLanDiscoveryPayload(payload))
            {
                continue;
            }

            BeaconSample candidate;
            candidate.payload = std::move(payload);
            candidate.sourceIp = from.sin_addr.s_addr;
            candidate.sourcePort = ntohs(from.sin_port);
            candidate.capturedAt = nowTimestamp();
            const int candidateScore = scoreBeaconSample(candidate, listenPort);
            if (!haveSample || candidateScore > bestScore)
            {
                bestSample = std::move(candidate);
                bestScore = candidateScore;
                haveSample = true;
            }

            if (haveSample && bestScore >= 120)
            {
                break;
            }
        }

        if (haveSample)
        {
            result->success = true;
            result->sample = std::move(bestSample);
            fillSuccessMessage();
            result->info += L" (selected best packet score=" + std::to_wstring(bestScore) + L")";
            return true;
        }
        return false;
    };

    auto captureViaRawSocketFallback = [&]() -> bool
    {
        SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (rawSocket == INVALID_SOCKET)
        {
            const int err = WSAGetLastError();
            result->info =
                L"Capture failed: UDP port is busy and raw fallback socket creation failed (WSA "
                + std::to_wstring(err)
                + L"). Run as Administrator or stop app using UDP "
                + std::to_wstring(listenPort) + L".";
            return false;
        }

        DWORD timeoutMs = 250;
        setsockopt(rawSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));

        uint32_t localAddress = 0;
        if (!pickPrimaryIpv4Address(&localAddress))
        {
            closesocket(rawSocket);
            result->info = L"Capture failed: could not resolve local IPv4 address for raw fallback.";
            return false;
        }

        sockaddr_in bindAddress{};
        bindAddress.sin_family = AF_INET;
        bindAddress.sin_port = 0;
        bindAddress.sin_addr.s_addr = localAddress;
        if (bind(rawSocket, reinterpret_cast<const sockaddr*>(&bindAddress), sizeof(bindAddress)) == SOCKET_ERROR)
        {
            const int err = WSAGetLastError();
            closesocket(rawSocket);
            result->info =
                L"Capture failed: raw fallback bind failed on "
                + formatIpv4Address(localAddress) + L" (WSA " + std::to_wstring(err) + L").";
            return false;
        }

        DWORD rcval = RCVALL_ON;
        DWORD bytesReturned = 0;
        if (WSAIoctl(
                rawSocket,
                SIO_RCVALL,
                &rcval,
                sizeof(rcval),
                nullptr,
                0,
                &bytesReturned,
                nullptr,
                nullptr) == SOCKET_ERROR)
        {
            const int err = WSAGetLastError();
            closesocket(rawSocket);
            result->info =
                L"Capture failed: raw fallback capture mode rejected (WSA " + std::to_wstring(err)
                + L"). Try running relay as Administrator.";
            return false;
        }

        bool captured = false;
        BeaconSample bestSample;
        int bestScore = -1;
        std::vector<uint8_t> frameBuffer(65536);
        while (!g_app.capture.stopRequested.load() && std::chrono::steady_clock::now() < deadline)
        {
            const int received = recv(rawSocket, reinterpret_cast<char*>(frameBuffer.data()), static_cast<int>(frameBuffer.size()), 0);
            if (received <= 0)
            {
                continue;
            }

            BeaconSample sample;
            if (!tryExtractLanDiscoveryFromRawIp(frameBuffer.data(), received, listenPort, &sample))
            {
                continue;
            }

            const int candidateScore = scoreBeaconSample(sample, listenPort);
            if (!captured || candidateScore > bestScore)
            {
                bestSample = std::move(sample);
                bestScore = candidateScore;
                captured = true;
            }

            if (captured && bestScore >= 120)
            {
                break;
            }
        }

        if (captured)
        {
            result->success = true;
            result->sample = std::move(bestSample);
            fillSuccessMessage();
            result->info += L" (raw fallback mode, selected best packet score=" + std::to_wstring(bestScore) + L")";
        }
        else if (!g_app.capture.stopRequested.load())
        {
            result->info =
                L"Raw fallback capture timed out after "
                + std::to_wstring(kDefaultCaptureTimeoutMs / 1000)
                + L"s on UDP "
                + std::to_wstring(listenPort)
                + L".";
        }

        rcval = RCVALL_OFF;
        WSAIoctl(
            rawSocket,
            SIO_RCVALL,
            &rcval,
            sizeof(rcval),
            nullptr,
            0,
            &bytesReturned,
            nullptr,
            nullptr);
        closesocket(rawSocket);
        return captured;
    };

    SOCKET receiveSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (receiveSocket == INVALID_SOCKET)
    {
        const int err = WSAGetLastError();
        result->success = false;
        result->info = L"Capture failed: cannot create UDP socket (WSA " + std::to_wstring(err) + L").";
        finalizeResult();
        return;
    }

    DWORD timeoutMs = 250;
    setsockopt(receiveSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
    int reuse = 1;
    setsockopt(receiveSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in bindAddress{};
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_port = htons(listenPort);
    bindAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(receiveSocket, reinterpret_cast<const sockaddr*>(&bindAddress), sizeof(bindAddress)) == SOCKET_ERROR)
    {
        const int err = WSAGetLastError();
        closesocket(receiveSocket);
        receiveSocket = INVALID_SOCKET;

        if (err == WSAEADDRINUSE)
        {
            result->info =
                L"UDP " + std::to_wstring(listenPort)
                + L" is busy (WSA 10048), trying raw fallback capture...";
            if (!captureViaRawSocketFallback())
            {
                result->success = false;
            }
        }
        else
        {
            result->success = false;
            result->info =
                L"Capture failed: cannot bind UDP " + std::to_wstring(listenPort)
                + L" (WSA " + std::to_wstring(err) + L").";
        }
    }
    else
    {
        captureViaUdpBoundSocket(receiveSocket);
        closesocket(receiveSocket);
        receiveSocket = INVALID_SOCKET;
    }

    if (!result->success)
    {
        if (g_app.capture.stopRequested.load())
        {
            result->info = L"Capture cancelled.";
        }
        else if (result->info.empty())
        {
            result->info = L"Capture timeout after "
                + std::to_wstring(kDefaultCaptureTimeoutMs / 1000)
                + L"s. Start the selected server and keep relay port visible on network.";
        }
    }

    finalizeResult();
}

void startCaptureFromUi(CaptureTarget target)
{
    if (g_app.runtime.running.load())
    {
        showValidationError(L"Stop relay before capture. Capture needs exclusive bind on listen UDP port.");
        return;
    }
    if (g_app.capture.running.load())
    {
        showValidationError(L"A capture is already in progress.");
        return;
    }

    uint16_t listenPort = 0;
    if (!parsePort(getWindowTextString(g_app.listenPortEdit), &listenPort))
    {
        showValidationError(L"Listen port must be in range 1..65535.");
        return;
    }

    g_app.capture.stopRequested.store(false);
    g_app.capture.running.store(true);
    setUiRunningState(g_app.runtime.running.load());
    setWindowTextString(
        g_app.captureStatusStatic,
        (target == CaptureTarget::InGame)
            ? L"Capturing IN-GAME sample... keep only game-host server active."
            : L"Capturing STANDALONE sample... keep only wrapper server active.");
    appendLogLine(
        (target == CaptureTarget::InGame)
            ? L"Capture started: IN-GAME sample (listen UDP " + std::to_wstring(listenPort) + L")."
            : L"Capture started: STANDALONE sample (listen UDP " + std::to_wstring(listenPort) + L").");

    try
    {
        g_app.capture.worker = std::thread(
            [target, listenPort]()
            {
                runCaptureWorker(target, listenPort);
            });
    }
    catch (...)
    {
        g_app.capture.running.store(false);
        g_app.capture.stopRequested.store(false);
        setUiRunningState(g_app.runtime.running.load());
        showValidationError(L"Failed to start capture thread.");
    }
}

void resetCapturedSamples()
{
    if (g_app.capture.running.load())
    {
        showValidationError(L"Stop current capture before resetting samples.");
        return;
    }

    g_app.inGameSample.reset();
    g_app.standaloneSample.reset();
    g_app.lastDiffReport.clear();
    updateCaptureStatusLabel();
    setUiRunningState(g_app.runtime.running.load());
    appendLogLine(L"Cleared captured samples and previous diff report.");
}

void generateDiffFromSamples()
{
    if (!g_app.inGameSample.has_value() || !g_app.standaloneSample.has_value())
    {
        showValidationError(L"Capture both IN-GAME and STANDALONE samples first.");
        return;
    }

    g_app.lastDiffReport = buildBeaconDiffReport(*g_app.inGameSample, *g_app.standaloneSample);
    setUiRunningState(g_app.runtime.running.load());
    appendLogLine(L"Generated detailed beacon diff report.");
    appendRawToEdit(g_app.logEdit, L"\r\n" + g_app.lastDiffReport + L"\r\n");
}

void copyDiffReportToClipboard()
{
    if (g_app.lastDiffReport.empty())
    {
        showValidationError(L"No diff report available. Generate a report first.");
        return;
    }

    if (!copyTextToClipboard(g_app.lastDiffReport))
    {
        showValidationError(L"Failed to copy report to clipboard.");
        return;
    }

    appendLogLine(L"Diff report copied to clipboard.");
}

void saveDiffReportToFile()
{
    if (g_app.lastDiffReport.empty())
    {
        showValidationError(L"No diff report available. Generate a report first.");
        return;
    }

    const std::wstring path = relayDiffReportPath();
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file)
    {
        showValidationError(L"Failed to open output file for diff report.");
        return;
    }

    const std::string utf8 = toUtf8(g_app.lastDiffReport);
    file.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    if (!file.good())
    {
        showValidationError(L"Failed to write diff report file.");
        return;
    }

    appendLogLine(L"Saved diff report: " + path);
}

void showValidationError(const std::wstring& message)
{
    MessageBoxW(g_app.window, message.c_str(), L"NFSLAN Relay", MB_ICONERROR | MB_OK);
}

void startRelayFromUi()
{
    if (g_app.runtime.running.load())
    {
        return;
    }
    if (g_app.capture.running.load())
    {
        showValidationError(L"Wait for capture to finish (or click Stop) before starting relay.");
        return;
    }

    std::wstring validationError;
    const auto config = buildRelayConfigFromUi(&validationError);
    if (!config.has_value())
    {
        appendLogLine(L"Config error: " + validationError);
        showValidationError(validationError);
        return;
    }

    g_app.runtime.stopRequested.store(false);
    g_app.runtime.running.store(true);
    setUiRunningState(true);
    setWindowTextString(g_app.statusStatic, L"Starting...");
    appendLogLine(L"Starting relay...");

    try
    {
        g_app.runtime.worker = std::thread(
            [configCopy = *config]()
            {
                runRelayWorker(configCopy);
                if (g_app.window)
                {
                    PostMessageW(g_app.window, WM_APP_RELAY_STOPPED, 0, 0);
                }
            });
    }
    catch (...)
    {
        g_app.runtime.running.store(false);
        g_app.runtime.stopRequested.store(false);
        setUiRunningState(false);
        setWindowTextString(g_app.statusStatic, L"Stopped");
        appendLogLine(L"Failed to start worker thread.");
        showValidationError(L"Failed to start relay worker thread.");
        return;
    }
}

void stopRelayFromUi(bool waitForThread)
{
    if (!g_app.runtime.running.load() && !g_app.runtime.worker.joinable())
    {
        return;
    }

    g_app.runtime.stopRequested.store(true);
    setWindowTextString(g_app.statusStatic, L"Stopping...");

    if (waitForThread && g_app.runtime.worker.joinable())
    {
        g_app.runtime.worker.join();
    }
}

void stopCaptureFromUi(bool waitForThread)
{
    if (!g_app.capture.running.load() && !g_app.capture.worker.joinable())
    {
        return;
    }

    g_app.capture.stopRequested.store(true);
    setWindowTextString(g_app.captureStatusStatic, L"Stopping capture...");

    if (waitForThread && g_app.capture.worker.joinable())
    {
        g_app.capture.worker.join();
        g_app.capture.running.store(false);
        g_app.capture.stopRequested.store(false);
        updateCaptureStatusLabel();
        setUiRunningState(g_app.runtime.running.load());
    }
}

void finalizeStoppedUi()
{
    if (g_app.runtime.worker.joinable())
    {
        g_app.runtime.worker.join();
    }
    g_app.runtime.running.store(false);
    g_app.runtime.stopRequested.store(false);
    setUiRunningState(false);
    setWindowTextString(g_app.statusStatic, L"Stopped");
}

LRESULT CALLBACK windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        g_app.window = hwnd;

        HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        const int left = 20;
        const int top = 20;
        const int leftWidth = 330;
        const int right = left + leftWidth + 20;
        const int rightWidth = 560;

        auto createLabel = [&](const wchar_t* text, int x, int y, int w, int h) -> HWND
        {
            return CreateWindowExW(
                0,
                L"STATIC",
                text,
                WS_CHILD | WS_VISIBLE,
                x,
                y,
                w,
                h,
                hwnd,
                nullptr,
                nullptr,
                nullptr);
        };

        auto setControlFont = [&](HWND control)
        {
            SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        };

        HWND title = createLabel(L"NFSLAN Relay (UG2/MW LAN Discovery Bridge)", left, top, 420, 20);
        setControlFont(title);

        const std::wstring buildTagText = std::wstring(L"Build: ") + kBuildTag;
        HWND buildTag = createLabel(buildTagText.c_str(), left, top + 22, 300, 18);
        setControlFont(buildTag);

        createLabel(L"Mode", left, top + 52, 120, 18);
        g_app.modeCombo = CreateWindowExW(
            0,
            L"COMBOBOX",
            L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            left,
            top + 72,
            leftWidth,
            160,
            hwnd,
            reinterpret_cast<HMENU>(kIdModeCombo),
            nullptr,
            nullptr);
        SendMessageW(g_app.modeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Transparent spoof (VPN/LAN, admin)"));
        SendMessageW(g_app.modeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Fixed source spoof (-e style, admin)"));
        SendMessageW(g_app.modeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"No spoof (compat mode, no admin)"));
        SendMessageW(g_app.modeCombo, CB_SETCURSEL, 0, 0);
        setControlFont(g_app.modeCombo);

        createLabel(L"Listen UDP port", left, top + 108, 140, 18);
        g_app.listenPortEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            L"9999",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            left,
            top + 128,
            150,
            24,
            hwnd,
            reinterpret_cast<HMENU>(kIdListenPortEdit),
            nullptr,
            nullptr);
        setControlFont(g_app.listenPortEdit);

        createLabel(L"Target UDP port", left + 180, top + 108, 140, 18);
        g_app.targetPortEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            L"9999",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            left + 180,
            top + 128,
            150,
            24,
            hwnd,
            reinterpret_cast<HMENU>(kIdTargetPortEdit),
            nullptr,
            nullptr);
        setControlFont(g_app.targetPortEdit);

        createLabel(L"Fixed source IPv4 (used only in fixed-source mode)", left, top + 164, leftWidth, 18);
        g_app.fixedSourceEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            L"203.0.113.10",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            left,
            top + 184,
            leftWidth,
            24,
            hwnd,
            reinterpret_cast<HMENU>(kIdFixedSourceEdit),
            nullptr,
            nullptr);
        setControlFont(g_app.fixedSourceEdit);

        createLabel(L"Peers (one IPv4 per line)", left, top + 220, leftWidth, 18);
        g_app.peersEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            L"192.168.1.10\r\n192.168.1.20",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            left,
            top + 240,
            leftWidth,
            220,
            hwnd,
            reinterpret_cast<HMENU>(kIdPeersEdit),
            nullptr,
            nullptr);
        setControlFont(g_app.peersEdit);

        g_app.startButton = CreateWindowExW(
            0,
            L"BUTTON",
            L"Start Relay",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            left,
            top + 480,
            100,
            30,
            hwnd,
            reinterpret_cast<HMENU>(kIdStartButton),
            nullptr,
            nullptr);
        setControlFont(g_app.startButton);

        g_app.stopButton = CreateWindowExW(
            0,
            L"BUTTON",
            L"Stop",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            left + 110,
            top + 480,
            80,
            30,
            hwnd,
            reinterpret_cast<HMENU>(kIdStopButton),
            nullptr,
            nullptr);
        setControlFont(g_app.stopButton);

        g_app.clearLogButton = CreateWindowExW(
            0,
            L"BUTTON",
            L"Clear Log",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            left + 200,
            top + 480,
            100,
            30,
            hwnd,
            reinterpret_cast<HMENU>(kIdClearLogButton),
            nullptr,
            nullptr);
        setControlFont(g_app.clearLogButton);

        createLabel(L"Status", left, top + 520, 60, 18);
        g_app.statusStatic = CreateWindowExW(
            0,
            L"STATIC",
            L"Stopped",
            WS_CHILD | WS_VISIBLE,
            left,
            top + 540,
            leftWidth,
            20,
            hwnd,
            reinterpret_cast<HMENU>(kIdStatusStatic),
            nullptr,
            nullptr);
        setControlFont(g_app.statusStatic);

        HWND hint = createLabel(
            L"Notes:\r\n"
            L"- Spoof modes need Administrator rights on Windows.\r\n"
            L"- Use No spoof mode first if testing on one PC.\r\n"
            L"- Relay forwards UDP discovery packets to peer list.\r\n"
            L"- Capture diff flow: in-game sample -> standalone sample -> Generate Diff.",
            left,
            top + 568,
            leftWidth,
            88);
        setControlFont(hint);

        createLabel(L"Beacon diff capture (in-game vs standalone)", right, top + 22, rightWidth, 18);

        g_app.captureInGameButton = CreateWindowExW(
            0,
            L"BUTTON",
            L"Capture In-Game",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            right,
            top + 44,
            140,
            28,
            hwnd,
            reinterpret_cast<HMENU>(kIdCaptureInGameButton),
            nullptr,
            nullptr);
        setControlFont(g_app.captureInGameButton);

        g_app.captureStandaloneButton = CreateWindowExW(
            0,
            L"BUTTON",
            L"Capture Standalone",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            right + 150,
            top + 44,
            160,
            28,
            hwnd,
            reinterpret_cast<HMENU>(kIdCaptureStandaloneButton),
            nullptr,
            nullptr);
        setControlFont(g_app.captureStandaloneButton);

        g_app.generateDiffButton = CreateWindowExW(
            0,
            L"BUTTON",
            L"Generate Diff",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            right + 320,
            top + 44,
            120,
            28,
            hwnd,
            reinterpret_cast<HMENU>(kIdGenerateDiffButton),
            nullptr,
            nullptr);
        setControlFont(g_app.generateDiffButton);

        g_app.copyDiffButton = CreateWindowExW(
            0,
            L"BUTTON",
            L"Copy Diff",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            right,
            top + 78,
            120,
            26,
            hwnd,
            reinterpret_cast<HMENU>(kIdCopyDiffButton),
            nullptr,
            nullptr);
        setControlFont(g_app.copyDiffButton);

        g_app.saveDiffButton = CreateWindowExW(
            0,
            L"BUTTON",
            L"Save Diff",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            right + 130,
            top + 78,
            120,
            26,
            hwnd,
            reinterpret_cast<HMENU>(kIdSaveDiffButton),
            nullptr,
            nullptr);
        setControlFont(g_app.saveDiffButton);

        g_app.resetSamplesButton = CreateWindowExW(
            0,
            L"BUTTON",
            L"Reset Samples",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            right + 260,
            top + 78,
            130,
            26,
            hwnd,
            reinterpret_cast<HMENU>(kIdResetSamplesButton),
            nullptr,
            nullptr);
        setControlFont(g_app.resetSamplesButton);

        g_app.captureStatusStatic = createLabel(
            L"In-game: <missing> | Standalone: <missing>",
            right,
            top + 110,
            rightWidth,
            34);
        setControlFont(g_app.captureStatusStatic);

        createLabel(L"Runtime log", right, top + 150, 200, 18);
        g_app.logEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            right,
            top + 170,
            rightWidth,
            470,
            hwnd,
            reinterpret_cast<HMENU>(kIdLogEdit),
            nullptr,
            nullptr);
        setControlFont(g_app.logEdit);

        appendLogLine(L"NFSLAN Relay UI initialized.");
        appendLogLine(L"Build tag: " + std::wstring(kBuildTag));
        appendLogLine(
            L"Hint: if U2 standalone server is still hidden on same PC with near-identical beacon payloads, "
            L"use NFSLAN-U2-Patcher.");
        setUiRunningState(false);
        updateCaptureStatusLabel();
        refreshModeDependentUi();
        return 0;
    }
    case WM_COMMAND:
    {
        const int controlId = LOWORD(wParam);
        const int code = HIWORD(wParam);
        if (controlId == kIdModeCombo && code == CBN_SELCHANGE)
        {
            refreshModeDependentUi();
            return 0;
        }
        if (controlId == kIdStartButton && code == BN_CLICKED)
        {
            startRelayFromUi();
            return 0;
        }
        if (controlId == kIdStopButton && code == BN_CLICKED)
        {
            bool handled = false;
            if (g_app.capture.running.load() || g_app.capture.worker.joinable())
            {
                stopCaptureFromUi(true);
                appendLogLine(L"Capture stop requested by user.");
                handled = true;
            }
            if (g_app.runtime.running.load() || g_app.runtime.worker.joinable())
            {
                stopRelayFromUi(true);
                finalizeStoppedUi();
                appendLogLine(L"Relay stop requested by user.");
                handled = true;
            }
            if (!handled)
            {
                appendLogLine(L"Nothing to stop.");
            }
            return 0;
        }
        if (controlId == kIdClearLogButton && code == BN_CLICKED)
        {
            setWindowTextString(g_app.logEdit, L"");
            appendLogLine(L"Log cleared.");
            return 0;
        }
        if (controlId == kIdCaptureInGameButton && code == BN_CLICKED)
        {
            startCaptureFromUi(CaptureTarget::InGame);
            return 0;
        }
        if (controlId == kIdCaptureStandaloneButton && code == BN_CLICKED)
        {
            startCaptureFromUi(CaptureTarget::Standalone);
            return 0;
        }
        if (controlId == kIdGenerateDiffButton && code == BN_CLICKED)
        {
            generateDiffFromSamples();
            return 0;
        }
        if (controlId == kIdCopyDiffButton && code == BN_CLICKED)
        {
            copyDiffReportToClipboard();
            return 0;
        }
        if (controlId == kIdSaveDiffButton && code == BN_CLICKED)
        {
            saveDiffReportToFile();
            return 0;
        }
        if (controlId == kIdResetSamplesButton && code == BN_CLICKED)
        {
            resetCapturedSamples();
            return 0;
        }
        break;
    }
    case WM_APP_RELAY_LOG:
    {
        auto* line = reinterpret_cast<std::wstring*>(lParam);
        if (line)
        {
            appendLogLine(*line);
            delete line;
        }
        return 0;
    }
    case WM_APP_RELAY_STATUS:
    {
        auto* status = reinterpret_cast<std::wstring*>(lParam);
        if (status)
        {
            setWindowTextString(g_app.statusStatic, *status);
            delete status;
        }
        return 0;
    }
    case WM_APP_RELAY_STOPPED:
    {
        finalizeStoppedUi();
        return 0;
    }
    case WM_APP_CAPTURE_DONE:
    {
        auto* result = reinterpret_cast<CaptureResultMessage*>(lParam);
        if (result)
        {
            if (result->success)
            {
                if (result->target == CaptureTarget::InGame)
                {
                    g_app.inGameSample = result->sample;
                }
                else
                {
                    g_app.standaloneSample = result->sample;
                }
                g_app.lastDiffReport.clear();
            }
            appendLogLine(result->info);
            delete result;
        }

        finalizeCaptureThread();
        updateCaptureStatusLabel();
        return 0;
    }
    case WM_CLOSE:
    {
        stopCaptureFromUi(true);
        stopRelayFromUi(true);
        finalizeStoppedUi();
        DestroyWindow(hwnd);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

} // namespace

int NFSLANRelayMain(HINSTANCE instance, int showCommand)
{
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = windowProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kWindowClassName;

    if (!RegisterClassExW(&wc))
    {
        MessageBoxW(nullptr, L"Failed to register window class.", L"NFSLAN Relay", MB_ICONERROR | MB_OK);
        return 1;
    }

    HWND window = CreateWindowExW(
        0,
        kWindowClassName,
        L"NFSLAN Relay",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        980,
        720,
        nullptr,
        nullptr,
        instance,
        nullptr);
    if (!window)
    {
        MessageBoxW(nullptr, L"Failed to create main window.", L"NFSLAN Relay", MB_ICONERROR | MB_OK);
        return 1;
    }

    ShowWindow(window, showCommand);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0))
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return static_cast<int>(message.wParam);
}

#if !defined(NFSLAN_RELAY_NO_MAIN)
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand)
{
    return NFSLANRelayMain(instance, showCommand);
}
#endif
