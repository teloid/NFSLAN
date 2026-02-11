#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <cwctype>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{

constexpr wchar_t kWindowClassName[] = L"NFSLANRelayWindowClass";
constexpr wchar_t kBuildTag[] = L"2026-02-11-relay-ui-1";

constexpr UINT WM_APP_RELAY_LOG = WM_APP + 20;
constexpr UINT WM_APP_RELAY_STATUS = WM_APP + 21;
constexpr UINT WM_APP_RELAY_STOPPED = WM_APP + 22;

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
    kIdLogEdit,
    kIdStatusStatic
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
    HWND logEdit = nullptr;
    HWND statusStatic = nullptr;
    RelayRuntime runtime;
};

AppState g_app;

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
    EnableWindow(g_app.modeCombo, running ? FALSE : TRUE);
    EnableWindow(g_app.listenPortEdit, running ? FALSE : TRUE);
    EnableWindow(g_app.targetPortEdit, running ? FALSE : TRUE);
    EnableWindow(g_app.peersEdit, running ? FALSE : TRUE);
    EnableWindow(g_app.fixedSourceEdit, (!running && currentRelayMode() == RelayMode::FixedSourceSpoof) ? TRUE : FALSE);

    EnableWindow(g_app.startButton, running ? FALSE : TRUE);
    EnableWindow(g_app.stopButton, running ? TRUE : FALSE);
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

        HWND buildTag = createLabel(L"Build: 2026-02-11-relay-ui-1", left, top + 22, 300, 18);
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
            L"- Relay forwards UDP discovery packets to peer list.",
            left,
            top + 568,
            leftWidth,
            72);
        setControlFont(hint);

        createLabel(L"Runtime log", right, top + 22, 200, 18);
        g_app.logEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            right,
            top + 42,
            rightWidth,
            598,
            hwnd,
            reinterpret_cast<HMENU>(kIdLogEdit),
            nullptr,
            nullptr);
        setControlFont(g_app.logEdit);

        appendLogLine(L"NFSLAN Relay UI initialized.");
        appendLogLine(L"Build tag: " + std::wstring(kBuildTag));
        setUiRunningState(false);
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
            stopRelayFromUi(true);
            finalizeStoppedUi();
            appendLogLine(L"Stop requested by user.");
            return 0;
        }
        if (controlId == kIdClearLogButton && code == BN_CLICKED)
        {
            setWindowTextString(g_app.logEdit, L"");
            appendLogLine(L"Log cleared.");
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
    case WM_CLOSE:
    {
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
