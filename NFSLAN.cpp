// NFS LAN server launcher (U2-focused release path)
// by Xan/Tenjoin

#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <regex>
#include <array>
#include <fstream>
#include <sstream>
#include <optional>
#include <exception>
#include <cctype>
#include <cwctype>
#include <limits>
#include <iomanip>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <atomic>
#include <signal.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "injector/injector.hpp"
#include "injector/assembly.hpp"
#include "injector/hooking/Hooking.Patterns.h"
#include "Network.h"
#include <thread>

bool (*StartServer)(char* ServerName, int32_t ForceNameNFSMW, void* Callback, void* CallbackParam);
bool (*IsServerRunning)();
void (*StopServer)();

bool bDisablePatching = false;

uintptr_t who_func = 0x1000AAD0;
uintptr_t packet_buffer = 0x10058A5C;

std::map<uint32_t, uint32_t> RedirIPs;
std::vector<uint32_t> LocalUsers;

uint32_t lobbyClientDestAddr = 0;

namespace
{

struct WorkerLaunchOptions
{
    std::string serverName;
    bool sameMachineMode = false;
    bool localEmulation = false;
    bool lanDiag = false;
    bool ug2BeaconEmulation = false;
    bool beaconOnly = false;
    std::optional<int> u2Mode;
};

struct WorkerResolvedSettings
{
    int u2Mode = 0;
    bool lanDiag = false;
    bool sameMachineMode = false;
    bool localEmulation = false;
    bool ug2BeaconEmulation = false;
    int discoveryPort = 9999;
    std::string discoveryAddr = "127.0.0.1";
    std::string endpointAddr = "127.0.0.1";
    int endpointPort = 9900;
};

constexpr int kDefaultLanDiscoveryPort = 9999;
constexpr const char* kBuildTag = "2026-02-13-worker-mw-caddr-1";
constexpr size_t kUg2LanBeaconLength = 0x180;
constexpr size_t kUg2IdentOffset = 0x08;
constexpr size_t kUg2IdentMax = 0x08;
constexpr size_t kUg2NameOffset = 0x28;
constexpr size_t kUg2NameMax = 0x20;
constexpr size_t kUg2StatsOffset = 0x48;
constexpr size_t kUg2StatsMax = 0xC0;

std::atomic<bool> gLanBridgeRunning{ false };
std::thread gLanBridgeThread;
std::atomic<bool> gUg2BeaconEmuRunning{ false };
std::thread gUg2BeaconEmuThread;
std::atomic<int> gUg2BeaconPort{ 9900 };
std::string gUg2BeaconServerName = "Test Server";
std::string gUg2BeaconLobbyIdent = "NFSU2NA";

using SendToFn = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
SendToFn gOriginalSendTo = nullptr;
std::atomic<bool> gSendToHookInstalled{ false };
std::atomic<bool> gLanDiagEnabled{ false };
std::atomic<int> gLanDiagBeaconLogCount{ 0 };
std::atomic<bool> gSameMachineModeEnabled{ false };
std::atomic<bool> gLocalEmulationEnabled{ false };
std::atomic<int> gLanDiscoveryPort{ kDefaultLanDiscoveryPort };
std::string gLanDiscoveryAddr = "127.0.0.1";
std::atomic<bool> gLoopbackMirrorAnnounced{ false };
HANDLE gServerIdentityMutex = nullptr;
std::wstring gServerIdentityMutexName;

using SendFn = int (WSAAPI*)(SOCKET, const char*, int, int);
SendFn gOriginalSend = nullptr;
std::atomic<bool> gSendHookInstalled{ false };
std::atomic<bool> gMwDirCompatEnabled{ false };
std::string gMwDirCompatAddr = "127.0.0.1";
std::atomic<int> gMwDirCompatPort{ 9900 };
std::atomic<bool> gMwDirCompatAnnounced{ false };

bool LooksLikeUg2LanBeacon(const char* payload, int length);
bool TryParseIpv4Address(const std::string& text, in_addr* addressOut);

std::string TrimAscii(const std::string& input)
{
    const auto first = input.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
    {
        return {};
    }
    const auto last = input.find_last_not_of(" \t\r\n");
    return input.substr(first, (last - first) + 1);
}

bool EqualsIgnoreCase(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
    {
        return false;
    }

    for (size_t i = 0; i < a.size(); ++i)
    {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
        {
            return false;
        }
    }

    return true;
}

bool StartsWithIgnoreCase(const std::string& text, const std::string& prefix)
{
    if (text.size() < prefix.size())
    {
        return false;
    }

    for (size_t i = 0; i < prefix.size(); ++i)
    {
        if (std::tolower(static_cast<unsigned char>(text[i]))
            != std::tolower(static_cast<unsigned char>(prefix[i])))
        {
            return false;
        }
    }

    return true;
}

bool TryParseInt(const std::string& input, int* valueOut)
{
    const std::string trimmed = TrimAscii(input);
    if (trimmed.empty())
    {
        return false;
    }

    char* end = nullptr;
    const long parsed = std::strtol(trimmed.c_str(), &end, 10);
    if (!end || *end != '\0')
    {
        return false;
    }

    if (parsed < static_cast<long>((std::numeric_limits<int>::min)())
        || parsed > static_cast<long>((std::numeric_limits<int>::max)()))
    {
        return false;
    }

    *valueOut = static_cast<int>(parsed);
    return true;
}

bool TryParseIntRange(const std::string& input, int minValue, int maxValue, int* valueOut)
{
    int parsed = 0;
    if (!TryParseInt(input, &parsed))
    {
        return false;
    }

    if (parsed < minValue || parsed > maxValue)
    {
        return false;
    }

    *valueOut = parsed;
    return true;
}

std::wstring AsciiToWide(const std::string& input)
{
    if (input.empty())
    {
        return {};
    }

    std::wstring output;
    output.reserve(input.size());
    for (unsigned char ch : input)
    {
        output.push_back(static_cast<wchar_t>(ch));
    }
    return output;
}

std::wstring NormalizeIdentityTokenForMutex(const std::wstring& input)
{
    std::wstring out;
    out.reserve(input.size());

    for (const wchar_t ch : input)
    {
        if ((ch >= L'0' && ch <= L'9')
            || (ch >= L'A' && ch <= L'Z')
            || (ch >= L'a' && ch <= L'z')
            || ch == L'_' || ch == L'-' || ch == L'.')
        {
            out.push_back(static_cast<wchar_t>(towupper(ch)));
        }
        else
        {
            out.push_back(L'_');
        }
    }

    if (out.empty())
    {
        return L"UNKNOWN";
    }
    return out;
}

std::wstring BuildServerIdentityMutexName(const std::string& lobbyIdent, int port)
{
    return L"Local\\NFSLAN_SERVER_IDENT_"
        + NormalizeIdentityTokenForMutex(AsciiToWide(TrimAscii(lobbyIdent)))
        + L"_"
        + std::to_wstring(port);
}

void ReleaseServerIdentityLock()
{
    if (!gServerIdentityMutex)
    {
        return;
    }

    CloseHandle(gServerIdentityMutex);
    gServerIdentityMutex = nullptr;
    gServerIdentityMutexName.clear();
}

bool AcquireServerIdentityLock(const std::string& lobbyIdent, int port)
{
    ReleaseServerIdentityLock();

    gServerIdentityMutexName = BuildServerIdentityMutexName(lobbyIdent, port);
    HANDLE mutexHandle = CreateMutexW(nullptr, FALSE, gServerIdentityMutexName.c_str());
    if (!mutexHandle)
    {
        std::cerr << "ERROR: Failed to create server identity mutex (Win32 " << GetLastError() << ").\n";
        gServerIdentityMutexName.clear();
        return false;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        std::cerr << "ERROR: Another NFSLAN server instance with identity "
                  << TrimAscii(lobbyIdent) << ":" << port
                  << " is already running on this machine.\n";
        CloseHandle(mutexHandle);
        gServerIdentityMutexName.clear();
        return false;
    }

    gServerIdentityMutex = mutexHandle;
    std::cout << "NFSLAN: Identity lock acquired for " << TrimAscii(lobbyIdent) << ":" << port << ".\n";
    return true;
}

struct ScopedServerIdentityLock
{
    bool armed = false;

    ~ScopedServerIdentityLock()
    {
        if (armed)
        {
            ReleaseServerIdentityLock();
        }
    }
};

bool ParseConfigLine(const std::string& line, std::string* keyOut, std::string* valueOut)
{
    std::string working = line;
    if (!working.empty() && working.back() == '\r')
    {
        working.pop_back();
    }

    const std::string trimmed = TrimAscii(working);
    if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';')
    {
        return false;
    }

    const auto equalsPos = trimmed.find('=');
    if (equalsPos == std::string::npos)
    {
        return false;
    }

    *keyOut = TrimAscii(trimmed.substr(0, equalsPos));
    *valueOut = TrimAscii(trimmed.substr(equalsPos + 1));
    return !keyOut->empty();
}

std::optional<std::string> GetConfigValue(const std::string& configText, const std::string& key)
{
    std::istringstream stream(configText);
    std::string line;
    while (std::getline(stream, line))
    {
        std::string foundKey;
        std::string foundValue;
        if (ParseConfigLine(line, &foundKey, &foundValue) && EqualsIgnoreCase(foundKey, key))
        {
            return foundValue;
        }
    }
    return std::nullopt;
}

std::string UpsertConfigValue(const std::string& configText, const std::string& key, const std::string& value)
{
    std::istringstream stream(configText);
    std::string line;
    std::vector<std::string> lines;
    bool replaced = false;

    while (std::getline(stream, line))
    {
        std::string foundKey;
        std::string foundValue;
        if (ParseConfigLine(line, &foundKey, &foundValue) && EqualsIgnoreCase(foundKey, key))
        {
            lines.push_back(key + "=" + value);
            replaced = true;
        }
        else
        {
            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }
            lines.push_back(line);
        }
    }

    if (!replaced)
    {
        lines.push_back(key + "=" + value);
    }

    std::string output;
    for (size_t i = 0; i < lines.size(); ++i)
    {
        output += lines[i];
        if (i + 1 < lines.size())
        {
            output += "\r\n";
        }
    }

    return output;
}

bool ReadTextFile(const std::filesystem::path& path, std::string* outText)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        return false;
    }

    *outText = std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return true;
}

bool WriteTextFile(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file)
    {
        return false;
    }

    file.write(text.data(), static_cast<std::streamsize>(text.size()));
    return file.good();
}

bool ResolveServerIdentityFromConfig(bool underground2Server, std::string* lobbyIdentOut, int* portOut)
{
    std::string lobbyIdent = underground2Server ? "NFSU2NA" : "NFSMWNA";
    int port = 9900;

    std::string configText;
    if (!ReadTextFile("server.cfg", &configText))
    {
        *lobbyIdentOut = lobbyIdent;
        *portOut = port;
        return true;
    }

    const std::string configuredLobby = TrimAscii(GetConfigValue(configText, "LOBBY_IDENT").value_or(""));
    if (!configuredLobby.empty())
    {
        lobbyIdent = configuredLobby;
    }

    const std::string configuredPort = TrimAscii(GetConfigValue(configText, "PORT").value_or(""));
    int parsedPort = 0;
    if (!configuredPort.empty())
    {
        if (TryParseIntRange(configuredPort, 1, 65535, &parsedPort))
        {
            port = parsedPort;
        }
        else
        {
            std::cout << "NFSLAN: WARNING - invalid PORT='" << configuredPort
                      << "' in server.cfg, using default 9900 for identity lock.\n";
        }
    }

    *lobbyIdentOut = TrimAscii(lobbyIdent);
    *portOut = port;
    return true;
}

bool IsTruthy(const std::string& value)
{
    const std::string normalized = TrimAscii(value);
    return EqualsIgnoreCase(normalized, "1")
        || EqualsIgnoreCase(normalized, "true")
        || EqualsIgnoreCase(normalized, "yes")
        || EqualsIgnoreCase(normalized, "on");
}

std::string EnsureConfigValue(std::string* configText, const std::string& key, const std::string& fallback, bool* changed)
{
    const std::string existing = TrimAscii(GetConfigValue(*configText, key).value_or(""));
    if (!existing.empty())
    {
        return existing;
    }

    *configText = UpsertConfigValue(*configText, key, fallback);
    *changed = true;
    std::cout << "NFSLAN: Added " << key << "=" << fallback << '\n';
    return fallback;
}

void EnsureMirroredKey(std::string* configText, const std::string& key, const std::string& value, bool* changed)
{
    const std::string existing = TrimAscii(GetConfigValue(*configText, key).value_or(""));
    if (!existing.empty())
    {
        return;
    }

    *configText = UpsertConfigValue(*configText, key, value);
    *changed = true;
    std::cout << "NFSLAN: Added " << key << "=" << value << " (derived)\n";
}

void ForceConfigValue(std::string* configText, const std::string& key, const std::string& value, bool* changed)
{
    const std::string existing = TrimAscii(GetConfigValue(*configText, key).value_or(""));
    if (EqualsIgnoreCase(existing, value))
    {
        return;
    }

    *configText = UpsertConfigValue(*configText, key, value);
    *changed = true;
    if (existing.empty())
    {
        std::cout << "NFSLAN: Added " << key << "=" << value << '\n';
    }
    else
    {
        std::cout << "NFSLAN: Updated " << key << "=" << value << " (was " << existing << ")\n";
    }
}

bool IsAsciiPrintable(char c)
{
    const unsigned char u = static_cast<unsigned char>(c);
    return u >= 32 && u <= 126;
}

std::string ReadBeaconStringField(const char* payload, int length, size_t offset, size_t maxLen)
{
    if (!payload || length <= 0 || offset >= static_cast<size_t>(length))
    {
        return {};
    }

    std::string out;
    const size_t safeMaxLen = (std::min)(maxLen, static_cast<size_t>(length) - offset);
    out.reserve(safeMaxLen);

    for (size_t i = 0; i < safeMaxLen; ++i)
    {
        const char ch = payload[offset + i];
        if (ch == '\0')
        {
            break;
        }
        if (!IsAsciiPrintable(ch))
        {
            break;
        }
        out.push_back(ch);
    }

    return out;
}

std::string FindPrintableString(const char* payload, int length, size_t start, size_t end, size_t minLen)
{
    if (!payload || length <= 0 || start >= end)
    {
        return {};
    }

    const size_t maxBound = (std::min)(end, static_cast<size_t>(length));
    for (size_t i = start; i < maxBound; ++i)
    {
        const std::string candidate = ReadBeaconStringField(payload, length, i, maxBound - i);
        if (candidate.size() >= minLen)
        {
            return candidate;
        }
    }

    return {};
}

std::string ExtractUg2BeaconName(const char* payload, int length)
{
    std::string serverName = ReadBeaconStringField(payload, length, kUg2NameOffset, kUg2NameMax);
    if (!serverName.empty())
    {
        return serverName;
    }
    return FindPrintableString(payload, length, 0x20, 0x80, 3);
}

std::string HexPreview(const char* payload, int length, size_t bytesToShow)
{
    if (!payload || length <= 0)
    {
        return {};
    }

    const size_t bytes = (std::min)(static_cast<size_t>(length), bytesToShow);
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes; ++i)
    {
        if (i > 0)
        {
            stream << ' ';
        }
        stream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(payload[i]));
    }
    return stream.str();
}

bool ShouldLogLanDiagSample(std::atomic<int>* counter, int maxSamples)
{
    if (!gLanDiagEnabled.load())
    {
        return false;
    }

    const int sample = counter->fetch_add(1) + 1;
    return sample <= maxSamples;
}

void LogUg2LanBeaconDiag(const char* sourceTag, const char* payload, int length, bool patched)
{
    if (!gLanDiagEnabled.load() || !LooksLikeUg2LanBeacon(payload, length))
    {
        return;
    }

    const std::string ident = ReadBeaconStringField(payload, length, kUg2IdentOffset, kUg2IdentMax);
    const std::string serverName = ExtractUg2BeaconName(payload, length);
    const std::string stats = ReadBeaconStringField(payload, length, kUg2StatsOffset, kUg2StatsMax);
    const std::string preview = HexPreview(payload, length, 64);

    std::cout << "NFSLAN: LAN-DIAG " << sourceTag
              << " ident=" << ident
              << " stats='" << stats << "'"
              << " name='" << serverName << "'"
              << " patched=" << (patched ? "1" : "0")
              << " len=" << length << '\n';
    std::cout << "NFSLAN: LAN-DIAG " << sourceTag << " bytes[0..63]: " << preview << '\n';
}

void WriteAsciiFieldToBuffer(char* buffer, size_t bufferSize, size_t offset, size_t maxFieldLen, const std::string& value)
{
    if (!buffer || bufferSize == 0 || offset >= bufferSize || maxFieldLen == 0)
    {
        return;
    }

    const size_t safeMaxLen = (std::min)(maxFieldLen, bufferSize - offset);
    if (safeMaxLen == 0)
    {
        return;
    }

    const size_t copyLen = (std::min)(value.size(), safeMaxLen - 1);
    if (copyLen > 0)
    {
        std::memcpy(buffer + offset, value.data(), copyLen);
    }
    buffer[offset + copyLen] = '\0';
}

std::array<char, kUg2LanBeaconLength> BuildSyntheticUg2Beacon(const std::string& lobbyIdent, const std::string& serverName, int port)
{
    std::array<char, kUg2LanBeaconLength> packet{};
    packet[0] = 'g';
    packet[1] = 'E';
    packet[2] = 'A';
    packet[3] = 0x03;

    const std::string effectiveLobby = TrimAscii(lobbyIdent).empty() ? "NFSU2NA" : TrimAscii(lobbyIdent);
    const std::string effectiveServerName = TrimAscii(serverName).empty() ? "Test Server" : TrimAscii(serverName);
    const int effectivePort = (std::max)(1, (std::min)(65535, port));
    // Keep stock-like stats for maximum compatibility with UG2 client parsing.
    const std::string stats = std::to_string(effectivePort) + "|0";

    WriteAsciiFieldToBuffer(packet.data(), packet.size(), kUg2IdentOffset, kUg2IdentMax, effectiveLobby);
    WriteAsciiFieldToBuffer(packet.data(), packet.size(), kUg2NameOffset, kUg2NameMax, effectiveServerName);
    WriteAsciiFieldToBuffer(packet.data(), packet.size(), kUg2StatsOffset, kUg2StatsMax, stats);
    WriteAsciiFieldToBuffer(packet.data(), packet.size(), 0x108, 0x40, "TCP:~1:1024\tUDP:~1:1024");

    return packet;
}

void MirrorUg2BeaconToLoopback(SOCKET socketHandle, const char* payload, int length, int flags)
{
    if (!gSameMachineModeEnabled.load() || !gOriginalSendTo || !payload || length <= 0)
    {
        return;
    }

    const int discoveryPort = (std::max)(1, (std::min)(65535, gLanDiscoveryPort.load()));
    const std::string configuredDiscoveryAddr = TrimAscii(gLanDiscoveryAddr);

    bool loggedLoopbackFailure = false;
    bool loggedDiscoveryFailure = false;
    bool mirroredLoopback = false;
    bool mirroredDiscovery = false;

    const auto mirrorTo = [&](const sockaddr_in& target, const char* tag, bool* loggedFailure) -> bool
    {
        const int mirrorResult = gOriginalSendTo(
            socketHandle,
            payload,
            length,
            flags,
            reinterpret_cast<const sockaddr*>(&target),
            sizeof(target));
        if (mirrorResult < 0)
        {
            if (gLanDiagEnabled.load() && loggedFailure && !(*loggedFailure))
            {
                *loggedFailure = true;
                std::cerr << "NFSLAN: LAN-DIAG " << tag << " mirror failed (WSA error "
                          << WSAGetLastError() << ").\n";
            }
            return false;
        }

        if (ShouldLogLanDiagSample(&gLanDiagBeaconLogCount, 6))
        {
            LogUg2LanBeaconDiag(tag, payload, length, true);
        }
        return true;
    };

    sockaddr_in loopbackAddr{};
    loopbackAddr.sin_family = AF_INET;
    loopbackAddr.sin_port = htons(static_cast<u_short>(discoveryPort));
    loopbackAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    mirroredLoopback = mirrorTo(loopbackAddr, "hook-mirror-loopback", &loggedLoopbackFailure);

    in_addr discoveryAddr{};
    if (TryParseIpv4Address(configuredDiscoveryAddr, &discoveryAddr)
        && discoveryAddr.s_addr != htonl(INADDR_LOOPBACK))
    {
        sockaddr_in directAddr{};
        directAddr.sin_family = AF_INET;
        directAddr.sin_port = htons(static_cast<u_short>(discoveryPort));
        directAddr.sin_addr = discoveryAddr;
        mirroredDiscovery = mirrorTo(directAddr, "hook-mirror-discovery", &loggedDiscoveryFailure);
    }

    if (!mirroredLoopback && !mirroredDiscovery)
    {
        return;
    }

    if (!gLoopbackMirrorAnnounced.exchange(true))
    {
        std::cout << "NFSLAN: Same-machine UG2 beacon mirror active on 127.0.0.1:"
                  << discoveryPort;
        if (mirroredDiscovery && !configuredDiscoveryAddr.empty())
        {
            std::cout << " and " << configuredDiscoveryAddr << ":" << discoveryPort;
        }
        std::cout << ".\n";
    }
}

bool LooksLikeUg2LanBeacon(const char* payload, int length)
{
    if (!payload || static_cast<size_t>(length) != kUg2LanBeaconLength)
    {
        return false;
    }

    if (!(payload[0] == 'g' && payload[1] == 'E' && payload[2] == 'A'))
    {
        return false;
    }

    if (static_cast<unsigned char>(payload[3]) != 0x03)
    {
        return false;
    }

    return std::memcmp(payload + kUg2IdentOffset, "NFSU", 4) == 0;
}

bool ContainsSubstringIgnoreCase(const char* data, int dataLen, const char* needle)
{
    if (!data || dataLen <= 0 || !needle)
    {
        return false;
    }
    const size_t needleLen = std::strlen(needle);
    if (needleLen == 0 || needleLen > static_cast<size_t>(dataLen))
    {
        return false;
    }

    for (int i = 0; i + static_cast<int>(needleLen) <= dataLen; ++i)
    {
        bool match = true;
        for (size_t j = 0; j < needleLen; ++j)
        {
            const unsigned char a = static_cast<unsigned char>(data[i + static_cast<int>(j)]);
            const unsigned char b = static_cast<unsigned char>(needle[j]);
            if (std::tolower(a) != std::tolower(b))
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            return true;
        }
    }
    return false;
}

int WSAAPI HookedSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    if (!gOriginalSendTo)
    {
        return SOCKET_ERROR;
    }

    if (LooksLikeUg2LanBeacon(buf, len))
    {
        const bool logOriginalSample = ShouldLogLanDiagSample(&gLanDiagBeaconLogCount, 8);
        if (logOriginalSample)
        {
            LogUg2LanBeaconDiag("hook-send-original", buf, len, false);
        }
        MirrorUg2BeaconToLoopback(s, buf, len, flags);
    }

    return gOriginalSendTo(s, buf, len, flags, to, tolen);
}

bool InstallSendToHook(HMODULE moduleHandle)
{
    if (!moduleHandle || gSendToHookInstalled.load())
    {
        return true;
    }

    const auto base = reinterpret_cast<std::uint8_t*>(moduleHandle);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "NFSLAN: WARNING - cannot install sendto hook: invalid DOS header.\n";
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "NFSLAN: WARNING - cannot install sendto hook: invalid NT header.\n";
        return false;
    }

    const IMAGE_DATA_DIRECTORY importDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0)
    {
        std::cerr << "NFSLAN: WARNING - cannot install sendto hook: import table missing.\n";
        return false;
    }

    const auto patchThunk = [&](IMAGE_THUNK_DATA* thunk, const char* sourceTag) -> bool
    {
        if (thunk->u1.Function == reinterpret_cast<ULONG_PTR>(&HookedSendTo))
        {
            gSendToHookInstalled.store(true);
            std::cout << "NFSLAN: UG2 sendto hook already installed (" << sourceTag << ").\n";
            return true;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), PAGE_READWRITE, &oldProtect))
        {
            std::cerr << "NFSLAN: WARNING - cannot install sendto hook: VirtualProtect failed.\n";
            return false;
        }

        gOriginalSendTo = reinterpret_cast<SendToFn>(thunk->u1.Function);
        thunk->u1.Function = reinterpret_cast<ULONG_PTR>(&HookedSendTo);

        DWORD restoreProtect = 0;
        VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), oldProtect, &restoreProtect);
        FlushInstructionCache(GetCurrentProcess(), &thunk->u1.Function, sizeof(thunk->u1.Function));

        gSendToHookInstalled.store(true);
        std::cout << "NFSLAN: Installed UG2 sendto mirror hook (" << sourceTag << ").\n";
        return true;
    };

    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor)
    {
        const auto* dllName = reinterpret_cast<const char*>(base + descriptor->Name);
        if (!dllName
            || (!EqualsIgnoreCase(dllName, "ws2_32.dll") && !EqualsIgnoreCase(dllName, "wsock32.dll")))
        {
            continue;
        }

        if (descriptor->OriginalFirstThunk == 0)
        {
            // Bound imports may not preserve name table; pointer-match fallback below handles this case.
            continue;
        }

        auto* originalThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->OriginalFirstThunk);
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);

        for (; originalThunk->u1.AddressOfData != 0; ++originalThunk, ++thunk)
        {
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
            {
                continue;
            }

            const auto* importByName =
                reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + originalThunk->u1.AddressOfData);
            const char* functionName = reinterpret_cast<const char*>(importByName->Name);
            if (!functionName)
            {
                continue;
            }

            const std::string fn(functionName);
            if (!(EqualsIgnoreCase(fn, "sendto")
                || EqualsIgnoreCase(fn, "_sendto@24")
                || EqualsIgnoreCase(fn, "__imp_sendto")))
            {
                continue;
            }

            return patchThunk(thunk, "named import");
        }
    }

    FARPROC ws2SendTo = nullptr;
    if (HMODULE ws2 = GetModuleHandleA("ws2_32.dll"))
    {
        ws2SendTo = GetProcAddress(ws2, "sendto");
    }
    else if (HMODULE ws2Loaded = LoadLibraryA("ws2_32.dll"))
    {
        ws2SendTo = GetProcAddress(ws2Loaded, "sendto");
    }

    FARPROC wsockSendTo = nullptr;
    if (HMODULE wsock = GetModuleHandleA("wsock32.dll"))
    {
        wsockSendTo = GetProcAddress(wsock, "sendto");
    }

    if (!ws2SendTo && !wsockSendTo)
    {
        std::cerr << "NFSLAN: WARNING - could not resolve sendto in ws2_32/wsock32.\n";
        return false;
    }

    descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor)
    {
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);
        for (; thunk->u1.Function != 0; ++thunk)
        {
            const ULONG_PTR fn = thunk->u1.Function;
            if ((ws2SendTo && fn == reinterpret_cast<ULONG_PTR>(ws2SendTo))
                || (wsockSendTo && fn == reinterpret_cast<ULONG_PTR>(wsockSendTo)))
            {
                return patchThunk(thunk, "pointer match import");
            }
        }
    }

    std::cerr << "NFSLAN: WARNING - could not find sendto import thunk to hook.\n";
    return false;
}

int WSAAPI HookedSend(SOCKET s, const char* buf, int len, int flags)
{
    if (!gOriginalSend)
    {
        return SOCKET_ERROR;
    }

    if (!buf || len < 12 || len > 0xFF || !gMwDirCompatEnabled.load())
    {
        return gOriginalSend(s, buf, len, flags);
    }

    // Titan-style messages use a 12-byte header: "@cmd" + 7x 0x00 + 1-byte total length.
    if (buf[0] != '@' || buf[11] != static_cast<char>(len))
    {
        return gOriginalSend(s, buf, len, flags);
    }

    const bool isDir = (buf[1] == 'd' && buf[2] == 'i' && buf[3] == 'r');
    if (!isDir)
    {
        return gOriginalSend(s, buf, len, flags);
    }

    const char* body = buf + 12;
    const int bodyLen = len - 12;
    const bool hasLadr = ContainsSubstringIgnoreCase(body, bodyLen, "ladr=");
    const bool hasLprt = ContainsSubstringIgnoreCase(body, bodyLen, "lprt=");
    const bool hasIdown = ContainsSubstringIgnoreCase(body, bodyLen, "IDOWN=");

    if (hasIdown || !hasLadr || !hasLprt)
    {
        const std::string addr = TrimAscii(gMwDirCompatAddr);
        const int port = gMwDirCompatPort.load();
        if (!addr.empty() && port > 0 && port <= 65535)
        {
            // Minimal directory response to keep MW clients from treating the server as "down".
            // Most Wanted client expects at least ladr/lprt to be present.
            std::string patchedBody;
            patchedBody.reserve(96);
            patchedBody += "ladr=";
            patchedBody += addr;
            patchedBody += "\n";
            patchedBody += "lprt=";
            patchedBody += std::to_string(port);
            patchedBody += "\n";

            const int totalLen = 12 + static_cast<int>(patchedBody.size()) + 1; // include trailing NUL
            if (totalLen <= 0xFF)
            {
                std::array<char, 0x100> out{};
                out[0] = '@';
                out[1] = 'd';
                out[2] = 'i';
                out[3] = 'r';
                // out[4..10] are already 0.
                out[11] = static_cast<char>(totalLen);
                std::memcpy(out.data() + 12, patchedBody.data(), patchedBody.size());
                out[12 + patchedBody.size()] = '\0';

                if (!gMwDirCompatAnnounced.exchange(true))
                {
                    std::cout << "NFSLAN: Installed MW @dir compatibility response (forcing ladr/lprt to "
                              << addr << ":" << port << ").\n";
                }

                if (gLanDiagEnabled.load())
                {
                    std::cout << "NFSLAN: LAN-DIAG MW @dir patched (len=" << totalLen
                              << ", hadIdown=" << (hasIdown ? 1 : 0)
                              << ", hadLadr=" << (hasLadr ? 1 : 0)
                              << ", hadLprt=" << (hasLprt ? 1 : 0) << ").\n";
                }

                return gOriginalSend(s, out.data(), totalLen, flags);
            }
        }
    }

    return gOriginalSend(s, buf, len, flags);
}

bool InstallSendHook(HMODULE moduleHandle)
{
    if (!moduleHandle || gSendHookInstalled.load())
    {
        return true;
    }

    const auto base = reinterpret_cast<std::uint8_t*>(moduleHandle);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "NFSLAN: WARNING - cannot install send hook: invalid DOS header.\n";
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "NFSLAN: WARNING - cannot install send hook: invalid NT header.\n";
        return false;
    }

    const IMAGE_DATA_DIRECTORY importDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0)
    {
        std::cerr << "NFSLAN: WARNING - cannot install send hook: import table missing.\n";
        return false;
    }

    const auto patchThunk = [&](IMAGE_THUNK_DATA* thunk, const char* sourceTag) -> bool
    {
        if (thunk->u1.Function == reinterpret_cast<ULONG_PTR>(&HookedSend))
        {
            gSendHookInstalled.store(true);
            std::cout << "NFSLAN: send hook already installed (" << sourceTag << ").\n";
            return true;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), PAGE_READWRITE, &oldProtect))
        {
            std::cerr << "NFSLAN: WARNING - cannot install send hook: VirtualProtect failed.\n";
            return false;
        }

        gOriginalSend = reinterpret_cast<SendFn>(thunk->u1.Function);
        thunk->u1.Function = reinterpret_cast<ULONG_PTR>(&HookedSend);

        DWORD restoreProtect = 0;
        VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), oldProtect, &restoreProtect);
        FlushInstructionCache(GetCurrentProcess(), &thunk->u1.Function, sizeof(thunk->u1.Function));

        gSendHookInstalled.store(true);
        std::cout << "NFSLAN: Installed send hook (" << sourceTag << ").\n";
        return true;
    };

    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor)
    {
        const auto* dllName = reinterpret_cast<const char*>(base + descriptor->Name);
        if (!dllName
            || (!EqualsIgnoreCase(dllName, "ws2_32.dll") && !EqualsIgnoreCase(dllName, "wsock32.dll")))
        {
            continue;
        }

        if (descriptor->OriginalFirstThunk == 0)
        {
            continue;
        }

        auto* originalThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->OriginalFirstThunk);
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);

        for (; originalThunk->u1.AddressOfData != 0; ++originalThunk, ++thunk)
        {
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
            {
                continue;
            }

            const auto* importByName =
                reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + originalThunk->u1.AddressOfData);
            const char* functionName = reinterpret_cast<const char*>(importByName->Name);
            if (!functionName)
            {
                continue;
            }

            const std::string fn(functionName);
            if (!(EqualsIgnoreCase(fn, "send")
                || EqualsIgnoreCase(fn, "_send@16")
                || EqualsIgnoreCase(fn, "__imp_send")))
            {
                continue;
            }

            return patchThunk(thunk, "named import");
        }
    }

    FARPROC ws2Send = nullptr;
    if (HMODULE ws2 = GetModuleHandleA("ws2_32.dll"))
    {
        ws2Send = GetProcAddress(ws2, "send");
    }
    else if (HMODULE ws2Loaded = LoadLibraryA("ws2_32.dll"))
    {
        ws2Send = GetProcAddress(ws2Loaded, "send");
    }

    FARPROC wsockSend = nullptr;
    if (HMODULE wsock = GetModuleHandleA("wsock32.dll"))
    {
        wsockSend = GetProcAddress(wsock, "send");
    }

    if (!ws2Send && !wsockSend)
    {
        std::cerr << "NFSLAN: WARNING - could not resolve send in ws2_32/wsock32.\n";
        return false;
    }

    descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor)
    {
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);
        for (; thunk->u1.Function != 0; ++thunk)
        {
            const ULONG_PTR fn = thunk->u1.Function;
            if ((ws2Send && fn == reinterpret_cast<ULONG_PTR>(ws2Send))
                || (wsockSend && fn == reinterpret_cast<ULONG_PTR>(wsockSend)))
            {
                return patchThunk(thunk, "pointer match import");
            }
        }
    }

    std::cerr << "NFSLAN: WARNING - could not find send import thunk to hook.\n";
    return false;
}

bool IsLanDiscoveryPacket(const char* data, int length)
{
    return data && length >= 9 && data[0] == 'g' && data[1] == 'E' && data[2] == 'A';
}

std::array<char, kUg2LanBeaconLength> BuildLanDiscoveryQueryPacket()
{
    std::array<char, kUg2LanBeaconLength> packet{};
    packet[0] = 'g';
    packet[1] = 'E';
    packet[2] = 'A';
    packet[8] = '?';
    return packet;
}

bool TryParseIpv4Address(const std::string& text, in_addr* addressOut)
{
    if (!addressOut)
    {
        return false;
    }

    const std::string trimmed = TrimAscii(text);
    if (trimmed.empty())
    {
        return false;
    }

    in_addr parsed{};
    if (InetPtonA(AF_INET, trimmed.c_str(), &parsed) != 1)
    {
        return false;
    }

    if (parsed.s_addr == htonl(INADDR_ANY))
    {
        return false;
    }

    *addressOut = parsed;
    return true;
}

void RunLanDiscoveryLoopbackBridge()
{
    try
    {
        WSASession wsaSession;

        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET)
        {
            const int err = WSAGetLastError();
            std::cerr << "NFSLAN: WARNING - LAN bridge socket creation failed (WSA error " << err << ").\n";
            return;
        }

        DWORD recvTimeoutMs = 250;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recvTimeoutMs), sizeof(recvTimeoutMs));
        int allowBroadcast = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&allowBroadcast), sizeof(allowBroadcast));

        const int discoveryPort = (std::max)(1, (std::min)(65535, gLanDiscoveryPort.load()));
        const std::string configuredDiscoveryAddr = TrimAscii(gLanDiscoveryAddr);
        in_addr parsedDiscoveryAddr{};
        bool discoveryAddrFallback = false;
        if (!TryParseIpv4Address(configuredDiscoveryAddr, &parsedDiscoveryAddr))
        {
            parsedDiscoveryAddr.s_addr = htonl(INADDR_LOOPBACK);
            discoveryAddrFallback = !configuredDiscoveryAddr.empty();
        }

        const std::string effectiveDiscoveryAddr =
            discoveryAddrFallback ? "127.0.0.1" : (configuredDiscoveryAddr.empty() ? "127.0.0.1" : configuredDiscoveryAddr);

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(static_cast<u_short>(discoveryPort));
        serverAddr.sin_addr = parsedDiscoveryAddr;

        sockaddr_in loopbackServerAddr{};
        loopbackServerAddr.sin_family = AF_INET;
        loopbackServerAddr.sin_port = htons(static_cast<u_short>(discoveryPort));
        loopbackServerAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        const bool probeLoopbackAlso =
            gLocalEmulationEnabled.load() && !EqualsIgnoreCase(effectiveDiscoveryAddr, "127.0.0.1");

        sockaddr_in localClientAddr{};
        localClientAddr.sin_family = AF_INET;
        localClientAddr.sin_port = htons(static_cast<u_short>(discoveryPort));
        localClientAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        sockaddr_in broadcastClientAddr{};
        broadcastClientAddr.sin_family = AF_INET;
        broadcastClientAddr.sin_port = htons(static_cast<u_short>(discoveryPort));
        broadcastClientAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

        const auto queryPacket = BuildLanDiscoveryQueryPacket();
        bool loggedFirstResponse = false;
        bool loggedSendError = false;
        bool loggedBroadcastError = false;
        int silentCycles = 0;

        if (discoveryAddrFallback)
        {
            std::cout << "NFSLAN: WARNING - invalid DISCOVERY_ADDR='" << configuredDiscoveryAddr
                      << "', falling back to 127.0.0.1 for local emulation probe.\n";
        }

        std::cout << "NFSLAN: LAN bridge probe target " << effectiveDiscoveryAddr
                  << ":" << discoveryPort << ".\n";

        if (gLanDiagEnabled.load())
        {
            std::cout << "NFSLAN: LAN-DIAG bridge probe enabled on UDP " << discoveryPort << ".\n";
        }

        while (gLanBridgeRunning.load())
        {
            const int sentPrimary = sendto(
                sock,
                queryPacket.data(),
                static_cast<int>(queryPacket.size()),
                0,
                reinterpret_cast<sockaddr*>(&serverAddr),
                sizeof(serverAddr));

            int sentLoopback = 0;
            if (probeLoopbackAlso)
            {
                sentLoopback = sendto(
                    sock,
                    queryPacket.data(),
                    static_cast<int>(queryPacket.size()),
                    0,
                    reinterpret_cast<sockaddr*>(&loopbackServerAddr),
                    sizeof(loopbackServerAddr));
            }

            if (sentPrimary < 0 && (!probeLoopbackAlso || sentLoopback < 0))
            {
                if (!loggedSendError)
                {
                    loggedSendError = true;
                    std::cerr << "NFSLAN: WARNING - LAN bridge probe send failed (WSA error "
                              << WSAGetLastError() << ").\n";
                }
                ++silentCycles;
                Sleep(1000);
                continue;
            }

            loggedSendError = false;
            bool forwardedAny = false;
            for (int i = 0; i < 8; ++i)
            {
                std::array<char, kUg2LanBeaconLength> response{};
                sockaddr_in from{};
                int fromLen = sizeof(from);
                const int received = recvfrom(
                    sock,
                    response.data(),
                    static_cast<int>(response.size()),
                    0,
                    reinterpret_cast<sockaddr*>(&from),
                    &fromLen);

                if (received <= 0)
                {
                    break;
                }

                if (!IsLanDiscoveryPacket(response.data(), received))
                {
                    continue;
                }

                if (response[8] == '?')
                {
                    continue;
                }

                if (ShouldLogLanDiagSample(&gLanDiagBeaconLogCount, 60))
                {
                    LogUg2LanBeaconDiag("bridge-forward", response.data(), received, false);
                }

                forwardedAny = true;
                sendto(
                    sock,
                    response.data(),
                    received,
                    0,
                    reinterpret_cast<sockaddr*>(&localClientAddr),
                    sizeof(localClientAddr));
                const int rebroadcast = sendto(
                    sock,
                    response.data(),
                    received,
                    0,
                    reinterpret_cast<sockaddr*>(&broadcastClientAddr),
                    sizeof(broadcastClientAddr));
                if (rebroadcast < 0 && !loggedBroadcastError)
                {
                    loggedBroadcastError = true;
                    std::cerr << "NFSLAN: WARNING - LAN bridge rebroadcast failed (WSA error " << WSAGetLastError() << ").\n";
                }

                if (!loggedFirstResponse)
                {
                    loggedFirstResponse = true;
                    std::cout << "NFSLAN: Same-machine LAN bridge active on UDP " << discoveryPort << ".\n";
                }
            }

            if (forwardedAny)
            {
                silentCycles = 0;
            }
            else
            {
                ++silentCycles;
                if (silentCycles == 5)
                {
                    std::cout << "NFSLAN: WARNING - no LAN discovery replies seen on emulation probe yet.\n";
                }
            }

            Sleep(1000);
        }

        closesocket(sock);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "NFSLAN: WARNING - LAN bridge failed: " << ex.what() << '\n';
    }
}

void StartLanDiscoveryLoopbackBridge(bool enabled)
{
    if (!enabled || gLanBridgeRunning.load())
    {
        return;
    }

    gLanBridgeRunning.store(true);
    try
    {
        gLanBridgeThread = std::thread(RunLanDiscoveryLoopbackBridge);
    }
    catch (const std::exception& ex)
    {
        gLanBridgeRunning.store(false);
        std::cerr << "NFSLAN: WARNING - failed to start LAN bridge thread: " << ex.what() << '\n';
    }
}

void StopLanDiscoveryLoopbackBridge()
{
    if (!gLanBridgeRunning.load())
    {
        return;
    }

    gLanBridgeRunning.store(false);
    if (gLanBridgeThread.joinable())
    {
        gLanBridgeThread.join();
    }
}

void RunUg2BeaconEmulator()
{
    try
    {
        WSASession wsaSession;
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET)
        {
            const int err = WSAGetLastError();
            std::cerr << "NFSLAN: WARNING - UG2 beacon emulator socket creation failed (WSA error " << err << ").\n";
            return;
        }

        int allowBroadcast = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&allowBroadcast), sizeof(allowBroadcast));
        int reuseAddress = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuseAddress), sizeof(reuseAddress));
        DWORD recvTimeoutMs = 120;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recvTimeoutMs), sizeof(recvTimeoutMs));

        bool boundTo9999 = false;
        sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_port = htons(static_cast<u_short>(kDefaultLanDiscoveryPort));
        bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(sock, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) == 0)
        {
            boundTo9999 = true;
            std::cout << "NFSLAN: UG2 beacon emulator bound source UDP 9999.\n";
        }
        else
        {
            const int err = WSAGetLastError();
            std::cout << "NFSLAN: WARNING - UG2 beacon emulator could not bind source UDP 9999 (WSA error "
                      << err << "); using ephemeral source port.\n";
        }

        const int discoveryPort = (std::max)(1, (std::min)(65535, gLanDiscoveryPort.load()));
        const std::string discoveryAddrText = TrimAscii(gLanDiscoveryAddr);
        in_addr discoveryAddr{};
        const bool hasDiscoveryAddr = TryParseIpv4Address(discoveryAddrText, &discoveryAddr);

        auto sendBeaconTo = [&](const std::array<char, kUg2LanBeaconLength>& packet, const sockaddr_in& target) -> bool
        {
            const int result = sendto(
                sock,
                packet.data(),
                static_cast<int>(packet.size()),
                0,
                reinterpret_cast<const sockaddr*>(&target),
                sizeof(target));
            return result == static_cast<int>(packet.size());
        };

        std::cout << "NFSLAN: UG2 beacon emulator active on UDP " << kDefaultLanDiscoveryPort
                  << " (discovery endpoint " << (hasDiscoveryAddr ? discoveryAddrText : std::string("127.0.0.1"))
                  << ":" << discoveryPort << ").\n";
        if (boundTo9999)
        {
            std::cout << "NFSLAN: UG2 beacon emulator sends with source port 9999.\n";
        }

        bool loggedFirstQuery = false;
        while (gUg2BeaconEmuRunning.load())
        {
            const auto packet = BuildSyntheticUg2Beacon(
                gUg2BeaconLobbyIdent,
                gUg2BeaconServerName,
                gUg2BeaconPort.load());

            sockaddr_in loopback9999{};
            loopback9999.sin_family = AF_INET;
            loopback9999.sin_port = htons(static_cast<u_short>(kDefaultLanDiscoveryPort));
            loopback9999.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

            sockaddr_in broadcast9999{};
            broadcast9999.sin_family = AF_INET;
            broadcast9999.sin_port = htons(static_cast<u_short>(kDefaultLanDiscoveryPort));
            broadcast9999.sin_addr.s_addr = htonl(INADDR_BROADCAST);

            const bool loopbackSent = sendBeaconTo(packet, loopback9999);
            const bool broadcastSent = sendBeaconTo(packet, broadcast9999);

            bool discoverySent = false;
            if (hasDiscoveryAddr)
            {
                sockaddr_in discoveryTarget{};
                discoveryTarget.sin_family = AF_INET;
                discoveryTarget.sin_port = htons(static_cast<u_short>(discoveryPort));
                discoveryTarget.sin_addr = discoveryAddr;
                discoverySent = sendBeaconTo(packet, discoveryTarget);

                if (discoveryTarget.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
                {
                    sockaddr_in loopbackDiscovery{};
                    loopbackDiscovery.sin_family = AF_INET;
                    loopbackDiscovery.sin_port = htons(static_cast<u_short>(discoveryPort));
                    loopbackDiscovery.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                    sendBeaconTo(packet, loopbackDiscovery);
                }
            }

            if (gLanDiagEnabled.load() && ShouldLogLanDiagSample(&gLanDiagBeaconLogCount, 120))
            {
                LogUg2LanBeaconDiag("beacon-emu-send", packet.data(), static_cast<int>(packet.size()), false);
            }

            if (!loopbackSent && !broadcastSent && !discoverySent)
            {
                std::cerr << "NFSLAN: WARNING - UG2 beacon emulator send failed (WSA error "
                          << WSAGetLastError() << ").\n";
            }

            // Query-response path: reply directly when a LAN discovery probe arrives.
            for (int i = 0; i < 6 && gUg2BeaconEmuRunning.load(); ++i)
            {
                std::array<char, kUg2LanBeaconLength> incoming{};
                sockaddr_in from{};
                int fromLen = sizeof(from);
                const int received = recvfrom(
                    sock,
                    incoming.data(),
                    static_cast<int>(incoming.size()),
                    0,
                    reinterpret_cast<sockaddr*>(&from),
                    &fromLen);

                if (received <= 0)
                {
                    break;
                }

                if (!IsLanDiscoveryPacket(incoming.data(), received))
                {
                    continue;
                }

                // Typical UG2 search probe has '?' at byte 8.
                if (incoming[8] != '?')
                {
                    continue;
                }

                if (!loggedFirstQuery)
                {
                    loggedFirstQuery = true;
                    const char* fromIp = inet_ntoa(from.sin_addr);
                    std::cout << "NFSLAN: UG2 beacon emulator received LAN query from "
                              << (fromIp ? fromIp : "unknown")
                              << ":" << ntohs(from.sin_port) << ".\n";
                }

                const int replied = sendto(
                    sock,
                    packet.data(),
                    static_cast<int>(packet.size()),
                    0,
                    reinterpret_cast<const sockaddr*>(&from),
                    sizeof(from));
                if (replied < 0)
                {
                    std::cerr << "NFSLAN: WARNING - UG2 beacon emulator direct query reply failed (WSA error "
                              << WSAGetLastError() << ").\n";
                }
                else if (gLanDiagEnabled.load() && ShouldLogLanDiagSample(&gLanDiagBeaconLogCount, 120))
                {
                    LogUg2LanBeaconDiag("beacon-emu-query-reply", packet.data(), static_cast<int>(packet.size()), false);
                }
            }

            Sleep(1000);
        }

        closesocket(sock);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "NFSLAN: WARNING - UG2 beacon emulator failed: " << ex.what() << '\n';
    }
}

void StartUg2BeaconEmulator(bool enabled, const std::string& lobbyIdent, const std::string& serverName, int port)
{
    if (!enabled || gUg2BeaconEmuRunning.load())
    {
        return;
    }

    gUg2BeaconLobbyIdent = TrimAscii(lobbyIdent).empty() ? "NFSU2NA" : TrimAscii(lobbyIdent);
    gUg2BeaconServerName = TrimAscii(serverName).empty() ? "Test Server" : TrimAscii(serverName);
    gUg2BeaconPort.store((std::max)(1, (std::min)(65535, port)));

    gUg2BeaconEmuRunning.store(true);
    try
    {
        gUg2BeaconEmuThread = std::thread(RunUg2BeaconEmulator);
    }
    catch (const std::exception& ex)
    {
        gUg2BeaconEmuRunning.store(false);
        std::cerr << "NFSLAN: WARNING - failed to start UG2 beacon emulator thread: " << ex.what() << '\n';
    }
}

void StopUg2BeaconEmulator()
{
    if (!gUg2BeaconEmuRunning.load())
    {
        return;
    }

    gUg2BeaconEmuRunning.store(false);
    if (gUg2BeaconEmuThread.joinable())
    {
        gUg2BeaconEmuThread.join();
    }
}

void LogLanDiscoveryPortDiagnostic(int discoveryPort)
{
    try
    {
        const int diagnosticPort = (std::max)(1, (std::min)(65535, discoveryPort));
        WSASession wsaSession;
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET)
        {
            std::cout << "NFSLAN: WARNING - UDP " << diagnosticPort
                      << " diagnostic socket creation failed (WSA error "
                      << WSAGetLastError() << ").\n";
            return;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<u_short>(diagnosticPort));
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        const int bindResult = bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (bindResult == 0)
        {
            std::cout << "NFSLAN: UDP " << diagnosticPort
                      << " appears free for local client discovery bind.\n";
        }
        else
        {
            const int err = WSAGetLastError();
            if (err == WSAEADDRINUSE)
            {
                std::cout << "NFSLAN: UDP " << diagnosticPort
                          << " is already in use (expected when server discovery socket is active).\n";
            }
            else
            {
                std::cout << "NFSLAN: UDP " << diagnosticPort
                          << " diagnostic bind failed (WSA error " << err << ").\n";
            }
        }

        closesocket(sock);
    }
    catch (const std::exception& ex)
    {
        std::cout << "NFSLAN: WARNING - UDP discovery diagnostic failed: " << ex.what() << '\n';
    }
}

bool ParseIpv4(const std::string& input, uint8_t* octets)
{
    unsigned int a = 0;
    unsigned int b = 0;
    unsigned int c = 0;
    unsigned int d = 0;
    char tail = '\0';

    if (std::sscanf(input.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4)
    {
        return false;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255)
    {
        return false;
    }

    octets[0] = static_cast<uint8_t>(a);
    octets[1] = static_cast<uint8_t>(b);
    octets[2] = static_cast<uint8_t>(c);
    octets[3] = static_cast<uint8_t>(d);
    return true;
}

bool LooksPrivateOrNonRoutableIpv4(const std::string& value);

std::optional<std::string> DetectPreferredLocalLanIpv4()
{
    std::optional<std::string> fallback;
    try
    {
        WSASession wsaSession;

        auto considerCandidate = [&](const in_addr& address) -> std::optional<std::string>
        {
            const char* text = inet_ntoa(address);
            if (!text)
            {
                return std::nullopt;
            }

            const std::string candidate = TrimAscii(text);
            uint8_t octets[4] = {};
            if (!ParseIpv4(candidate, octets))
            {
                return std::nullopt;
            }

            if (octets[0] == 127 || octets[0] == 0)
            {
                return std::nullopt;
            }

            if (LooksPrivateOrNonRoutableIpv4(candidate))
            {
                return candidate;
            }

            if (!fallback.has_value())
            {
                fallback = candidate;
            }
            return std::nullopt;
        };

        // Route-based probe: picks the IPv4 address that Windows would use externally.
        SOCKET probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (probe != INVALID_SOCKET)
        {
            sockaddr_in remote{};
            remote.sin_family = AF_INET;
            remote.sin_port = htons(53);
            if (InetPtonA(AF_INET, "8.8.8.8", &remote.sin_addr) == 1
                && connect(probe, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) == 0)
            {
                sockaddr_in local{};
                int localLen = static_cast<int>(sizeof(local));
                if (getsockname(probe, reinterpret_cast<sockaddr*>(&local), &localLen) == 0)
                {
                    if (const auto preferred = considerCandidate(local.sin_addr))
                    {
                        closesocket(probe);
                        return preferred;
                    }
                }
            }
            closesocket(probe);
        }

        // Fallback: enumerate host IPv4 addresses via DNS APIs.
        char hostName[256] = {};
        if (gethostname(hostName, static_cast<int>(sizeof(hostName))) == 0)
        {
            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;

            addrinfo* results = nullptr;
            if (getaddrinfo(hostName, nullptr, &hints, &results) == 0 && results != nullptr)
            {
                for (addrinfo* entry = results; entry != nullptr; entry = entry->ai_next)
                {
                    if (!entry->ai_addr || entry->ai_addrlen < static_cast<int>(sizeof(sockaddr_in)))
                    {
                        continue;
                    }
                    const auto* in = reinterpret_cast<const sockaddr_in*>(entry->ai_addr);
                    if (const auto preferred = considerCandidate(in->sin_addr))
                    {
                        freeaddrinfo(results);
                        return preferred;
                    }
                }
                freeaddrinfo(results);
            }
        }
    }
    catch (...)
    {
        // Keep fallback behavior when Winsock bootstrap fails in restrictive environments.
    }

    return fallback;
}

bool LooksPrivateOrNonRoutableIpv4(const std::string& value)
{
    uint8_t octets[4] = {};
    if (!ParseIpv4(TrimAscii(value), octets))
    {
        return false;
    }

    const uint8_t a = octets[0];
    const uint8_t b = octets[1];

    if (a == 10 || a == 127 || a == 0)
    {
        return true;
    }
    if (a == 169 && b == 254)
    {
        return true;
    }
    if (a == 172 && b >= 16 && b <= 31)
    {
        return true;
    }
    if (a == 192 && b == 168)
    {
        return true;
    }
    return false;
}

void PrintUsage()
{
    std::cout
        << "USAGE: NFSLAN servername [options]\n"
        << "  --same-machine  Force same-PC host mode (sets FORCE_LOCAL and addr fixups)\n"
        << "  --local-host    Alias for --same-machine\n"
        << "  --local-emulation  Enable discovery emulation bridge in worker\n"
        << "  --ug2-beacon-emu  Enable synthetic UG2 LAN beacon broadcaster\n"
        << "  --beacon-only   Run synthetic UG2 beacon broadcaster without loading server.dll\n"
        << "  --u2-mode N     Underground 2 StartServer mode (0..13)\n"
        << "  --diag-lan      Enable deep LAN discovery diagnostics\n";
}

bool ParseWorkerLaunchOptions(int argc, char* argv[], WorkerLaunchOptions* optionsOut)
{
    if (argc < 2)
    {
        PrintUsage();
        return false;
    }

    WorkerLaunchOptions options;
    options.serverName = argv[1];

    for (int i = 2; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "-n")
        {
            std::cout << "NFSLAN: NOTE - -n is deprecated and ignored; binary patching is always enabled.\n";
        }
        else if (arg == "--same-machine" || arg == "--local-host")
        {
            options.sameMachineMode = true;
        }
        else if (arg == "--local-emulation" || arg == "--network-emulation")
        {
            options.localEmulation = true;
        }
        else if (arg == "--ug2-beacon-emu")
        {
            options.ug2BeaconEmulation = true;
        }
        else if (arg == "--beacon-only")
        {
            options.beaconOnly = true;
            options.ug2BeaconEmulation = true;
        }
        else if (arg == "--u2-mode")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "ERROR: --u2-mode requires a value in range 0..13.\n";
                return false;
            }

            int mode = 0;
            if (!TryParseIntRange(argv[i + 1], 0, 13, &mode))
            {
                std::cerr << "ERROR: --u2-mode value '" << argv[i + 1] << "' is invalid. Expected 0..13.\n";
                return false;
            }

            options.u2Mode = mode;
            ++i;
        }
        else if (arg == "--diag-lan")
        {
            options.lanDiag = true;
        }
        else
        {
            std::cerr << "NFSLAN: WARNING - unknown option '" << arg << "' ignored.\n";
        }
    }

    *optionsOut = options;
    return true;
}

bool ApplyServerConfigCompatibility(
    const WorkerLaunchOptions& options,
    bool underground2Server,
    WorkerResolvedSettings* resolvedOut)
{
    WorkerResolvedSettings resolved{};
    resolved.sameMachineMode = options.sameMachineMode;
    resolved.localEmulation = options.localEmulation;
    resolved.lanDiag = options.lanDiag;
    if (underground2Server && options.u2Mode.has_value())
    {
        resolved.u2Mode = *options.u2Mode;
    }

    const std::filesystem::path configPath = "server.cfg";
    if (!std::filesystem::exists(configPath))
    {
        std::cerr << "NFSLAN: WARNING - server.cfg not found. Running with server.dll defaults.\n";
        if (resolvedOut)
        {
            *resolvedOut = resolved;
        }
        return true;
    }

    std::string configText;
    if (!ReadTextFile(configPath, &configText))
    {
        std::cerr << "ERROR: Failed to read server.cfg.\n";
        return false;
    }

    const bool lanDiagFromConfig =
        IsTruthy(GetConfigValue(configText, "LAN_DIAG").value_or("0"))
        || IsTruthy(GetConfigValue(configText, "LAN_DIAGNOSTICS").value_or("0"));
    resolved.lanDiag = options.lanDiag || lanDiagFromConfig;
    const bool localEmulationFromConfig =
        IsTruthy(GetConfigValue(configText, "LOCAL_EMULATION").value_or("0"))
        || IsTruthy(GetConfigValue(configText, "LOCAL_NET_EMULATION").value_or("0"));
    resolved.localEmulation = options.localEmulation || localEmulationFromConfig;
    resolved.sameMachineMode = resolved.sameMachineMode || resolved.localEmulation;
    const bool beaconEmulationFromConfig =
        IsTruthy(GetConfigValue(configText, "UG2_BEACON_EMULATION").value_or("0"))
        || IsTruthy(GetConfigValue(configText, "BEACON_EMULATION").value_or("0"));
    resolved.ug2BeaconEmulation =
        underground2Server && (options.ug2BeaconEmulation || options.beaconOnly || beaconEmulationFromConfig || resolved.sameMachineMode);

    bool changed = false;
    std::cout << "NFSLAN: Detected server profile: " << (underground2Server ? "Underground 2" : "Most Wanted") << '\n';

    // LOBBY_IDENT/LOBBY are protocol IDs that must match the client build.
    // Default to NA values only when missing; do not force-override.
    const std::string lobbyIdentDefault = underground2Server ? "NFSU2NA" : "NFSMWNA";
    const std::string lobbyIdentPrefix = underground2Server ? "NFSU2" : "NFSMW";
    std::string lobbyIdent = TrimAscii(GetConfigValue(configText, "LOBBY_IDENT").value_or(""));
    if (lobbyIdent.empty())
    {
        ForceConfigValue(&configText, "LOBBY_IDENT", lobbyIdentDefault, &changed);
        lobbyIdent = lobbyIdentDefault;
    }
    else if (!StartsWithIgnoreCase(lobbyIdent, lobbyIdentPrefix))
    {
        std::cout << "NFSLAN: WARNING - LOBBY_IDENT='" << lobbyIdent
                  << "' does not look like " << (underground2Server ? "Underground 2" : "Most Wanted")
                  << " (expected prefix '" << lobbyIdentPrefix << "'). Forcing LOBBY_IDENT=" << lobbyIdentDefault
                  << ".\n";
        ForceConfigValue(&configText, "LOBBY_IDENT", lobbyIdentDefault, &changed);
        lobbyIdent = lobbyIdentDefault;
    }

    const std::string configuredLobby = TrimAscii(GetConfigValue(configText, "LOBBY").value_or(""));
    if (configuredLobby.empty())
    {
        ForceConfigValue(&configText, "LOBBY", lobbyIdent, &changed);
    }
    else if (!EqualsIgnoreCase(configuredLobby, lobbyIdent))
    {
        std::cout << "NFSLAN: WARNING - LOBBY='" << configuredLobby
                  << "' does not match LOBBY_IDENT='" << lobbyIdent << "'. Forcing LOBBY to match.\n";
        ForceConfigValue(&configText, "LOBBY", lobbyIdent, &changed);
    }

    const std::string portValue = EnsureConfigValue(&configText, "PORT", "9900", &changed);
    std::string addrValue = EnsureConfigValue(&configText, "ADDR", "0.0.0.0", &changed);
    std::string ug2EndpointAddrValue = addrValue;
    std::string mwEndpointAddrValue = addrValue;

    // Keep essential services enabled even for minimal server.cfg files.
    EnsureConfigValue(&configText, "ACCOUNT", "1", &changed);
    EnsureConfigValue(&configText, "MASTER", "1", &changed);
    EnsureConfigValue(&configText, "SLAVE", "1", &changed);
    EnsureConfigValue(&configText, "REDIR", "1", &changed);

    if (underground2Server)
    {
        const std::string trimmedAddr = TrimAscii(addrValue);
        const bool wildcardAddr = trimmedAddr.empty() || EqualsIgnoreCase(trimmedAddr, "0.0.0.0");
        const bool bindExpressionAddr = trimmedAddr.find("%%bind(") != std::string::npos;
        if (wildcardAddr || bindExpressionAddr)
        {
            const auto detectedLan = DetectPreferredLocalLanIpv4();
            if (detectedLan.has_value())
            {
                ug2EndpointAddrValue = *detectedLan;
                std::cout << "NFSLAN: UG2 endpoint identity resolved to LAN IPv4 " << ug2EndpointAddrValue
                          << " (ADDR='" << trimmedAddr << "').\n";
            }
            else if (wildcardAddr)
            {
                ug2EndpointAddrValue = "127.0.0.1";
                std::cout << "NFSLAN: WARNING - could not auto-detect LAN IPv4 for UG2 endpoint identity; "
                             "falling back to 127.0.0.1.\n";
            }
        }
    }
    else
    {
        const std::string trimmedAddr = TrimAscii(addrValue);
        const bool wildcardAddr = trimmedAddr.empty() || EqualsIgnoreCase(trimmedAddr, "0.0.0.0");
        const bool bindExpressionAddr = trimmedAddr.find("%%bind(") != std::string::npos;
        if (wildcardAddr || bindExpressionAddr)
        {
            const auto detectedLan = DetectPreferredLocalLanIpv4();
            if (detectedLan.has_value())
            {
                mwEndpointAddrValue = *detectedLan;
                std::cout << "NFSLAN: MW endpoint identity resolved to LAN IPv4 " << mwEndpointAddrValue
                          << " (ADDR='" << trimmedAddr << "').\n";
            }
            else if (wildcardAddr)
            {
                mwEndpointAddrValue = "127.0.0.1";
                std::cout << "NFSLAN: WARNING - could not auto-detect LAN IPv4 for MW endpoint identity; "
                             "falling back to 127.0.0.1.\n";
            }
        }
    }

    if (resolved.sameMachineMode)
    {
        if (!EqualsIgnoreCase(TrimAscii(addrValue), "127.0.0.1"))
        {
            configText = UpsertConfigValue(configText, "ADDR", "127.0.0.1");
            addrValue = "127.0.0.1";
            changed = true;
            std::cout << "NFSLAN: Same-machine mode enabled -> ADDR=127.0.0.1\n";
        }

        if (!IsTruthy(GetConfigValue(configText, "FORCE_LOCAL").value_or("0")))
        {
            configText = UpsertConfigValue(configText, "FORCE_LOCAL", "1");
            changed = true;
            std::cout << "NFSLAN: Same-machine mode enabled -> FORCE_LOCAL=1\n";
        }

        if (underground2Server)
        {
            ForceConfigValue(&configText, "MADDR", "127.0.0.1", &changed);
            ForceConfigValue(&configText, "RADDR", "127.0.0.1", &changed);
            ForceConfigValue(&configText, "AADDR", "127.0.0.1", &changed);
            ForceConfigValue(&configText, "MPORT", portValue, &changed);
            ForceConfigValue(&configText, "RPORT", portValue, &changed);
            ForceConfigValue(&configText, "APORT", portValue, &changed);
            std::cout << "NFSLAN: Same-machine mode enabled -> UG2 endpoints forced to loopback.\n";
        }
    }

    if (resolved.localEmulation && !IsTruthy(GetConfigValue(configText, "LOCAL_EMULATION").value_or("0")))
    {
        configText = UpsertConfigValue(configText, "LOCAL_EMULATION", "1");
        changed = true;
        std::cout << "NFSLAN: LOCAL_EMULATION=1 enabled.\n";
    }

    if (underground2Server && resolved.ug2BeaconEmulation
        && !IsTruthy(GetConfigValue(configText, "UG2_BEACON_EMULATION").value_or("0")))
    {
        configText = UpsertConfigValue(configText, "UG2_BEACON_EMULATION", "1");
        changed = true;
        std::cout << "NFSLAN: UG2_BEACON_EMULATION=1 enabled.\n";
    }

    if (resolved.lanDiag && !IsTruthy(GetConfigValue(configText, "LAN_DIAG").value_or("0")))
    {
        configText = UpsertConfigValue(configText, "LAN_DIAG", "1");
        changed = true;
        std::cout << "NFSLAN: Added LAN_DIAG=1 (deep LAN diagnostics enabled).\n";
    }

    if (underground2Server)
    {
        int resolvedMode = 0;
        const auto modeValue = GetConfigValue(configText, "U2_START_MODE");
        if (options.u2Mode.has_value())
        {
            resolvedMode = *options.u2Mode;
            ForceConfigValue(&configText, "U2_START_MODE", std::to_string(resolvedMode), &changed);
        }
        else if (modeValue.has_value())
        {
            if (!TryParseIntRange(modeValue.value(), 0, 13, &resolvedMode))
            {
                std::cout << "NFSLAN: WARNING - invalid U2_START_MODE='" << modeValue.value()
                          << "', forcing U2_START_MODE=0.\n";
                resolvedMode = 0;
                ForceConfigValue(&configText, "U2_START_MODE", "0", &changed);
            }
        }
        else
        {
            resolvedMode = 0;
            configText = UpsertConfigValue(configText, "U2_START_MODE", "0");
            changed = true;
            std::cout << "NFSLAN: Added U2_START_MODE=0\n";
        }

        resolved.u2Mode = resolvedMode;
        std::cout << "NFSLAN: Effective U2 StartServer mode: " << resolved.u2Mode << '\n';
    }
    else if (options.u2Mode.has_value())
    {
        std::cout << "NFSLAN: NOTE - --u2-mode was provided for MW profile and will be ignored.\n";
    }

    std::cout << "NFSLAN: Effective LAN diagnostics: " << (resolved.lanDiag ? "enabled" : "disabled") << '\n';
    if (underground2Server)
    {
        std::cout << "NFSLAN: Effective UG2 beacon emulation: "
                  << (resolved.ug2BeaconEmulation ? "enabled" : "disabled") << '\n';
    }

    ForceConfigValue(&configText, "ENABLE_GAME_ADDR_FIXUPS", "1", &changed);

    if (underground2Server)
    {
        ForceConfigValue(&configText, "MADDR", ug2EndpointAddrValue, &changed);
        ForceConfigValue(&configText, "RADDR", ug2EndpointAddrValue, &changed);
        ForceConfigValue(&configText, "AADDR", ug2EndpointAddrValue, &changed);
        ForceConfigValue(&configText, "MPORT", portValue, &changed);
        ForceConfigValue(&configText, "RPORT", portValue, &changed);
        ForceConfigValue(&configText, "APORT", portValue, &changed);
        std::cout << "NFSLAN: UG2 endpoints aligned with resolved endpoint identity and PORT.\n";
    }
    else
    {
        // MW clients can discover the server via UDP beacons but still fail to join if the
        // configured endpoints resolve to loopback/wildcard. Force concrete endpoint identity.
        ForceConfigValue(&configText, "AADDR", mwEndpointAddrValue, &changed);
        ForceConfigValue(&configText, "APORT", portValue, &changed);
        std::cout << "NFSLAN: MW endpoints aligned with resolved endpoint identity and PORT.\n";
    }

    if (underground2Server)
    {
        for (const std::string& key : { std::string("MPORT"), std::string("RPORT"), std::string("APORT") })
        {
            EnsureMirroredKey(&configText, key, portValue, &changed);
        }
        for (const std::string& key : { std::string("MADDR"), std::string("RADDR"), std::string("AADDR") })
        {
            EnsureMirroredKey(&configText, key, ug2EndpointAddrValue, &changed);
        }
    }
    else
    {
        // MW endpoints: AADDR/APORT are required. CADDR/CPORT are used by some builds during
        // connection setup and are commonly expected to mirror the primary endpoint identity.
        EnsureMirroredKey(&configText, "APORT", portValue, &changed);
        EnsureMirroredKey(&configText, "AADDR", mwEndpointAddrValue, &changed);

        EnsureMirroredKey(&configText, "CADDR", mwEndpointAddrValue, &changed);
        EnsureMirroredKey(&configText, "CPORT", portValue, &changed);
    }

    int discoveryPort = kDefaultLanDiscoveryPort;
    const std::string discoveryPortValue = TrimAscii(GetConfigValue(configText, "DISCOVERY_PORT").value_or(""));
    if (!discoveryPortValue.empty())
    {
        if (!TryParseIntRange(discoveryPortValue, 1, 65535, &discoveryPort))
        {
            discoveryPort = kDefaultLanDiscoveryPort;
            std::cout << "NFSLAN: WARNING - invalid DISCOVERY_PORT='" << discoveryPortValue
                      << "', forcing DISCOVERY_PORT=" << kDefaultLanDiscoveryPort << ".\n";
            configText = UpsertConfigValue(configText, "DISCOVERY_PORT", std::to_string(kDefaultLanDiscoveryPort));
            changed = true;
        }
    }
    else if (resolved.localEmulation)
    {
        configText = UpsertConfigValue(configText, "DISCOVERY_PORT", std::to_string(kDefaultLanDiscoveryPort));
        changed = true;
        std::cout << "NFSLAN: Added DISCOVERY_PORT=" << kDefaultLanDiscoveryPort << '\n';
    }

    std::string discoveryAddr = TrimAscii(GetConfigValue(configText, "DISCOVERY_ADDR").value_or(""));
    if (discoveryAddr.empty())
    {
        if (resolved.localEmulation)
        {
            const auto detectedLan = DetectPreferredLocalLanIpv4();
            if (detectedLan.has_value())
            {
                discoveryAddr = *detectedLan;
                std::cout << "NFSLAN: Auto-detected DISCOVERY_ADDR=" << discoveryAddr
                          << " for local emulation.\n";
            }
        }

        if (discoveryAddr.empty())
        {
            discoveryAddr = resolved.sameMachineMode ? "127.0.0.1" : TrimAscii(addrValue);
            if (discoveryAddr.empty()
                || EqualsIgnoreCase(discoveryAddr, "0.0.0.0")
                || discoveryAddr.find("%%bind(") != std::string::npos)
            {
                discoveryAddr = "127.0.0.1";
            }
        }

        if (resolved.localEmulation)
        {
            configText = UpsertConfigValue(configText, "DISCOVERY_ADDR", discoveryAddr);
            changed = true;
            std::cout << "NFSLAN: Added DISCOVERY_ADDR=" << discoveryAddr << '\n';
        }
    }

    uint8_t discoveryOctets[4] = {};
    if (!ParseIpv4(discoveryAddr, discoveryOctets))
    {
        std::cout << "NFSLAN: WARNING - DISCOVERY_ADDR='" << discoveryAddr
                  << "' is not a concrete IPv4 address, using 127.0.0.1 for bridge probe.\n";
        discoveryAddr = "127.0.0.1";
        if (resolved.localEmulation)
        {
            configText = UpsertConfigValue(configText, "DISCOVERY_ADDR", discoveryAddr);
            changed = true;
        }
    }

    resolved.discoveryPort = discoveryPort;
    resolved.discoveryAddr = discoveryAddr;
    resolved.endpointAddr = underground2Server ? ug2EndpointAddrValue : mwEndpointAddrValue;
    int parsedEndpointPort = 9900;
    if (!TryParseIntRange(portValue, 1, 65535, &parsedEndpointPort))
    {
        parsedEndpointPort = 9900;
    }
    resolved.endpointPort = parsedEndpointPort;

    const auto cfg = [&](const std::string& key) -> std::string
    {
        return TrimAscii(GetConfigValue(configText, key).value_or(""));
    };

    std::cout << "NFSLAN: Effective ADDR/PORT: " << cfg("ADDR") << ":" << cfg("PORT") << '\n';
    std::cout << "NFSLAN: Effective lobby ident: LOBBY_IDENT=" << cfg("LOBBY_IDENT")
              << " LOBBY=" << cfg("LOBBY") << '\n';
    std::cout << "NFSLAN: Effective local emulation: " << (resolved.localEmulation ? "enabled" : "disabled") << '\n';
    if (resolved.localEmulation || resolved.sameMachineMode)
    {
        std::cout << "NFSLAN: Effective discovery probe endpoint: "
                  << resolved.discoveryAddr << ":" << resolved.discoveryPort << '\n';
    }
    if (underground2Server)
    {
        std::cout << "NFSLAN: Effective UG2 endpoints: M=" << cfg("MADDR") << ":" << cfg("MPORT")
                  << " R=" << cfg("RADDR") << ":" << cfg("RPORT")
                  << " A=" << cfg("AADDR") << ":" << cfg("APORT") << '\n';
    }
    else
    {
        std::cout << "NFSLAN: Effective MW endpoints: A=" << cfg("AADDR") << ":" << cfg("APORT")
                  << " C=" << cfg("CADDR") << ":" << cfg("CPORT") << '\n';
    }

    if (addrValue == "0.0.0.0")
    {
        std::cout << "NFSLAN: NOTE - ADDR=0.0.0.0 is fine for local bind, but internet clients need a public endpoint.\n";
    }
    else if (!resolved.sameMachineMode && LooksPrivateOrNonRoutableIpv4(addrValue))
    {
        std::cout << "NFSLAN: NOTE - ADDR=" << addrValue
                  << " is private/non-routable; remote internet players will not reach this directly.\n";
    }
    else if (!resolved.sameMachineMode && addrValue.find("%%bind(") != std::string::npos)
    {
        std::cout
            << "NFSLAN: NOTE - ADDR uses %%bind(...), which usually resolves to a LAN IP. "
            << "Use a public IP/DNS for internet hosting.\n";
    }

    if (resolved.sameMachineMode && portValue == "9900")
    {
        std::cout << "NFSLAN: NOTE - Same-machine mode with PORT=9900 can still conflict on some client patches. "
                     "Try a different server PORT if local client cannot see/join.\n";
    }
    if (underground2Server && (resolved.sameMachineMode || resolved.localEmulation))
    {
        std::cout << "NFSLAN: NOTE - UG2 client filters self-discovered LAN servers in speed2.exe. "
                     "Use NFSLAN-U2-Patcher when running host and client on the same machine.\n";
        if (resolved.ug2BeaconEmulation)
        {
            std::cout << "NFSLAN: NOTE - UG2 synthetic beacon emulator is active (visibility-first fallback mode).\n";
        }
    }

    if (changed)
    {
        if (!WriteTextFile(configPath, configText))
        {
            std::cerr << "ERROR: Failed to update server.cfg.\n";
            return false;
        }
        std::cout << "NFSLAN: Updated server.cfg compatibility flags.\n";
    }

    if (resolvedOut)
    {
        *resolvedOut = resolved;
    }

    return true;
}

} // namespace

// requires that the client is using the LanIP plugin!
void LocalChallengeClient(uint32_t addr)
{
    constexpr DWORD ChallengeTimeOut = 1000; // 1sec timeout
    uint32_t query = 0x6A093EC9; // strhash of "LOCAL?" 6A093EC9
    uint32_t response = 0;
    char strIP[32];
    sprintf(strIP, "%u.%u.%u.%u", addr >> 24 & 0xFF, addr >> 16 & 0xFF, addr >> 8 & 0xFF, addr & 0xFF);

    std::cout << "NFSLAN: challenging addr " << strIP << '\n';

    try
    {
        UDPSocket Socket;
        Socket.SetTimeout(ChallengeTimeOut);
        Socket.SendTo(strIP, 9901, (char*)&query, sizeof(uint32_t));
        Socket.RecvFrom((char*)&response, sizeof(uint32_t));
        if (response == 0x8DB682D1) // strhash of "YESIMLOCAL" 8DB682D1
        {
            sprintf(strIP, "%u.%u.%u.%u", addr >> 24 & 0xFF, addr >> 16 & 0xFF, addr >> 8 & 0xFF, addr & 0xFF);
            std::cout << "NFSLAN: addr " << strIP << " is local!\n";
            LocalUsers.push_back(addr);
        }
    }
    catch (std::exception& ex)
    {
        std::cerr << "ERROR: " << ex.what() << '\n';
        return;
    }
}

uintptr_t lobbyAddrFunc = 0x100025E0;
void hkLobbyAddr(uintptr_t a0, uintptr_t a1, uintptr_t a2, uint32_t addr)
{
    uint32_t setaddr = addr;

    if (addr != lobbyClientDestAddr)
    {
        if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), lobbyClientDestAddr) != LocalUsers.cend())
        {
            if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), addr) != LocalUsers.cend())
            {
                setaddr = addr;
            }
            else if (RedirIPs.find(addr) != RedirIPs.end())
                setaddr = RedirIPs.at(addr);
        }
        else if (RedirIPs.find(addr) != RedirIPs.end())
            setaddr = RedirIPs.at(addr);
   }
    else if (RedirIPs.find(addr) != RedirIPs.end())
        setaddr = RedirIPs.at(addr);


    //printf("Setting local: Addr: %X Dest: %X\n", setaddr, lobbyClientDestAddr);

    //printf("Addr: %X Dest: %X\n", setaddr, lobbyClientDestAddr);

    return reinterpret_cast<void(*)(uintptr_t, uintptr_t, uintptr_t, uint32_t)>(lobbyAddrFunc)(a0, a1, a2, setaddr);
}

// server patches for MW server (server.dll in MW and Carbon (yes really, Carbon's is slightly different but it's there))
void PatchServerMW(uintptr_t base)
{
    // base is usually 10000000 but it's better safe than sorry
    hook::details::set_process_base(base);

    // 1001DC8B - 1001DC93
    uintptr_t loc_1001DC8B = reinterpret_cast<uintptr_t>(hook::pattern("83 C4 08 50 E8 ? ? ? ? 8B 4E 7C 83 C4 08 6A 00 8B D8 68").get_first(0)) + 4;

    // 1001DCAD - 1001DCBA
    uintptr_t loc_1001DCAD = loc_1001DC8B + 0x22;

    // 10006ABE
    uintptr_t loc_10006ABE = reinterpret_cast<uintptr_t>(hook::pattern("C7 46 14 FE FF FF FF C6 01 00").get_first(0));

    // 10007294
    uintptr_t loc_10007294 = reinterpret_cast<uintptr_t>(hook::pattern("8B 4E 5C 8B 56 60 8B E8 8B 45 18 50").get_first(0));

    // 1001BEDF
    uintptr_t loc_1001BEDF = reinterpret_cast<uintptr_t>(hook::pattern("8B 82 38 0A 00 00 8D 88 70 03 00 00 51 8B 8A 6C 0D 00 00").get_first(0));

    // 1000AB32
    uintptr_t loc_1000AB32 = reinterpret_cast<uintptr_t>(hook::pattern("8B 86 D0 02 00 00 8D 8E D0 00 00 00 51 8B").get_first(0));

    // 1000AB03
    uintptr_t loc_1000AB03 = reinterpret_cast<uintptr_t>(hook::pattern("8B 8E D4 02 00 00 52 8B 96 18 03 00 00").get_first(0));

    // 100099EF
    uintptr_t loc_100099EF = reinterpret_cast<uintptr_t>(hook::pattern("8B 86 38 0A 00 00 85 C0 BB ? ? ? ? 74 13 50 E8").get_first(0));

    // 10026514
    uintptr_t loc_10026514 = reinterpret_cast<uintptr_t>(hook::pattern("55 8D 4C 24 14 51 57 53 E8 ? ? ? ? 56 8D 54 24 24 68 ? ? ? ? 52 E8 ? ? ? ? 8B 44 24 50").get_first(0)) + 8;

    // 1001363D
    uintptr_t loc_1001363D = reinterpret_cast<uintptr_t>(hook::pattern("C7 45 5C F4 FF 00 00 89 75 50 89 75 54 89 75 58").get_first(0)) + 7;

    // 10013C95
    uintptr_t loc_10013C95 = reinterpret_cast<uintptr_t>(hook::pattern("51 89 7D 50 89 7D 54 89 7D 58 8B 4B 10").get_first(0)) + 1;


    struct PatchAddr1
    {
        void operator()(injector::reg_pack& regs)
        {
            regs.eax = *(uint32_t*)(regs.esi + 0x14);
            regs.ecx = *(uint32_t*)(regs.esi + 0x7C);
        }
    }; injector::MakeInline<PatchAddr1>(loc_1001DC8B, loc_1001DC8B + 8);

    struct PatchPort1
    {
        void operator()(injector::reg_pack& regs)
        {
            regs.ecx = *(uint8_t*)(regs.esp + 0x1E);
            regs.edi = *(uint16_t*)(regs.esi + 0x18);
        }
    }; injector::MakeInline<PatchPort1>(loc_1001DCAD, loc_1001DCAD + 0xD);

    // disable IP address invalidation at this point
    injector::MakeNOP(loc_10006ABE, 7);

    struct PatchAddrAndPort2
    {
        void operator()(injector::reg_pack& regs)
        {
            *(uint32_t*)(regs.eax + 0x18) = *(uint32_t*)(regs.esi + 0x14);
            //*(uint16_t*)(regs.eax + 0xC) = *(uint16_t*)(regs.esi + 0x18);
            *(int32_t*)(regs.esi + 0x14) = -5;
            regs.ecx = *(uint32_t*)(regs.esi + 0x5C);
            regs.edx = *(uint32_t*)(regs.esi + 0x60);
        }
    }; injector::MakeInline<PatchAddrAndPort2>(loc_10007294, loc_10007294 + 6);

    struct CatchLocalSKU
    {
        void operator()(injector::reg_pack& regs)
        {
            regs.eax = *(uint32_t*)(regs.edx + 0xA38);
            char* strSKU = (char*)(regs.eax + 0x80);
            static const std::regex kIpv4Regex(R"(^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$)");
            if (std::regex_match(strSKU, kIpv4Regex))
            {
                uint32_t connIP = *(uint32_t*)(regs.ebx + 0x14);
                uint32_t incomingIP = 0;
                uint8_t p1, p2, p3, p4;
                sscanf(strSKU, "%hhu.%hhu.%hhu.%hhu", &p1, &p2, &p3, &p4);
                incomingIP = p1 << 24 | p2 << 16 | p3 << 8 | p4;

                if (incomingIP != connIP)
                {
                    RedirIPs.insert(std::pair(connIP, incomingIP));

                    // challenge the connIP to see if it's local to the server, and if it is, add it to its own list
                    std::thread(LocalChallengeClient, connIP).detach();
                }
            }
        }
    }; injector::MakeInline<CatchLocalSKU>(loc_1001BEDF, loc_1001BEDF + 6);

    struct TestLocalSKU
    {
        void operator()(injector::reg_pack& regs)
        {
            uint32_t connIP = *(uint32_t*)(regs.esi + 0x2D0);
            uint32_t destIP = *(uint32_t*)(regs.edi + 0x14);

            if (connIP != destIP)
            {
                if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), destIP) != LocalUsers.cend())
                {
                    if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), connIP) != LocalUsers.cend())
                    {
                        regs.eax = connIP;
                    }
                    else if (RedirIPs.find(connIP) != RedirIPs.end())
                        regs.eax = RedirIPs.at(connIP);
                }
                else if (RedirIPs.find(connIP) != RedirIPs.end())
                    regs.eax = RedirIPs.at(connIP);
            }
            else if (RedirIPs.find(connIP) != RedirIPs.end())
                regs.eax = RedirIPs.at(connIP);

            //printf("A: Setting local: Addr: %X Dest: %X\n", regs.eax, destIP);
        }
    }; injector::MakeInline<TestLocalSKU>(loc_1000AB32, loc_1000AB32 + 6);

    struct TestLocalSKU_LA
    {
        void operator()(injector::reg_pack& regs)
        {
            uint32_t connIP = *(uint32_t*)(regs.esi + 0x2D4);
            uint32_t destIP = *(uint32_t*)(regs.edi + 0x14);

            if (connIP != destIP)
            {
                if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), destIP) != LocalUsers.cend())
                {
                    if (std::find(LocalUsers.cbegin(), LocalUsers.cend(), connIP) != LocalUsers.cend())
                    {
                        regs.ecx = connIP;
                    }
                    else if (RedirIPs.find(connIP) != RedirIPs.end())
                        regs.ecx = RedirIPs.at(connIP);
                }
                else if (RedirIPs.find(connIP) != RedirIPs.end())
                    regs.ecx = RedirIPs.at(connIP);
            }
            else if (RedirIPs.find(connIP) != RedirIPs.end())
                regs.ecx = RedirIPs.at(connIP);
            //printf("LA: Setting local: Addr: %X Dest: %X\n", regs.ecx, destIP);
        }
    }; injector::MakeInline<TestLocalSKU_LA>(loc_1000AB03, loc_1000AB03 + 6);


    struct CatchLocalSKU_TERM
    {
        void operator()(injector::reg_pack& regs)
        {
            uint32_t a1 = *(uint32_t*)(regs.esp + 0x410);
            uint32_t connIP = *(uint32_t*)(a1 + 0x14);

            LocalUsers.erase(std::remove(LocalUsers.begin(), LocalUsers.end(), connIP), LocalUsers.end());
            RedirIPs.erase(connIP);

            regs.eax = *(uint32_t*)(regs.esi + 0xA38);
        }
    }; injector::MakeInline<CatchLocalSKU_TERM>(loc_100099EF, loc_100099EF + 6);

    struct CatchDestAddr1
    {
        void operator()(injector::reg_pack& regs)
        {
            lobbyClientDestAddr = *(uint32_t*)(regs.ebp + 0x14);
            *(uint32_t*)(regs.ebp + 0x50) = 0;
            *(uint32_t*)(regs.ebp + 0x54) = 0;
        }
    }; injector::MakeInline<CatchDestAddr1>(loc_1001363D, loc_1001363D + 6);

    struct CatchDestAddr2
    {
        void operator()(injector::reg_pack& regs)
        {
            lobbyClientDestAddr = *(uint32_t*)(regs.ebp + 0x14);
            *(uint32_t*)(regs.ebp + 0x50) = 0;
            *(uint32_t*)(regs.ebp + 0x54) = 0;
        }
    }; injector::MakeInline<CatchDestAddr2>(loc_10013C95, loc_10013C95 + 6);

    lobbyAddrFunc = reinterpret_cast<uintptr_t>(injector::MakeCALL(loc_10026514, hkLobbyAddr).get_raw<void>());
    injector::MakeCALL(loc_10026514 + 0x21, hkLobbyAddr);
}

void PatchServerUG2(uintptr_t base)
{
    std::cout << "NFSLAN: Server patching for NFS Underground 2 not yet implemented.\n";
}

bool ModuleContainsAscii(uintptr_t base, const char* needle)
{
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + static_cast<uintptr_t>(dos->e_lfanew));
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    const size_t imageSize = static_cast<size_t>(nt->OptionalHeader.SizeOfImage);
    const size_t needleLength = std::strlen(needle);
    if (needleLength == 0 || needleLength > imageSize)
    {
        return false;
    }

    const auto* bytes = reinterpret_cast<const char*>(base);
    for (size_t i = 0; i + needleLength <= imageSize; ++i)
    {
        if (std::memcmp(bytes + i, needle, needleLength) == 0)
        {
            return true;
        }
    }

    return false;
}

bool bIsUnderground2Server(uintptr_t base)
{
    // Prefer protocol markers: they vary by build/region (suffix), but the prefix is stable.
    const bool hasU2 = ModuleContainsAscii(base, "NFSU2");
    const bool hasMw = ModuleContainsAscii(base, "NFSMW");
    if (hasU2 && !hasMw)
    {
        return true;
    }
    if (hasMw && !hasU2)
    {
        return false;
    }

    if (ModuleContainsAscii(base, "RPORT")
        && ModuleContainsAscii(base, "RADDR")
        && ModuleContainsAscii(base, "TRUST_MATCH"))
    {
        return true;
    }

    // base is usually 10000000 but it's better safe than sorry
    hook::details::set_process_base(base);

    // 100013FB in MW, 100013EC in UG2
    try
    {
        uintptr_t defServerNamePtr = reinterpret_cast<uintptr_t>(hook::pattern("6A 03 68 66 76 64 61 53").get_first(0)) + 0x12;
        char* defServerName = *(char**)defServerNamePtr;
        if ((defServerName != nullptr) && (std::strstr(defServerName, "Underground 2") != nullptr))
        {
            return true;
        }
    }
    catch (...)
    {
        // ignore and fall back to default false
    }

    return false;
}

void SigInterruptHandler(int signum)
{
    StopLanDiscoveryLoopbackBridge();
    StopUg2BeaconEmulator();
    if (IsServerRunning && StopServer && IsServerRunning())
    {
        std::cout << "NFSLAN: Stopping server...\n";
        StopServer();
    }
    else
    {
        std::cout << "NFSLAN: WARNING - server was NOT running during interrupt!\n";
    }
    ReleaseServerIdentityLock();
    gSameMachineModeEnabled.store(false);
    gLocalEmulationEnabled.store(false);
    exit(signum);
}

int NFSLANWorkerMain(int argc, char* argv[])
{
    std::ios::sync_with_stdio(true);
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);

    std::cout << "NFS LAN Server Launcher\n";
    std::cout << "NFSLAN: Build tag " << kBuildTag << '\n';

    WorkerLaunchOptions options;
    if (!ParseWorkerLaunchOptions(argc, argv, &options))
    {
        return -1;
    }

    bDisablePatching = false;
    gSameMachineModeEnabled.store(options.sameMachineMode);
    gLocalEmulationEnabled.store(options.localEmulation);
    gLanDiscoveryPort.store(kDefaultLanDiscoveryPort);
    gLanDiscoveryAddr = "127.0.0.1";
    gLoopbackMirrorAnnounced.store(false);
    if (options.sameMachineMode)
    {
        std::cout << "NFSLAN: Same-machine mode enabled.\n";
    }
    if (options.localEmulation)
    {
        std::cout << "NFSLAN: Local discovery emulation requested from CLI.\n";
    }
    if (options.lanDiag)
    {
        std::cout << "NFSLAN: Deep LAN diagnostics requested from CLI.\n";
    }

    StartServer = nullptr;
    IsServerRunning = nullptr;
    StopServer = nullptr;

    const bool beaconOnlyMode = options.beaconOnly;
    HMODULE serverdll = nullptr;
    bool underground2Server = true;

    if (beaconOnlyMode)
    {
        std::cout << "NFSLAN: Beacon-only mode enabled (server.dll not required).\n";
        std::cout << "NFSLAN: Beacon-only currently targets Underground 2 LAN discovery format.\n";
    }
    else
    {
        if (!std::filesystem::exists("server.dll"))
        {
            std::cerr << "ERROR: server.dll not found! Please place the server.dll from the game in this executable's path!\n";
            return -1;
        }

        serverdll = LoadLibraryA("server");
        if (!serverdll)
        {
            std::cerr << "ERROR: server.dll failed to load!\n";
            return -1;
        }

        StartServer = (bool(*)(char*, int32_t, void*, void*))GetProcAddress(serverdll, "StartServer");
        if (!StartServer)
        {
            std::cerr << "ERROR: could not find function StartServer inside server.dll!\n";
            return -1;
        }
        IsServerRunning = (bool(*)())GetProcAddress(serverdll, "IsServerRunning");
        if (!IsServerRunning)
        {
            std::cerr << "ERROR: could not find function IsServerRunning inside server.dll!\n";
            return -1;
        }
        StopServer = (void(*)())GetProcAddress(serverdll, "StopServer");
        if (!StopServer)
        {
            std::cerr << "ERROR: could not find function StopServer inside server.dll!\n";
            return -1;
        }

        underground2Server = bIsUnderground2Server((uintptr_t)serverdll);
    }

    WorkerResolvedSettings resolved{};
    bool sendToHookInstalled = false;
    ScopedServerIdentityLock identityLock;

    if (!ApplyServerConfigCompatibility(options, underground2Server, &resolved))
    {
        return -1;
    }

    gSameMachineModeEnabled.store(resolved.sameMachineMode);
    gLocalEmulationEnabled.store(resolved.localEmulation);
    gLanDiscoveryPort.store(resolved.discoveryPort);
    gLanDiscoveryAddr = resolved.discoveryAddr;
    gMwDirCompatEnabled.store(!underground2Server);
    gMwDirCompatAddr = resolved.endpointAddr;
    gMwDirCompatPort.store(resolved.endpointPort);
    gMwDirCompatAnnounced.store(false);

    if (resolved.sameMachineMode && !options.sameMachineMode)
    {
        std::cout << "NFSLAN: Same-machine mode enabled from config/runtime normalization.\n";
    }
    if (resolved.localEmulation)
    {
        std::cout << "NFSLAN: Local discovery emulation active ("
                  << resolved.discoveryAddr << ":" << resolved.discoveryPort << ").\n";
    }

    std::string identityLobby;
    int identityPort = 9900;
    ResolveServerIdentityFromConfig(underground2Server, &identityLobby, &identityPort);
    if (!AcquireServerIdentityLock(identityLobby, identityPort))
    {
        return -1;
    }
    identityLock.armed = true;

    gLanDiagEnabled.store(resolved.lanDiag);
    gLanDiagBeaconLogCount.store(0);

    if (!beaconOnlyMode && underground2Server)
    {
        sendToHookInstalled = InstallSendToHook(serverdll);
        if (!sendToHookInstalled)
        {
            std::cout << "NFSLAN: WARNING - UG2 sendto hook unavailable; using bridge-level beacon diagnostics only.\n";
        }
    }
    else if (!beaconOnlyMode && !underground2Server)
    {
        const bool sendHookInstalled = InstallSendHook(serverdll);
        if (!sendHookInstalled)
        {
            std::cout << "NFSLAN: WARNING - MW send hook unavailable; remote clients may see IDOWN/no-master.\n";
        }
    }

    if (!beaconOnlyMode && !bDisablePatching)
    {
        std::cout << "NFSLAN: Patching the server to work on any network...\n";

        if (underground2Server)
            PatchServerUG2((uintptr_t)serverdll);
        else
            PatchServerMW((uintptr_t)serverdll);
    }

    signal(SIGINT, SigInterruptHandler);
    signal(SIGTERM, SigInterruptHandler);

    if (!beaconOnlyMode)
    {
        const int startMode = underground2Server ? resolved.u2Mode : 0;
        if (!StartServer(options.serverName.data(), startMode, nullptr, nullptr))
        {
            std::cerr << "ERROR: could not launch server! StartServer returned false!\n";
            return -1;
        }

        if (!IsServerRunning())
        {
            std::cerr << "ERROR: could not launch server! StartServer returned true but IsServerRunning returned false!\n";
            return -1;
        }
    }

    if (resolved.sameMachineMode || resolved.localEmulation)
    {
        LogLanDiscoveryPortDiagnostic(resolved.discoveryPort);
    }

    if (underground2Server && resolved.ug2BeaconEmulation)
    {
        StartUg2BeaconEmulator(true, identityLobby, options.serverName, identityPort);
    }

    if (beaconOnlyMode)
    {
        if (!gUg2BeaconEmuRunning.load())
        {
            std::cerr << "ERROR: Beacon-only mode requested but UG2 beacon emulator failed to start.\n";
            return -1;
        }

        std::cout << "NFSLAN: Beacon-only mode running. Synthetic UG2 LAN beacon is being broadcast.\n";
        std::cout << "NFSLAN: To stop, send CTRL+C to the console.\n";
        while (gUg2BeaconEmuRunning.load()) { Sleep(100); }
        return 0;
    }

    const bool useLanBridge =
        resolved.localEmulation
        || (resolved.sameMachineMode && (!underground2Server || !sendToHookInstalled));
    if (!resolved.localEmulation && resolved.sameMachineMode && underground2Server && sendToHookInstalled)
    {
        std::cout << "NFSLAN: Same-machine UG2 discovery uses sendto loopback mirror (bridge disabled).\n";
    }
    if (resolved.localEmulation && underground2Server && sendToHookInstalled)
    {
        std::cout << "NFSLAN: Local emulation keeps LAN bridge enabled even with UG2 sendto hook.\n";
    }
    StartLanDiscoveryLoopbackBridge(useLanBridge);

    std::cout << "NFSLAN: Server started. To stop gracefully, send CTRL+C to the console\n";
    while (IsServerRunning()) { Sleep(1); }
    StopLanDiscoveryLoopbackBridge();
    StopUg2BeaconEmulator();
    gSameMachineModeEnabled.store(false);
    gLocalEmulationEnabled.store(false);
    if (IsServerRunning())
    {
        std::cout << "NFSLAN: Stopping server...\n";
        StopServer();
    }
    else
    {
        std::cout << "NFSLAN: Server not running anymore, exiting...\n";
    }

    return 0;
}

#ifndef NFSLAN_WORKER_NO_MAIN
int main(int argc, char* argv[])
{
    return NFSLANWorkerMain(argc, argv);
}
#endif
