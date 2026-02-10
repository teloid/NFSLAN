// NFS LAN server launcher for Most Wanted (2005) and Underground 2
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
#include <iphlpapi.h>
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
    bool disablePatching = false;
    bool sameMachineMode = false;
    bool lanDiag = false;
    std::optional<int> u2Mode;
};

struct WorkerResolvedSettings
{
    int u2Mode = 0;
    bool lanDiag = false;
};

constexpr uint16_t kGameReportIdent = 0x9A3E;
constexpr uint16_t kGameReportVersion = 2;
constexpr int kLanDiscoveryPort = 9999;
constexpr const char* kBuildTag = "2026-02-10-ug2diag-5";

std::atomic<bool> gLanBridgeRunning{ false };
std::thread gLanBridgeThread;

using SendToFn = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
SendToFn gOriginalSendTo = nullptr;
std::atomic<bool> gSendToHookInstalled{ false };
std::atomic<int> gUg2BeaconPatchedCount{ 0 };
std::atomic<bool> gLanDiagEnabled{ false };
std::atomic<int> gLanDiagBeaconLogCount{ 0 };
std::atomic<bool> gSameMachineModeEnabled{ false };
std::atomic<bool> gLoopbackMirrorAnnounced{ false };

bool LooksLikeUg2LanBeacon(const char* payload, int length);

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

void MigrateLegacyConfigValue(
    std::string* configText,
    const std::string& key,
    const std::string& legacyValue,
    const std::string& newValue,
    bool* changed)
{
    const std::string existing = TrimAscii(GetConfigValue(*configText, key).value_or(""));
    if (existing.empty() || EqualsIgnoreCase(existing, legacyValue))
    {
        ForceConfigValue(configText, key, newValue, changed);
    }
}

bool TryReadGameReportFileHeader(const std::filesystem::path& path, uint16_t* identOut, uint16_t* versionOut)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        return false;
    }

    std::array<unsigned char, 4> header{};
    file.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (file.gcount() != static_cast<std::streamsize>(header.size()))
    {
        return false;
    }

    *identOut = static_cast<uint16_t>(header[0] | (static_cast<uint16_t>(header[1]) << 8));
    *versionOut = static_cast<uint16_t>(header[2] | (static_cast<uint16_t>(header[3]) << 8));
    return true;
}

std::string FormatGameReportHeader(uint16_t ident, uint16_t version)
{
    std::ostringstream stream;
    stream << "ident=0x" << std::hex << std::uppercase << ident << std::dec << " version=" << version;
    return stream.str();
}

bool IsCompatibleGameReportFile(const std::filesystem::path& path, std::string* detailsOut)
{
    uint16_t ident = 0;
    uint16_t version = 0;
    if (!TryReadGameReportFileHeader(path, &ident, &version))
    {
        if (detailsOut)
        {
            *detailsOut = "unable to read header";
        }
        return false;
    }

    if (detailsOut)
    {
        *detailsOut = FormatGameReportHeader(ident, version);
    }

    return ident == kGameReportIdent && version == kGameReportVersion;
}

std::optional<std::string> ResolveCompatibleGameReportFile(const std::string& configuredGamefile)
{
    std::vector<std::string> candidates;
    if (!configuredGamefile.empty())
    {
        candidates.push_back(configuredGamefile);
    }

    for (const std::string& fallback : { std::string("gamefile.bin"), std::string("gameplay.bin") })
    {
        if (std::find(candidates.begin(), candidates.end(), fallback) == candidates.end())
        {
            candidates.push_back(fallback);
        }
    }

    for (const std::string& candidate : candidates)
    {
        if (!std::filesystem::exists(std::filesystem::path(candidate)))
        {
            continue;
        }

        std::string details;
        if (IsCompatibleGameReportFile(candidate, &details))
        {
            return candidate;
        }

        if (candidate == configuredGamefile)
        {
            std::cout << "NFSLAN: GAMEFILE '" << candidate << "' is incompatible (" << details
                      << "), expected " << FormatGameReportHeader(kGameReportIdent, kGameReportVersion)
                      << ".\n";
        }
    }

    return std::nullopt;
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

std::string ExtractUg2BeaconStats(const char* payload, int length)
{
    constexpr size_t statsOffset = 0x48;
    constexpr size_t statsMax = 0xC0;
    if (!payload || length <= 0 || static_cast<size_t>(length) <= statsOffset)
    {
        return {};
    }

    return ReadBeaconStringField(payload, length, statsOffset, statsMax);
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

    const std::string ident(payload + 8, payload + 15);
    std::string serverName = ReadBeaconStringField(payload, length, 0x28, 0x20);
    if (serverName.empty())
    {
        serverName = FindPrintableString(payload, length, 0x20, 0x80, 3);
    }

    const std::string stats = ExtractUg2BeaconStats(payload, length);
    const std::string preview = HexPreview(payload, length, 64);

    std::cout << "NFSLAN: LAN-DIAG " << sourceTag
              << " ident=" << ident
              << " stats='" << stats << "'"
              << " name='" << serverName << "'"
              << " patched=" << (patched ? "1" : "0")
              << " len=" << length << '\n';
    std::cout << "NFSLAN: LAN-DIAG " << sourceTag << " bytes[0..63]: " << preview << '\n';
}

void MirrorUg2BeaconToLoopback(SOCKET socketHandle, const char* payload, int length, int flags)
{
    if (!gSameMachineModeEnabled.load() || !gOriginalSendTo || !payload || length <= 0)
    {
        return;
    }

    sockaddr_in loopbackAddr{};
    loopbackAddr.sin_family = AF_INET;
    loopbackAddr.sin_port = htons(static_cast<u_short>(kLanDiscoveryPort));
    loopbackAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    const int mirrorResult = gOriginalSendTo(
        socketHandle,
        payload,
        length,
        flags,
        reinterpret_cast<sockaddr*>(&loopbackAddr),
        sizeof(loopbackAddr));
    if (mirrorResult < 0)
    {
        if (gLanDiagEnabled.load())
        {
            std::cerr << "NFSLAN: LAN-DIAG loopback mirror failed (WSA error " << WSAGetLastError() << ").\n";
        }
        return;
    }

    if (!gLoopbackMirrorAnnounced.exchange(true))
    {
        std::cout << "NFSLAN: Same-machine UG2 beacon mirror active on 127.0.0.1:9999.\n";
    }

    if (ShouldLogLanDiagSample(&gLanDiagBeaconLogCount, 6))
    {
        LogUg2LanBeaconDiag("hook-mirror-loopback", payload, length, true);
    }
}

bool LooksLikeUg2LanBeacon(const char* payload, int length)
{
    if (!payload || length != 0x180)
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

    return std::memcmp(payload + 8, "NFSU2NA", 7) == 0;
}

bool PatchUg2LanBeaconCount(char* payload, int length)
{
    if (!LooksLikeUg2LanBeacon(payload, length))
    {
        return false;
    }

    constexpr size_t statsOffset = 0x48;
    constexpr size_t statsMax = 0xC0;
    size_t statsLen = 0;
    while (statsLen < statsMax && payload[statsOffset + statsLen] != '\0')
    {
        ++statsLen;
    }

    if (statsLen == 0 || statsLen >= statsMax)
    {
        return false;
    }

    std::string stats(payload + statsOffset, payload + statsOffset + statsLen);
    const size_t pipePos = stats.find('|');
    if (pipePos == std::string::npos)
    {
        return false;
    }

    const std::string before = stats.substr(0, pipePos);
    const std::string after = stats.substr(pipePos + 1);
    if (after != "0")
    {
        return false;
    }

    const std::string patchedStats = before + "|1";
    if (patchedStats.size() >= statsMax)
    {
        return false;
    }

    std::memset(payload + statsOffset, 0, statsMax);
    std::memcpy(payload + statsOffset, patchedStats.c_str(), patchedStats.size());
    return true;
}

int WSAAPI HookedSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    if (!gOriginalSendTo)
    {
        return SOCKET_ERROR;
    }

    if (LooksLikeUg2LanBeacon(buf, len))
    {
        if (ShouldLogLanDiagSample(&gLanDiagBeaconLogCount, 8))
        {
            LogUg2LanBeaconDiag("hook-send-original", buf, len, false);
        }

        std::array<char, 0x180> patched{};
        std::memcpy(patched.data(), buf, patched.size());
        if (PatchUg2LanBeaconCount(patched.data(), len))
        {
            const int patchIndex = ++gUg2BeaconPatchedCount;
            if (patchIndex <= 3)
            {
                std::cout << "NFSLAN: Patched UG2 LAN beacon stats to advertise at least one slot.\n";
            }

            if (ShouldLogLanDiagSample(&gLanDiagBeaconLogCount, 8))
            {
                LogUg2LanBeaconDiag("hook-send-patched", patched.data(), static_cast<int>(patched.size()), true);
            }

            MirrorUg2BeaconToLoopback(
                s,
                patched.data(),
                static_cast<int>(patched.size()),
                flags);

            return gOriginalSendTo(s, patched.data(), static_cast<int>(patched.size()), flags, to, tolen);
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
        std::cout << "NFSLAN: Installed UG2 sendto beacon compatibility hook (" << sourceTag << ").\n";
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

bool IsLanDiscoveryPacket(const char* data, int length)
{
    return data && length >= 9 && data[0] == 'g' && data[1] == 'E' && data[2] == 'A';
}

std::array<char, 0x180> BuildLanDiscoveryQueryPacket()
{
    std::array<char, 0x180> packet{};
    packet[0] = 'g';
    packet[1] = 'E';
    packet[2] = 'A';
    packet[8] = '?';
    return packet;
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

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(static_cast<u_short>(kLanDiscoveryPort));
        serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        sockaddr_in localClientAddr{};
        localClientAddr.sin_family = AF_INET;
        localClientAddr.sin_port = htons(static_cast<u_short>(kLanDiscoveryPort));
        localClientAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        sockaddr_in broadcastClientAddr{};
        broadcastClientAddr.sin_family = AF_INET;
        broadcastClientAddr.sin_port = htons(static_cast<u_short>(kLanDiscoveryPort));
        broadcastClientAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

        const auto queryPacket = BuildLanDiscoveryQueryPacket();
        bool loggedFirstResponse = false;
        bool loggedSendError = false;
        bool loggedBroadcastError = false;
        bool loggedBridgePatch = false;
        int silentCycles = 0;

        if (gLanDiagEnabled.load())
        {
            std::cout << "NFSLAN: LAN-DIAG bridge probe enabled on UDP " << kLanDiscoveryPort << ".\n";
        }

        while (gLanBridgeRunning.load())
        {
            const int sent = sendto(
                sock,
                queryPacket.data(),
                static_cast<int>(queryPacket.size()),
                0,
                reinterpret_cast<sockaddr*>(&serverAddr),
                sizeof(serverAddr));

            if (sent < 0)
            {
                if (!loggedSendError)
                {
                    loggedSendError = true;
                    std::cerr << "NFSLAN: WARNING - LAN bridge send failed (WSA error " << WSAGetLastError() << ").\n";
                }
                ++silentCycles;
                Sleep(1000);
                continue;
            }

            loggedSendError = false;
            bool forwardedAny = false;
            for (int i = 0; i < 8; ++i)
            {
                std::array<char, 0x180> response{};
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

                if (PatchUg2LanBeaconCount(response.data(), received))
                {
                    const int patchIndex = ++gUg2BeaconPatchedCount;
                    if (patchIndex <= 3 || !loggedBridgePatch)
                    {
                        loggedBridgePatch = true;
                        std::cout << "NFSLAN: Patched UG2 LAN beacon stats in LAN bridge response.\n";
                    }
                }

                if (ShouldLogLanDiagSample(&gLanDiagBeaconLogCount, 60))
                {
                    LogUg2LanBeaconDiag("bridge-forward", response.data(), received, true);
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
                    std::cout << "NFSLAN: Same-machine LAN bridge active on UDP " << kLanDiscoveryPort << ".\n";
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
                    std::cout << "NFSLAN: WARNING - no LAN discovery replies seen on loopback yet.\n";
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

void LogLanDiscoveryPortDiagnostic()
{
    try
    {
        WSASession wsaSession;
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET)
        {
            std::cout << "NFSLAN: WARNING - UDP 9999 diagnostic socket creation failed (WSA error "
                      << WSAGetLastError() << ").\n";
            return;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<u_short>(kLanDiscoveryPort));
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        const int bindResult = bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (bindResult == 0)
        {
            std::cout << "NFSLAN: UDP 9999 appears free for local client discovery bind.\n";
        }
        else
        {
            const int err = WSAGetLastError();
            if (err == WSAEADDRINUSE)
            {
                std::cout << "NFSLAN: UDP 9999 is already in use (expected when server discovery socket is active).\n";
            }
            else
            {
                std::cout << "NFSLAN: UDP 9999 diagnostic bind failed (WSA error " << err << ").\n";
            }
        }

        closesocket(sock);
    }
    catch (const std::exception& ex)
    {
        std::cout << "NFSLAN: WARNING - UDP 9999 diagnostic failed: " << ex.what() << '\n';
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
        << "  -n              Disable binary patching\n"
        << "  --same-machine  Force same-PC host mode (sets FORCE_LOCAL and addr fixups)\n"
        << "  --local-host    Alias for --same-machine\n"
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
            options.disablePatching = true;
        }
        else if (arg == "--same-machine" || arg == "--local-host")
        {
            options.sameMachineMode = true;
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

    bool changed = false;
    std::cout << "NFSLAN: Detected server profile: " << (underground2Server ? "Underground 2" : "Most Wanted") << '\n';

    const std::string lobbyIdentDefault = underground2Server ? "NFSU2NA" : "NFSMWNA";
    if (underground2Server)
    {
        MigrateLegacyConfigValue(&configText, "LOBBY_IDENT", "NFSU", lobbyIdentDefault, &changed);
        MigrateLegacyConfigValue(&configText, "LOBBY", "NFSU", lobbyIdentDefault, &changed);
        EnsureConfigValue(&configText, "LOBBY_IDENT", lobbyIdentDefault, &changed);
        EnsureConfigValue(&configText, "LOBBY", lobbyIdentDefault, &changed);
    }
    else
    {
        MigrateLegacyConfigValue(&configText, "LOBBY_IDENT", "NFSMW", lobbyIdentDefault, &changed);
        MigrateLegacyConfigValue(&configText, "LOBBY", "NFSMW", lobbyIdentDefault, &changed);
        EnsureConfigValue(&configText, "LOBBY_IDENT", lobbyIdentDefault, &changed);
        EnsureConfigValue(&configText, "LOBBY", lobbyIdentDefault, &changed);
    }

    const std::string portValue = EnsureConfigValue(&configText, "PORT", "9900", &changed);
    std::string addrValue = EnsureConfigValue(&configText, "ADDR", "0.0.0.0", &changed);

    if (options.sameMachineMode)
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

    if (!underground2Server)
    {
        const auto currentFixups = GetConfigValue(configText, "ENABLE_GAME_ADDR_FIXUPS");
        if (!currentFixups.has_value())
        {
            configText = UpsertConfigValue(configText, "ENABLE_GAME_ADDR_FIXUPS", "1");
            changed = true;
            std::cout << "NFSLAN: Added ENABLE_GAME_ADDR_FIXUPS=1 (recommended for MW).\n";
        }

        if (options.sameMachineMode && !IsTruthy(GetConfigValue(configText, "ENABLE_GAME_ADDR_FIXUPS").value_or("0")))
        {
            configText = UpsertConfigValue(configText, "ENABLE_GAME_ADDR_FIXUPS", "1");
            changed = true;
            std::cout << "NFSLAN: Same-machine mode enabled -> ENABLE_GAME_ADDR_FIXUPS=1\n";
        }
    }

    if (underground2Server)
    {
        for (const std::string& key : { std::string("MPORT"), std::string("RPORT"), std::string("APORT") })
        {
            EnsureMirroredKey(&configText, key, portValue, &changed);
        }
        for (const std::string& key : { std::string("MADDR"), std::string("RADDR"), std::string("AADDR") })
        {
            EnsureMirroredKey(&configText, key, addrValue, &changed);
        }
    }
    else
    {
        for (const std::string& key : { std::string("APORT"), std::string("CPORT") })
        {
            EnsureMirroredKey(&configText, key, portValue, &changed);
        }
        for (const std::string& key : { std::string("AADDR"), std::string("CADDR") })
        {
            EnsureMirroredKey(&configText, key, addrValue, &changed);
        }
    }

    const auto cfg = [&](const std::string& key) -> std::string
    {
        return TrimAscii(GetConfigValue(configText, key).value_or(""));
    };

    std::cout << "NFSLAN: Effective ADDR/PORT: " << cfg("ADDR") << ":" << cfg("PORT") << '\n';
    std::cout << "NFSLAN: Effective lobby ident: LOBBY_IDENT=" << cfg("LOBBY_IDENT")
              << " LOBBY=" << cfg("LOBBY") << '\n';
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

    const auto configuredGamefileEntry = GetConfigValue(configText, "GAMEFILE");
    std::string configuredGamefile = TrimAscii(configuredGamefileEntry.value_or("gamefile.bin"));
    if (configuredGamefile.empty())
    {
        configuredGamefile = "gamefile.bin";
    }

    const auto compatibleGamefile = ResolveCompatibleGameReportFile(configuredGamefile);
    if (compatibleGamefile.has_value())
    {
        if (!configuredGamefileEntry.has_value() || !EqualsIgnoreCase(configuredGamefile, *compatibleGamefile))
        {
            configText = UpsertConfigValue(configText, "GAMEFILE", *compatibleGamefile);
            changed = true;
            std::cout << "NFSLAN: Using GAMEFILE=" << *compatibleGamefile << '\n';
        }
    }
    else if (!std::filesystem::exists(std::filesystem::path(configuredGamefile)))
    {
        std::cout << "NFSLAN: WARNING - GAMEFILE '" << configuredGamefile
                  << "' not found. Missing game report data may cause tier/points/race-mode issues.\n";
    }
    else
    {
        std::string details;
        IsCompatibleGameReportFile(configuredGamefile, &details);
        std::cout << "NFSLAN: WARNING - GAMEFILE '" << configuredGamefile << "' is incompatible (" << details
                  << "), expected " << FormatGameReportHeader(kGameReportIdent, kGameReportVersion) << ".\n";
    }

    if (addrValue == "0.0.0.0")
    {
        std::cout << "NFSLAN: NOTE - ADDR=0.0.0.0 is fine for local bind, but internet clients need a public endpoint.\n";
    }
    else if (!options.sameMachineMode && LooksPrivateOrNonRoutableIpv4(addrValue))
    {
        std::cout << "NFSLAN: NOTE - ADDR=" << addrValue
                  << " is private/non-routable; remote internet players will not reach this directly.\n";
    }
    else if (!options.sameMachineMode && addrValue.find("%%bind(") != std::string::npos)
    {
        std::cout
            << "NFSLAN: NOTE - ADDR uses %%bind(...), which usually resolves to a LAN IP. "
            << "Use a public IP/DNS for internet hosting.\n";
    }

    if (options.sameMachineMode && portValue == "9900")
    {
        std::cout << "NFSLAN: NOTE - Same-machine mode with PORT=9900 can still conflict on some client patches. "
                     "Try a different server PORT if local client cannot see/join.\n";
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
    if (IsServerRunning())
    {
        std::cout << "NFSLAN: Stopping server...\n";
        StopServer();
    }
    else
    {
        std::cout << "NFSLAN: WARNING - server was NOT running during interrupt!\n";
    }
    exit(signum);
}

int NFSLANWorkerMain(int argc, char* argv[])
{
    std::cout << "NFS LAN Server Launcher\n";
    std::cout << "NFSLAN: Build tag " << kBuildTag << '\n';

    WorkerLaunchOptions options;
    if (!ParseWorkerLaunchOptions(argc, argv, &options))
    {
        return -1;
    }

    bDisablePatching = options.disablePatching;
    gSameMachineModeEnabled.store(options.sameMachineMode);
    gLoopbackMirrorAnnounced.store(false);
    if (options.sameMachineMode)
    {
        std::cout << "NFSLAN: Same-machine mode enabled.\n";
    }
    if (options.lanDiag)
    {
        std::cout << "NFSLAN: Deep LAN diagnostics requested from CLI.\n";
    }

    if (!std::filesystem::exists("server.dll"))
    {
        std::cerr << "ERROR: server.dll not found! Please place the server.dll from the game in this executable's path!\n";
        return -1;
    }

    HMODULE serverdll = LoadLibraryA("server");
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

    const bool underground2Server = bIsUnderground2Server((uintptr_t)serverdll);
    WorkerResolvedSettings resolved{};
    bool sendToHookInstalled = false;

    if (!ApplyServerConfigCompatibility(options, underground2Server, &resolved))
    {
        return -1;
    }

    gLanDiagEnabled.store(resolved.lanDiag);
    gLanDiagBeaconLogCount.store(0);

    if (underground2Server)
    {
        sendToHookInstalled = InstallSendToHook(serverdll);
        if (!sendToHookInstalled)
        {
            std::cout << "NFSLAN: WARNING - UG2 sendto hook unavailable; using bridge-level beacon diagnostics only.\n";
        }
    }

    if (!bDisablePatching)
    {
        std::cout << "NFSLAN: Patching the server to work on any network...\n";

        if (underground2Server)
            PatchServerUG2((uintptr_t)serverdll);
        else
            PatchServerMW((uintptr_t)serverdll);
    }

    signal(SIGINT, SigInterruptHandler);
    signal(SIGTERM, SigInterruptHandler);

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

    if (options.sameMachineMode)
    {
        LogLanDiscoveryPortDiagnostic();
    }

    const bool useLanBridge =
        options.sameMachineMode && (!underground2Server || !sendToHookInstalled);
    if (options.sameMachineMode && underground2Server && sendToHookInstalled)
    {
        std::cout << "NFSLAN: Same-machine UG2 discovery uses sendto loopback mirror (bridge disabled).\n";
    }
    StartLanDiscoveryLoopbackBridge(useLanBridge);

    std::cout << "NFSLAN: Server started. To stop gracefully, send CTRL+C to the console\n";
    while (IsServerRunning()) { Sleep(1); }
    StopLanDiscoveryLoopbackBridge();
    gSameMachineModeEnabled.store(false);
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
