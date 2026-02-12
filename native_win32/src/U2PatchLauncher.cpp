#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commdlg.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{

constexpr wchar_t kBuildTag[] = L"2026-02-12-u2-force-visible-4";

// Decompiled U2 speed2.exe globals/offsets (base image 0x00400000):
// DAT_008b7e28 -> LAN discovery manager singleton pointer.
constexpr std::uintptr_t kLanManagerGlobalRva = 0x004B7E28;
constexpr std::uintptr_t kLanManagerEntriesStartOffset = 0x28;
constexpr std::uintptr_t kLanManagerEntriesEndOffset = 0x2C;
constexpr std::uintptr_t kLanManagerUpdateCounterOffset = 0x4C;
constexpr std::uintptr_t kLanEntryIdentOffset = 0x08;
constexpr std::uintptr_t kLanEntryActiveOffset = 0x28;
constexpr std::uintptr_t kLanEntryNameOffset = 0x28;
constexpr std::uintptr_t kLanEntryStatsOffset = 0x48;
constexpr std::uintptr_t kLanEntryExpiryOffset = 0x180;
constexpr std::uintptr_t kLanEntrySockAddrOffset = 0x184;
constexpr std::uintptr_t kLanEntryAddrAOffset = 0x194;
constexpr std::uintptr_t kLanEntryAddrBOffset = 0x198;
constexpr std::uintptr_t kLanEntryReadyOffset = 0x194;
constexpr std::uintptr_t kLanEntrySelfFlagOffset = 0x19C;
constexpr std::uintptr_t kLanEntryTransportOffset = 0x108;
constexpr std::uintptr_t kLanEntryStride = 0x1A4;
constexpr std::uint32_t kMaxReasonableEntries = 1024;
constexpr std::uintptr_t kLegacyImageBase = 0x00400000;

struct PatchCycleInfo
{
    std::uint32_t manager = 0;
    std::uint32_t entryCount = 0;
    std::uint32_t activeCount = 0;
    std::uint32_t readyCount = 0;
    std::uint32_t selfFlagCount = 0;
    std::uint32_t sampleAddrA = 0;
    std::uint32_t sampleAddrB = 0;
};

std::wstring trim(const std::wstring& input);

bool tryParseIntRange(const std::wstring& text, int minValue, int maxValue, int* valueOut)
{
    if (!valueOut)
    {
        return false;
    }

    const std::wstring trimmed = trim(text);
    if (trimmed.empty())
    {
        return false;
    }

    wchar_t* end = nullptr;
    const long value = wcstol(trimmed.c_str(), &end, 10);
    if (!end || *end != L'\0')
    {
        return false;
    }
    if (value < minValue || value > maxValue)
    {
        return false;
    }

    *valueOut = static_cast<int>(value);
    return true;
}

bool tryParseIpv4StoredOrder(const std::wstring& text, std::uint32_t* valueOut)
{
    if (!valueOut)
    {
        return false;
    }

    const std::wstring trimmed = trim(text);
    if (trimmed.empty())
    {
        return false;
    }

    int a = -1;
    int b = -1;
    int c = -1;
    int d = -1;
    wchar_t trailing = 0;
    const int readCount = swscanf_s(trimmed.c_str(), L"%d.%d.%d.%d%c", &a, &b, &c, &d, &trailing, 1);
    if (readCount != 4)
    {
        return false;
    }
    if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255)
    {
        return false;
    }

    // Lan manager expects IPv4 in network-order integer form (A.B.C.D => 0xAABBCCDD).
    *valueOut =
        (static_cast<std::uint32_t>(a) << 24)
        | (static_cast<std::uint32_t>(b) << 16)
        | (static_cast<std::uint32_t>(c) << 8)
        | static_cast<std::uint32_t>(d);
    return true;
}

std::wstring formatIpv4StoredOrder(std::uint32_t value)
{
    std::wstringstream stream;
    stream << ((value >> 24) & 0xFF) << L"."
           << ((value >> 16) & 0xFF) << L"."
           << ((value >> 8) & 0xFF) << L"."
           << (value & 0xFF);
    return stream.str();
}

std::string sanitizeAscii(const std::wstring& text, size_t maxBytes)
{
    std::string output;
    if (maxBytes == 0)
    {
        return output;
    }

    output.reserve((std::min)(maxBytes, text.size()));
    for (wchar_t ch : text)
    {
        if (output.size() + 1 >= maxBytes)
        {
            break;
        }

        if (ch >= 32 && ch <= 126)
        {
            output.push_back(static_cast<char>(ch));
        }
        else
        {
            output.push_back('_');
        }
    }

    return output;
}

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

void logLine(const std::wstring& text)
{
    std::wcout << L"[" << nowTimestamp() << L"] " << text << L"\n";
}

std::wstring formatWin32Error(DWORD errorCode)
{
    LPWSTR message = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD size = FormatMessageW(
        flags,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&message),
        0,
        nullptr);

    std::wstring result;
    if (size > 0 && message)
    {
        result.assign(message, message + size);
        while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n'))
        {
            result.pop_back();
        }
    }
    else
    {
        result = L"(unknown error)";
    }

    if (message)
    {
        LocalFree(message);
    }
    return result;
}

std::wstring quoteArg(const std::wstring& arg)
{
    if (arg.empty())
    {
        return L"\"\"";
    }

    bool needsQuotes = false;
    for (wchar_t ch : arg)
    {
        if (iswspace(ch) || ch == L'"')
        {
            needsQuotes = true;
            break;
        }
    }
    if (!needsQuotes)
    {
        return arg;
    }

    std::wstring escaped;
    escaped.reserve(arg.size() + 8);
    escaped.push_back(L'"');
    for (wchar_t ch : arg)
    {
        if (ch == L'"')
        {
            escaped.push_back(L'\\');
            escaped.push_back(L'"');
        }
        else
        {
            escaped.push_back(ch);
        }
    }
    escaped.push_back(L'"');
    return escaped;
}

std::wstring browseForGameExe()
{
    wchar_t filePath[MAX_PATH] = {};

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    const wchar_t filter[] = L"NFSU2 executable (speed2.exe)\0speed2.exe\0Executable files (*.exe)\0*.exe\0All files\0*.*\0";
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = L"Select NFSU2 speed2.exe";

    if (!GetOpenFileNameW(&ofn))
    {
        return L"";
    }

    return std::wstring(filePath);
}

template <typename T>
bool readRemote(HANDLE process, std::uintptr_t address, T* out)
{
    SIZE_T readBytes = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), out, sizeof(T), &readBytes)
        && readBytes == sizeof(T);
}

template <typename T>
bool writeRemote(HANDLE process, std::uintptr_t address, const T& value)
{
    SIZE_T writtenBytes = 0;
    return WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), &value, sizeof(T), &writtenBytes)
        && writtenBytes == sizeof(T);
}

bool writeRemoteBytes(HANDLE process, std::uintptr_t address, const void* data, SIZE_T bytes)
{
    if (!data || bytes == 0)
    {
        return false;
    }

    SIZE_T writtenBytes = 0;
    return WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), data, bytes, &writtenBytes)
        && writtenBytes == bytes;
}

bool writeRemoteZeroedString(
    HANDLE process,
    std::uintptr_t address,
    SIZE_T maxBytes,
    const std::string& value)
{
    if (maxBytes == 0)
    {
        return false;
    }

    std::vector<char> buffer(maxBytes, '\0');
    const SIZE_T copyBytes = (std::min)(maxBytes - 1, static_cast<SIZE_T>(value.size()));
    if (copyBytes > 0)
    {
        std::memcpy(buffer.data(), value.data(), copyBytes);
    }
    return writeRemoteBytes(process, address, buffer.data(), buffer.size());
}

std::optional<std::uintptr_t> queryMainModuleBase(DWORD pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return std::nullopt;
    }

    MODULEENTRY32W module{};
    module.dwSize = sizeof(module);
    if (!Module32FirstW(snapshot, &module))
    {
        CloseHandle(snapshot);
        return std::nullopt;
    }

    std::uintptr_t base = reinterpret_cast<std::uintptr_t>(module.modBaseAddr);
    CloseHandle(snapshot);
    return base;
}

bool patchSelfFilterFlags(HANDLE process, std::uintptr_t imageBase, std::uint64_t* clearedOut, PatchCycleInfo* infoOut)
{
    PatchCycleInfo info{};
    std::uint32_t manager = 0;
    if (!readRemote(process, imageBase + kLanManagerGlobalRva, &manager))
    {
        return false;
    }
    info.manager = manager;
    if (manager == 0)
    {
        if (infoOut)
        {
            *infoOut = info;
        }
        return true;
    }

    std::uint32_t entriesStart = 0;
    std::uint32_t entriesEnd = 0;
    if (!readRemote(process, static_cast<std::uintptr_t>(manager) + kLanManagerEntriesStartOffset, &entriesStart)
        || !readRemote(process, static_cast<std::uintptr_t>(manager) + kLanManagerEntriesEndOffset, &entriesEnd))
    {
        return true;
    }

    if (entriesEnd <= entriesStart)
    {
        return true;
    }

    const std::uint32_t span = entriesEnd - entriesStart;
    if ((span % static_cast<std::uint32_t>(kLanEntryStride)) != 0)
    {
        return true;
    }

    const std::uint32_t entryCount = span / static_cast<std::uint32_t>(kLanEntryStride);
    if (entryCount == 0 || entryCount > kMaxReasonableEntries)
    {
        info.entryCount = entryCount;
        if (infoOut)
        {
            *infoOut = info;
        }
        return true;
    }
    info.entryCount = entryCount;

    std::uint64_t cleared = 0;
    for (std::uint32_t i = 0; i < entryCount; ++i)
    {
        const std::uintptr_t entry = static_cast<std::uintptr_t>(entriesStart) + i * kLanEntryStride;

        std::uint8_t active = 0;
        if (!readRemote(process, entry + kLanEntryActiveOffset, &active))
        {
            continue;
        }
        if (active != 0)
        {
            ++info.activeCount;
        }

        std::uint32_t ready = 0;
        if (!readRemote(process, entry + kLanEntryReadyOffset, &ready))
        {
            continue;
        }
        if (ready != 0)
        {
            ++info.readyCount;
            if (info.sampleAddrA == 0)
            {
                info.sampleAddrA = ready;
            }
        }

        std::uint32_t selfFlag = 0;
        if (!readRemote(process, entry + kLanEntrySelfFlagOffset, &selfFlag))
        {
            continue;
        }

        if (info.sampleAddrB == 0)
        {
            std::uint32_t addrB = 0;
            if (readRemote(process, entry + kLanEntryAddrBOffset, &addrB) && addrB != 0)
            {
                info.sampleAddrB = addrB;
            }
        }

        if (selfFlag != 0)
        {
            ++info.selfFlagCount;
            const std::uint32_t zero = 0;
            if (writeRemote(process, entry + kLanEntrySelfFlagOffset, zero))
            {
                ++cleared;
            }
        }
    }

    if (clearedOut)
    {
        *clearedOut = cleared;
    }
    if (infoOut)
    {
        *infoOut = info;
    }

    if (cleared > 0)
    {
        std::uint32_t updateCounter = 0;
        if (readRemote(process, static_cast<std::uintptr_t>(manager) + kLanManagerUpdateCounterOffset, &updateCounter))
        {
            updateCounter += static_cast<std::uint32_t>(cleared);
            writeRemote(process, static_cast<std::uintptr_t>(manager) + kLanManagerUpdateCounterOffset, updateCounter);
        }
    }
    return true;
}

bool injectSyntheticLanEntry(
    HANDLE process,
    std::uint32_t manager,
    std::uint32_t entryCount,
    std::uint32_t preferredAddrA,
    std::uint32_t preferredAddrB,
    const std::string& injectedName,
    int injectedPort,
    std::uint64_t* injectedOut)
{
    if (!manager || entryCount == 0 || entryCount > kMaxReasonableEntries)
    {
        if (injectedOut)
        {
            *injectedOut = 0;
        }
        return true;
    }

    std::uint32_t entriesStart = 0;
    std::uint32_t entriesEnd = 0;
    if (!readRemote(process, static_cast<std::uintptr_t>(manager) + kLanManagerEntriesStartOffset, &entriesStart)
        || !readRemote(process, static_cast<std::uintptr_t>(manager) + kLanManagerEntriesEndOffset, &entriesEnd))
    {
        return false;
    }
    if (entriesEnd <= entriesStart)
    {
        if (injectedOut)
        {
            *injectedOut = 0;
        }
        return true;
    }

    std::uint32_t selectedIndex = 0;
    std::uint32_t selectedAddrA = preferredAddrA;
    std::uint32_t selectedAddrB = preferredAddrB;
    bool selected = false;
    bool hasRealU2Entry = false;
    std::uintptr_t realU2Entry = 0;

    for (std::uint32_t i = 0; i < entryCount; ++i)
    {
        const std::uintptr_t candidate = static_cast<std::uintptr_t>(entriesStart) + i * kLanEntryStride;
        std::uint8_t active = 0;
        if (!readRemote(process, candidate + kLanEntryActiveOffset, &active))
        {
            continue;
        }
        if (active == 0)
        {
            continue;
        }

        std::array<char, 8> ident{};
        if (!readRemote(process, candidate + kLanEntryIdentOffset, &ident))
        {
            continue;
        }

        std::uint32_t addrA = 0;
        std::uint32_t addrB = 0;
        std::uint32_t ready = 0;
        readRemote(process, candidate + kLanEntryAddrAOffset, &addrA);
        readRemote(process, candidate + kLanEntryAddrBOffset, &addrB);
        readRemote(process, candidate + kLanEntryReadyOffset, &ready);

        if (!selected && (ready != 0 || addrA != 0 || addrB != 0))
        {
            selected = true;
            selectedIndex = i;
            if (selectedAddrA == 0)
            {
                selectedAddrA = (addrA != 0) ? addrA : ready;
            }
            if (selectedAddrB == 0)
            {
                selectedAddrB = addrB;
            }
        }

        if (std::memcmp(ident.data(), "NFSU2NA", 7) == 0)
        {
            hasRealU2Entry = true;
            realU2Entry = candidate;
            selected = true;
            selectedIndex = i;
            if (selectedAddrA == 0)
            {
                selectedAddrA = (addrA != 0) ? addrA : ready;
            }
            if (selectedAddrB == 0)
            {
                selectedAddrB = addrB;
            }
            break;
        }
    }

    // Keep discovered rows untouched. If the game already has a U2 row, avoid rewriting
    // unknown fields that are needed for stable join behavior.
    if (hasRealU2Entry)
    {
        std::uint32_t selfFlag = 0;
        if (readRemote(process, realU2Entry + kLanEntrySelfFlagOffset, &selfFlag) && selfFlag != 0)
        {
            const std::uint32_t zero = 0;
            writeRemote(process, realU2Entry + kLanEntrySelfFlagOffset, zero);
        }

        if (injectedOut)
        {
            *injectedOut = 0;
        }
        return true;
    }

    // Do not synthesize from an uninitialized slot. That can create entries that
    // are visible in UI but do not represent a connectable host.
    if (!selected)
    {
        if (injectedOut)
        {
            *injectedOut = 0;
        }
        return true;
    }

    const std::uintptr_t entry = static_cast<std::uintptr_t>(entriesStart) + selectedIndex * kLanEntryStride;

    const std::array<std::uint8_t, 4> header = {{'g', 'E', 'A', 0x03}};
    if (!writeRemoteBytes(process, entry, header.data(), header.size()))
    {
        return false;
    }

    const std::string ident = "NFSU2NA";
    const std::string name = injectedName.empty() ? "Test Server" : injectedName;
    const int clampedPort = (std::max)(1, (std::min)(65535, injectedPort));
    // Match stock-like dedicated-server beacon formatting.
    const std::string stats = std::to_string(clampedPort) + "|0";
    const std::string transport = "TCP:~1:1024\tUDP:~1:1024";

    if (!writeRemoteZeroedString(process, entry + kLanEntryIdentOffset, 8, ident)
        || !writeRemoteZeroedString(process, entry + kLanEntryNameOffset, 0x20, name)
        || !writeRemoteZeroedString(process, entry + kLanEntryStatsOffset, 0xC0, stats)
        || !writeRemoteZeroedString(process, entry + kLanEntryTransportOffset, 0x78, transport))
    {
        return false;
    }

    const std::uint32_t expiry = GetTickCount() + 30000;
    const std::uint32_t loopbackNetworkOrder = 0x7F000001; // 127.0.0.1 in network-order integer form
    const std::uint32_t addrA = selectedAddrA != 0 ? selectedAddrA : loopbackNetworkOrder;
    const std::uint32_t addrB = selectedAddrB != 0 ? selectedAddrB : addrA;
    const std::uint32_t selfFlag = 0;
    if (!writeRemote(process, entry + kLanEntryExpiryOffset, expiry)
        || !writeRemote(process, entry + kLanEntryAddrAOffset, addrA)
        || !writeRemote(process, entry + kLanEntryAddrBOffset, addrB)
        || !writeRemote(process, entry + kLanEntrySelfFlagOffset, selfFlag))
    {
        return false;
    }

    std::array<std::uint8_t, 16> fakeSockAddr{};
    fakeSockAddr[0] = 0x02; // AF_INET little-endian
    fakeSockAddr[1] = 0x00;
    fakeSockAddr[2] = static_cast<std::uint8_t>((clampedPort >> 8) & 0xFF); // port big-endian
    fakeSockAddr[3] = static_cast<std::uint8_t>(clampedPort & 0xFF);
    fakeSockAddr[4] = static_cast<std::uint8_t>((addrA >> 24) & 0xFF);
    fakeSockAddr[5] = static_cast<std::uint8_t>((addrA >> 16) & 0xFF);
    fakeSockAddr[6] = static_cast<std::uint8_t>((addrA >> 8) & 0xFF);
    fakeSockAddr[7] = static_cast<std::uint8_t>(addrA & 0xFF);
    if (!writeRemoteBytes(process, entry + kLanEntrySockAddrOffset, fakeSockAddr.data(), fakeSockAddr.size()))
    {
        return false;
    }

    std::uint32_t updateCounter = 0;
    if (readRemote(process, static_cast<std::uintptr_t>(manager) + kLanManagerUpdateCounterOffset, &updateCounter))
    {
        ++updateCounter;
        writeRemote(process, static_cast<std::uintptr_t>(manager) + kLanManagerUpdateCounterOffset, updateCounter);
    }

    if (injectedOut)
    {
        *injectedOut = 1;
    }
    return true;
}

void printUsage()
{
    std::wcout
        << L"NFSLAN U2 self-filter patch launcher\n"
        << L"Build tag: " << kBuildTag << L"\n\n"
        << L"Usage:\n"
        << L"  NFSLAN-U2-Patcher.exe [options] [path-to-speed2.exe] [game args...]\n\n"
        << L"Options:\n"
        << L"  --inject-name <name>   Visible LAN row name (default: Test Server)\n"
        << L"  --inject-port <port>   Visible LAN row port in stats field (default: 9900)\n"
        << L"  --inject-ip <ipv4>     Visible LAN row target IP (default: observed or 127.0.0.1)\n"
        << L"  --                     Treat all following args as game args\n\n"
        << L"If no path is provided, a file picker opens.\n"
        << L"This launcher keeps running while the game runs.\n";
}

} // namespace

int wmain(int argc, wchar_t* argv[])
{
    std::wstring gameExe;
    std::vector<std::wstring> gameArgs;
    std::wstring injectName = L"Test Server";
    int injectPort = 9900;
    std::optional<std::uint32_t> injectAddrOverride;
    bool forceGameArgs = false;

    for (int i = 1; i < argc; ++i)
    {
        const std::wstring arg = trim(argv[i] ? argv[i] : L"");
        if (arg.empty())
        {
            continue;
        }

        if (!forceGameArgs && (arg == L"--help" || arg == L"-h" || arg == L"/?"))
        {
            printUsage();
            return 0;
        }

        if (!forceGameArgs && arg == L"--")
        {
            forceGameArgs = true;
            continue;
        }

        if (!forceGameArgs && arg == L"--inject-name")
        {
            if (i + 1 >= argc)
            {
                logLine(L"Missing value for --inject-name.");
                return 1;
            }
            injectName = argv[++i];
            continue;
        }

        if (!forceGameArgs && arg == L"--inject-port")
        {
            if (i + 1 >= argc)
            {
                logLine(L"Missing value for --inject-port.");
                return 1;
            }
            int parsedPort = 0;
            if (!tryParseIntRange(argv[++i], 1, 65535, &parsedPort))
            {
                logLine(L"Invalid --inject-port value. Expected 1..65535.");
                return 1;
            }
            injectPort = parsedPort;
            continue;
        }

        if (!forceGameArgs && arg == L"--inject-ip")
        {
            if (i + 1 >= argc)
            {
                logLine(L"Missing value for --inject-ip.");
                return 1;
            }
            std::uint32_t parsedIp = 0;
            if (!tryParseIpv4StoredOrder(argv[++i], &parsedIp))
            {
                logLine(L"Invalid --inject-ip value. Expected IPv4 like 127.0.0.1.");
                return 1;
            }
            injectAddrOverride = parsedIp;
            continue;
        }

        if (gameExe.empty())
        {
            gameExe = arg;
        }
        else
        {
            gameArgs.emplace_back(argv[i]);
            forceGameArgs = true;
        }
    }

    if (gameExe.empty())
    {
        gameExe = browseForGameExe();
        if (gameExe.empty())
        {
            logLine(L"No executable selected. Exiting.");
            return 1;
        }
    }

    const std::string injectNameAscii = sanitizeAscii(injectName, 0x20);

    const std::filesystem::path gamePath = std::filesystem::path(trim(gameExe));
    if (gamePath.empty() || !std::filesystem::exists(gamePath))
    {
        logLine(L"Game executable does not exist: " + gamePath.wstring());
        return 1;
    }

    std::wstring commandLine = quoteArg(gamePath.wstring());
    for (const std::wstring& arg : gameArgs)
    {
        commandLine += L" ";
        commandLine += quoteArg(arg);
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring mutableCommandLine = commandLine;
    mutableCommandLine.push_back(L'\0');

    const BOOL created = CreateProcessW(
        gamePath.wstring().c_str(),
        mutableCommandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        gamePath.parent_path().wstring().c_str(),
        &si,
        &pi);

    if (!created)
    {
        const DWORD err = GetLastError();
        logLine(
            L"Failed to start game process. Win32 error "
            + std::to_wstring(err)
            + L": "
            + formatWin32Error(err));
        return 1;
    }

    logLine(L"Build tag: " + std::wstring(kBuildTag));
    logLine(L"Launched game suspended: " + gamePath.wstring());

    std::optional<std::uintptr_t> imageBase;
    for (int i = 0; i < 100; ++i)
    {
        imageBase = queryMainModuleBase(pi.dwProcessId);
        if (imageBase.has_value() && *imageBase != 0)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    bool usingFallbackBase = false;
    if (!imageBase.has_value() || *imageBase == 0)
    {
        logLine(L"WARNING: could not resolve main module base before resume.");
        imageBase = kLegacyImageBase;
        usingFallbackBase = true;
        std::wstringstream fallbackMsg;
        fallbackMsg << L"Using legacy fallback base: 0x" << std::hex << *imageBase << std::dec
                    << L" (common for UG2 32-bit images).";
        logLine(fallbackMsg.str());
    }
    else
    {
        std::wstringstream msg;
        msg << L"Resolved module base: 0x" << std::hex << *imageBase << std::dec;
        logLine(msg.str());
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    pi.hThread = nullptr;

    logLine(L"Game resumed. Self-filter patch loop is active.");
    logLine(L"Patch offsets: manager=+0x4B7E28 entryStride=0x1A4 active=+0x28 ready=+0x194 self=+0x19C.");
    logLine(L"Force-visible mode: self-filter patching is active; synthetic row injection is fallback-only.");
    logLine(
        L"Injection target: name='"
        + std::wstring(injectNameAscii.begin(), injectNameAscii.end())
        + L"' stats='"
        + std::to_wstring(injectPort)
        + L"|0' addr="
        + (injectAddrOverride.has_value() ? formatIpv4StoredOrder(*injectAddrOverride) : L"<auto>")
        + L" (fallback synthetic row only)"
        + L".");

    std::uint64_t totalCleared = 0;
    std::uint64_t totalInjected = 0;
    auto lastSummary = std::chrono::steady_clock::now();
    bool postResumeBaseLogged = false;

    while (true)
    {
        const DWORD waitResult = WaitForSingleObject(pi.hProcess, 100);
        if (waitResult == WAIT_OBJECT_0)
        {
            break;
        }
        if (waitResult != WAIT_TIMEOUT)
        {
            const DWORD err = GetLastError();
            logLine(L"WaitForSingleObject failed: " + std::to_wstring(err) + L" (" + formatWin32Error(err) + L")");
            break;
        }

        if (!imageBase.has_value() || *imageBase == 0)
        {
            imageBase = queryMainModuleBase(pi.dwProcessId);
            if (imageBase.has_value() && *imageBase != 0 && !postResumeBaseLogged)
            {
                postResumeBaseLogged = true;
                std::wstringstream msg;
                msg << L"Resolved module base after resume: 0x" << std::hex << *imageBase << std::dec;
                logLine(msg.str());
            }
            continue;
        }

        if (usingFallbackBase)
        {
            const std::optional<std::uintptr_t> probedBase = queryMainModuleBase(pi.dwProcessId);
            if (probedBase.has_value() && *probedBase != 0)
            {
                usingFallbackBase = false;
                imageBase = probedBase;
                std::wstringstream msg;
                msg << L"Replaced fallback base with detected module base: 0x" << std::hex << *imageBase << std::dec;
                logLine(msg.str());
            }
        }

        std::uint64_t clearedThisCycle = 0;
        PatchCycleInfo cycleInfo{};
        if (!patchSelfFilterFlags(pi.hProcess, *imageBase, &clearedThisCycle, &cycleInfo))
        {
            logLine(L"ReadProcessMemory failed while patching. Stopping patch loop.");
            break;
        }

        std::uint64_t injectedThisCycle = 0;
        if (!injectSyntheticLanEntry(
                pi.hProcess,
                cycleInfo.manager,
                cycleInfo.entryCount,
                injectAddrOverride.value_or(cycleInfo.sampleAddrA),
                injectAddrOverride.value_or(cycleInfo.sampleAddrB),
                injectNameAscii,
                injectPort,
                &injectedThisCycle))
        {
            logLine(L"WriteProcessMemory failed while injecting synthetic LAN entry. Stopping patch loop.");
            break;
        }
        if (injectedThisCycle > 0)
        {
            totalInjected += injectedThisCycle;
        }

        if (clearedThisCycle > 0)
        {
            totalCleared += clearedThisCycle;
            logLine(
                L"Cleared "
                + std::to_wstring(clearedThisCycle)
                + L" self-filter flag(s) this cycle, total="
                + std::to_wstring(totalCleared)
                + L".");
        }
        else
        {
            const auto now = std::chrono::steady_clock::now();
            if (now - lastSummary >= std::chrono::seconds(5))
            {
                lastSummary = now;
                std::wstringstream status;
                status << L"Patch loop alive. base=0x" << std::hex << *imageBase << std::dec
                       << L" manager=0x" << std::hex << cycleInfo.manager << std::dec
                       << L" entries=" << cycleInfo.entryCount
                       << L" active=" << cycleInfo.activeCount
                       << L" ready=" << cycleInfo.readyCount
                       << L" self=" << cycleInfo.selfFlagCount
                       << L" totalCleared=" << totalCleared
                       << L" totalInjected=" << totalInjected
                       << L".";
                logLine(status.str());
            }
        }
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    logLine(L"Game exited with code " + std::to_wstring(exitCode) + L".");
    logLine(L"Final total cleared self-filter flags: " + std::to_wstring(totalCleared) + L".");
    logLine(L"Final total synthetic entries injected: " + std::to_wstring(totalInjected) + L".");

    CloseHandle(pi.hProcess);
    return 0;
}
