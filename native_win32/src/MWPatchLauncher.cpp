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

constexpr wchar_t kBuildTag[] = L"2026-02-12-mw-self-filter-1";
constexpr std::uintptr_t kLegacyImageBase = 0x00400000;

// Most Wanted LAN row layout is compatible with the U2 row fields we patch:
// row[0x08] = ident, row[0x19C] = self-filter flag.
constexpr std::uintptr_t kLanEntryIdentOffset = 0x08;
constexpr std::uintptr_t kLanEntrySelfFlagOffset = 0x19C;

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
    const wchar_t filter[] = L"NFSMW executable (speed.exe)\0speed.exe\0Executable files (*.exe)\0*.exe\0All files\0*.*\0";
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = L"Select NFSMW speed.exe";

    if (!GetOpenFileNameW(&ofn))
    {
        return L"";
    }

    return std::wstring(filePath);
}

template <typename T>
bool writeRemote(HANDLE process, std::uintptr_t address, const T& value)
{
    SIZE_T writtenBytes = 0;
    return WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), &value, sizeof(T), &writtenBytes)
        && writtenBytes == sizeof(T);
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

bool isCandidateIdent(const std::uint8_t* ptr, size_t available)
{
    if (!ptr || available < 5)
    {
        return false;
    }

    if (available >= 7 && std::memcmp(ptr, "NFSMWNA", 7) == 0)
    {
        return true;
    }

    if (std::memcmp(ptr, "NFSMW", 5) == 0)
    {
        return true;
    }

    return false;
}

bool isWritableUserPage(const MEMORY_BASIC_INFORMATION& mbi)
{
    if (mbi.State != MEM_COMMIT)
    {
        return false;
    }
    if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
    {
        return false;
    }
    if (mbi.Type != MEM_PRIVATE)
    {
        return false;
    }

    const DWORD p = mbi.Protect & 0xFF;
    return p == PAGE_READWRITE
        || p == PAGE_WRITECOPY
        || p == PAGE_EXECUTE_READWRITE
        || p == PAGE_EXECUTE_WRITECOPY;
}

bool scanAndPatchMwSelfFilter(
    HANDLE process,
    std::uint64_t* scannedRowsOut,
    std::uint64_t* clearedRowsOut)
{
    if (!scannedRowsOut || !clearedRowsOut)
    {
        return false;
    }

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    std::uint64_t scannedRows = 0;
    std::uint64_t clearedRows = 0;

    std::uintptr_t address = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const std::uintptr_t maxAddress = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

    while (address < maxAddress)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T queried = VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
        if (queried == 0)
        {
            break;
        }

        const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const SIZE_T regionSize = mbi.RegionSize;
        std::uintptr_t nextAddress = regionBase + regionSize;
        if (nextAddress <= address)
        {
            break;
        }

        if (isWritableUserPage(mbi) && regionSize > 0)
        {
            constexpr SIZE_T kChunkSize = 1 << 20; // 1 MiB
            std::vector<std::uint8_t> buffer(kChunkSize);

            for (SIZE_T chunkOffset = 0; chunkOffset < regionSize; chunkOffset += kChunkSize)
            {
                const SIZE_T bytesToRead = (std::min)(kChunkSize, regionSize - chunkOffset);
                SIZE_T readBytes = 0;
                if (!ReadProcessMemory(
                        process,
                        reinterpret_cast<LPCVOID>(regionBase + chunkOffset),
                        buffer.data(),
                        bytesToRead,
                        &readBytes)
                    || readBytes <= (kLanEntryIdentOffset + 8 + kLanEntrySelfFlagOffset + sizeof(std::uint32_t)))
                {
                    continue;
                }

                const size_t bytes = static_cast<size_t>(readBytes);
                for (size_t i = static_cast<size_t>(kLanEntryIdentOffset);
                     i + 8 < bytes;
                     ++i)
                {
                    if (!isCandidateIdent(buffer.data() + i, bytes - i))
                    {
                        continue;
                    }

                    const size_t rowOffset = i - static_cast<size_t>(kLanEntryIdentOffset);
                    if (rowOffset + kLanEntrySelfFlagOffset + sizeof(std::uint32_t) > bytes)
                    {
                        continue;
                    }

                    if (std::memcmp(buffer.data() + rowOffset, "gEA\x03", 4) != 0)
                    {
                        continue;
                    }

                    ++scannedRows;

                    std::uint32_t selfFlag = 0;
                    std::memcpy(
                        &selfFlag,
                        buffer.data() + rowOffset + static_cast<size_t>(kLanEntrySelfFlagOffset),
                        sizeof(selfFlag));
                    if (selfFlag == 0)
                    {
                        continue;
                    }

                    const std::uint32_t zero = 0;
                    const std::uintptr_t patchAddress =
                        regionBase + chunkOffset + rowOffset + static_cast<size_t>(kLanEntrySelfFlagOffset);
                    if (writeRemote(process, patchAddress, zero))
                    {
                        ++clearedRows;
                    }
                }
            }
        }

        address = nextAddress;
    }

    *scannedRowsOut = scannedRows;
    *clearedRowsOut = clearedRows;
    return true;
}

void printUsage()
{
    std::wcout
        << L"NFSLAN MW self-filter patch launcher\n"
        << L"Build tag: " << kBuildTag << L"\n\n"
        << L"Usage:\n"
        << L"  NFSLAN-MW-Patcher.exe [options] [path-to-speed.exe] [game args...]\n\n"
        << L"Options:\n"
        << L"  --inject-name <name>   Accepted for UI compatibility (currently informational)\n"
        << L"  --inject-port <port>   Accepted for UI compatibility (currently informational)\n"
        << L"  --inject-ip <ipv4>     Accepted for UI compatibility (currently informational)\n"
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
    std::wstring injectIp = L"127.0.0.1";
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
            injectIp = argv[++i];
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
    logLine(
        L"Injection compatibility args: name='"
        + injectName
        + L"' port="
        + std::to_wstring(injectPort)
        + L" ip="
        + injectIp
        + L" (MW patcher currently only clears self-filter flags).");

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

    if (!imageBase.has_value() || *imageBase == 0)
    {
        imageBase = kLegacyImageBase;
        std::wstringstream msg;
        msg << L"WARNING: module base lookup failed before resume, using fallback 0x"
            << std::hex << *imageBase << std::dec << L".";
        logLine(msg.str());
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

    logLine(L"Game resumed. MW self-filter patch scan loop is active.");

    std::uint64_t totalScannedRows = 0;
    std::uint64_t totalClearedRows = 0;
    auto lastScan = std::chrono::steady_clock::now() - std::chrono::seconds(5);
    auto lastSummary = std::chrono::steady_clock::now();

    while (true)
    {
        const DWORD waitResult = WaitForSingleObject(pi.hProcess, 120);
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

        const auto now = std::chrono::steady_clock::now();
        if (now - lastScan < std::chrono::seconds(1))
        {
            continue;
        }
        lastScan = now;

        std::uint64_t scannedThisCycle = 0;
        std::uint64_t clearedThisCycle = 0;
        if (!scanAndPatchMwSelfFilter(pi.hProcess, &scannedThisCycle, &clearedThisCycle))
        {
            logLine(L"MW scan failed unexpectedly. Continuing.");
            continue;
        }

        totalScannedRows += scannedThisCycle;
        totalClearedRows += clearedThisCycle;

        if (clearedThisCycle > 0)
        {
            logLine(
                L"Cleared "
                + std::to_wstring(clearedThisCycle)
                + L" MW self-filter flag(s) this cycle, total="
                + std::to_wstring(totalClearedRows)
                + L".");
        }
        else if (now - lastSummary >= std::chrono::seconds(5))
        {
            lastSummary = now;
            logLine(
                L"Patch loop alive. scannedRowsThisCycle="
                + std::to_wstring(scannedThisCycle)
                + L" totalScannedRows="
                + std::to_wstring(totalScannedRows)
                + L" totalCleared="
                + std::to_wstring(totalClearedRows)
                + L".");
        }
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    logLine(L"Game exited with code " + std::to_wstring(exitCode) + L".");
    logLine(L"Final scanned MW rows: " + std::to_wstring(totalScannedRows) + L".");
    logLine(L"Final cleared MW self-filter flags: " + std::to_wstring(totalClearedRows) + L".");

    CloseHandle(pi.hProcess);
    return 0;
}
