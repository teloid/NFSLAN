#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commdlg.h>
#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace
{

constexpr wchar_t kBuildTag[] = L"2026-02-11-u2-self-filter-patcher-1";

// Decompiled U2 speed2.exe globals/offsets (base image 0x00400000):
// DAT_008b7e28 -> LAN discovery manager singleton pointer.
constexpr std::uintptr_t kLanManagerGlobalRva = 0x004B7E28;
constexpr std::uintptr_t kLanManagerEntriesStartOffset = 0x28;
constexpr std::uintptr_t kLanManagerEntriesEndOffset = 0x2C;
constexpr std::uintptr_t kLanEntryActiveOffset = 0x28;
constexpr std::uintptr_t kLanEntryReadyOffset = 0x194;
constexpr std::uintptr_t kLanEntrySelfFlagOffset = 0x19C;
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
};

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
        if (!readRemote(process, entry + kLanEntryActiveOffset, &active) || active == 0)
        {
            continue;
        }
        ++info.activeCount;

        std::uint32_t ready = 0;
        if (readRemote(process, entry + kLanEntryReadyOffset, &ready) && ready != 0)
        {
            ++info.readyCount;
        }

        std::uint32_t selfFlag = 0;
        if (!readRemote(process, entry + kLanEntrySelfFlagOffset, &selfFlag))
        {
            continue;
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
    return true;
}

void printUsage()
{
    std::wcout
        << L"NFSLAN U2 self-filter patch launcher\n"
        << L"Build tag: " << kBuildTag << L"\n\n"
        << L"Usage:\n"
        << L"  NFSLAN-U2-Patcher.exe [path-to-speed2.exe] [game args...]\n\n"
        << L"If no path is provided, a file picker opens.\n"
        << L"This launcher keeps running while the game runs.\n";
}

} // namespace

int wmain(int argc, wchar_t* argv[])
{
    if (argc > 1)
    {
        const std::wstring first = trim(argv[1]);
        if (first == L"--help" || first == L"-h" || first == L"/?")
        {
            printUsage();
            return 0;
        }
    }

    std::wstring gameExe;
    std::vector<std::wstring> gameArgs;

    if (argc > 1 && argv[1] && argv[1][0] != L'-')
    {
        gameExe = argv[1];
        for (int i = 2; i < argc; ++i)
        {
            gameArgs.emplace_back(argv[i]);
        }
    }
    else
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

    std::uint64_t totalCleared = 0;
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
                       << L".";
                logLine(status.str());
            }
        }
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    logLine(L"Game exited with code " + std::to_wstring(exitCode) + L".");
    logLine(L"Final total cleared self-filter flags: " + std::to_wstring(totalCleared) + L".");

    CloseHandle(pi.hProcess);
    return 0;
}
