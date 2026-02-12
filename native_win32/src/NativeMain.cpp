#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#if defined(NFSLAN_NATIVE_EMBED_WORKER)
int NFSLANWorkerMain(int argc, char* argv[]);
#endif
#if defined(NFSLAN_NATIVE_EMBED_RELAY)
int NFSLANRelayMain(HINSTANCE instance, int showCommand);
#endif

namespace
{
constexpr wchar_t kWindowClassName[] = L"NFSLANNativeWin32Window";
constexpr UINT kWorkerPollTimerId = 100;
constexpr UINT WM_APP_LOG_CHUNK = WM_APP + 1;
constexpr wchar_t kUiBuildTag[] = L"2026-02-12-native-ui-clean-path-2";
constexpr int kGameProfileMostWanted = 0;
constexpr int kGameProfileUnderground2 = 1;

enum ControlId : int
{
    kIdGameCombo = 1000,
    kIdServerName,
    kIdServerDir,
    kIdBrowseServerDir,
    kIdWorkerPath,
    kIdBrowseWorker,
    kIdU2GameExe,
    kIdBrowseU2GameExe,
    kIdPort,
    kIdAddr,
    kIdU2StartMode,
    kIdEnableAddrFixups,
    kIdDisablePatching,
    kIdLoadConfig,
    kIdSaveConfig,
    kIdStart,
    kIdStartU2SamePc,
    kIdStop,
    kIdOpenU2Patcher,
    kIdConfigEditor,
    kIdLogView
};

struct AppState
{
    HWND window = nullptr;
    HWND gameCombo = nullptr;
    HWND serverNameEdit = nullptr;
    HWND serverDirEdit = nullptr;
    HWND workerPathEdit = nullptr;
    HWND u2GameExeEdit = nullptr;
    HWND portEdit = nullptr;
    HWND addrEdit = nullptr;
    HWND u2StartModeEdit = nullptr;
    HWND enableAddrFixupsCheck = nullptr;
    HWND disablePatchingCheck = nullptr;
    HWND configEditor = nullptr;
    HWND logView = nullptr;
    HWND runtimeSummaryLabel = nullptr;
    HWND startButton = nullptr;
    HWND startU2SamePcButton = nullptr;
    HWND stopButton = nullptr;
    HWND openU2PatcherButton = nullptr;
    HWND browseU2GameExeButton = nullptr;

    HANDLE processHandle = nullptr;
    HANDLE processThread = nullptr;
    HANDLE pipeRead = nullptr;
    HANDLE pipeWrite = nullptr;
    HANDLE logReaderThread = nullptr;

    bool running = false;
    int lastGameProfile = kGameProfileMostWanted;
    std::wstring exePath;
    std::wstring pendingLogLine;
};

AppState g_app;

bool launchU2PatcherForGame(
    const std::filesystem::path& gameExePath,
    const std::wstring& injectName,
    int injectPort,
    const std::wstring& injectIp);
std::wstring formatIpv4FromNetworkOrder(DWORD addressNetworkOrder);

bool tryGetPrimaryLanIpv4(std::wstring* ipOut)
{
    if (!ipOut)
    {
        return false;
    }

    ULONG bufferSize = 0;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG result = GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &bufferSize);
    if (result != ERROR_BUFFER_OVERFLOW || bufferSize == 0)
    {
        return false;
    }

    std::vector<BYTE> buffer(bufferSize);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    result = GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &bufferSize);
    if (result != NO_ERROR)
    {
        return false;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != nullptr; adapter = adapter->Next)
    {
        if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }

        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != nullptr;
             unicast = unicast->Next)
        {
            if (!unicast->Address.lpSockaddr || unicast->Address.lpSockaddr->sa_family != AF_INET)
            {
                continue;
            }

            auto* sin = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
            const std::wstring address = formatIpv4FromNetworkOrder(sin->sin_addr.s_addr);
            if (address.empty() || address == L"127.0.0.1" || address == L"0.0.0.0")
            {
                continue;
            }

            *ipOut = address;
            return true;
        }
    }

    return false;
}

std::wstring formatIpv4FromNetworkOrder(DWORD addressNetworkOrder)
{
    IN_ADDR address{};
    address.S_un.S_addr = addressNetworkOrder;
    wchar_t buffer[INET_ADDRSTRLEN] = {};
    const PCWSTR converted = InetNtopW(AF_INET, &address, buffer, INET_ADDRSTRLEN);
    if (!converted)
    {
        return L"";
    }
    return std::wstring(converted);
}

bool tryGetWorkerListeningIpForPort(DWORD workerPid, uint16_t port, std::wstring* ipOut)
{
    if (!ipOut || workerPid == 0 || port == 0)
    {
        return false;
    }

    DWORD tableSize = 0;
    DWORD result = GetExtendedTcpTable(
        nullptr,
        &tableSize,
        FALSE,
        AF_INET,
        TCP_TABLE_OWNER_PID_LISTENER,
        0);
    if (result != ERROR_INSUFFICIENT_BUFFER || tableSize == 0)
    {
        return false;
    }

    std::vector<BYTE> tableBuffer(tableSize);
    auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tableBuffer.data());
    result = GetExtendedTcpTable(
        table,
        &tableSize,
        FALSE,
        AF_INET,
        TCP_TABLE_OWNER_PID_LISTENER,
        0);
    if (result != NO_ERROR)
    {
        return false;
    }

    bool hasWildcard = false;
    std::wstring specificAddress;

    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        const MIB_TCPROW_OWNER_PID& row = table->table[i];
        if (row.dwOwningPid != workerPid)
        {
            continue;
        }

        const uint16_t rowPort = ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFF));
        if (rowPort != port)
        {
            continue;
        }

        const std::wstring localIp = formatIpv4FromNetworkOrder(row.dwLocalAddr);
        if (localIp.empty())
        {
            continue;
        }

        if (localIp == L"127.0.0.1")
        {
            *ipOut = localIp;
            return true;
        }

        if (localIp == L"0.0.0.0")
        {
            hasWildcard = true;
            continue;
        }

        specificAddress = localIp;
    }

    if (!specificAddress.empty())
    {
        *ipOut = specificAddress;
        return true;
    }

    if (hasWildcard)
    {
        std::wstring lanIp;
        if (tryGetPrimaryLanIpv4(&lanIp))
        {
            *ipOut = lanIp;
            return true;
        }

        *ipOut = L"127.0.0.1";
        return true;
    }

    return false;
}

bool tryResolveRunningWorkerInjectIpForPort(int port, std::wstring* ipOut)
{
    if (!ipOut || !g_app.running || !g_app.processHandle || port < 1 || port > 65535)
    {
        return false;
    }

    const DWORD workerPid = GetProcessId(g_app.processHandle);
    if (workerPid == 0)
    {
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
    while (std::chrono::steady_clock::now() < deadline)
    {
        std::wstring detectedIp;
        if (tryGetWorkerListeningIpForPort(workerPid, static_cast<uint16_t>(port), &detectedIp))
        {
            *ipOut = detectedIp;
            return true;
        }

        const DWORD workerState = WaitForSingleObject(g_app.processHandle, 0);
        if (workerState == WAIT_OBJECT_0 || workerState == WAIT_FAILED)
        {
            break;
        }

        Sleep(120);
    }

    return false;
}

std::wstring trim(const std::wstring& input)
{
    const auto first = input.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos)
    {
        return L"";
    }

    const auto last = input.find_last_not_of(L" \t\r\n");
    return input.substr(first, (last - first) + 1);
}

std::wstring toWide(const std::string& input, UINT codePage)
{
    if (input.empty())
    {
        return L"";
    }

    const int length = MultiByteToWideChar(codePage, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (length <= 0)
    {
        return L"";
    }

    std::wstring output;
    output.resize(static_cast<size_t>(length));

    MultiByteToWideChar(codePage, 0, input.data(), static_cast<int>(input.size()), output.data(), length);
    return output;
}

std::wstring decodeBytes(const std::string& input)
{
    std::wstring utf8 = toWide(input, CP_UTF8);
    if (!utf8.empty() || input.empty())
    {
        return utf8;
    }

    return toWide(input, CP_ACP);
}

std::string toUtf8(const std::wstring& input)
{
    if (input.empty())
    {
        return "";
    }

    const int length = WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0)
    {
        return "";
    }

    std::string output;
    output.resize(static_cast<size_t>(length));

    WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), output.data(), length, nullptr, nullptr);
    return output;
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

    return std::wstring(buffer);
}

void appendLogLine(const std::wstring& line)
{
    if (!g_app.logView)
    {
        return;
    }

    const std::wstring entry = L"[" + nowTimestamp() + L"] " + line + L"\r\n";
    appendRawToEdit(g_app.logView, entry);
}

void flushPendingLog()
{
    if (!g_app.pendingLogLine.empty())
    {
        appendLogLine(g_app.pendingLogLine);
        g_app.pendingLogLine.clear();
    }
}

void appendLogChunk(const std::wstring& chunk)
{
    std::wstring normalized;
    normalized.reserve(chunk.size());

    for (wchar_t ch : chunk)
    {
        if (ch != L'\r')
        {
            normalized.push_back(ch);
        }
    }

    for (wchar_t ch : normalized)
    {
        if (ch == L'\n')
        {
            if (!g_app.pendingLogLine.empty())
            {
                appendLogLine(g_app.pendingLogLine);
                g_app.pendingLogLine.clear();
            }
        }
        else
        {
            g_app.pendingLogLine.push_back(ch);
        }
    }
}

bool equalCaseInsensitive(const std::wstring& a, const std::wstring& b)
{
    if (a.size() != b.size())
    {
        return false;
    }

    for (size_t i = 0; i < a.size(); ++i)
    {
        if (towlower(a[i]) != towlower(b[i]))
        {
            return false;
        }
    }

    return true;
}

bool parseBoolConfigValue(const std::wstring& value, bool defaultValue)
{
    const std::wstring normalized = trim(value);
    if (normalized.empty())
    {
        return defaultValue;
    }

    if (equalCaseInsensitive(normalized, L"1")
        || equalCaseInsensitive(normalized, L"true")
        || equalCaseInsensitive(normalized, L"yes")
        || equalCaseInsensitive(normalized, L"on"))
    {
        return true;
    }

    if (equalCaseInsensitive(normalized, L"0")
        || equalCaseInsensitive(normalized, L"false")
        || equalCaseInsensitive(normalized, L"no")
        || equalCaseInsensitive(normalized, L"off"))
    {
        return false;
    }

    return defaultValue;
}

bool parseConfigLine(const std::wstring& line, std::wstring* keyOut, std::wstring* valueOut)
{
    std::wstring working = line;
    if (!working.empty() && working.back() == L'\r')
    {
        working.pop_back();
    }

    const std::wstring trimmed = trim(working);
    if (trimmed.empty() || trimmed[0] == L'#' || trimmed[0] == L';')
    {
        return false;
    }

    const auto equalsPos = trimmed.find(L'=');
    if (equalsPos == std::wstring::npos)
    {
        return false;
    }

    *keyOut = trim(trimmed.substr(0, equalsPos));
    *valueOut = trim(trimmed.substr(equalsPos + 1));
    return !keyOut->empty();
}

std::wstring getConfigValue(const std::wstring& configText, const std::wstring& key)
{
    std::wistringstream stream(configText);
    std::wstring line;

    while (std::getline(stream, line))
    {
        std::wstring foundKey;
        std::wstring foundValue;
        if (parseConfigLine(line, &foundKey, &foundValue) && equalCaseInsensitive(foundKey, key))
        {
            return foundValue;
        }
    }

    return L"";
}

std::wstring upsertConfigValue(const std::wstring& configText, const std::wstring& key, const std::wstring& value)
{
    std::wistringstream stream(configText);
    std::wstring line;
    std::vector<std::wstring> lines;
    bool replaced = false;

    while (std::getline(stream, line))
    {
        std::wstring foundKey;
        std::wstring foundValue;

        if (parseConfigLine(line, &foundKey, &foundValue) && equalCaseInsensitive(foundKey, key))
        {
            lines.push_back(key + L"=" + value);
            replaced = true;
        }
        else
        {
            if (!line.empty() && line.back() == L'\r')
            {
                line.pop_back();
            }
            lines.push_back(line);
        }
    }

    if (!replaced)
    {
        lines.push_back(key + L"=" + value);
    }

    std::wstring output;
    for (size_t i = 0; i < lines.size(); ++i)
    {
        output += lines[i];
        if (i + 1 < lines.size())
        {
            output += L"\r\n";
        }
    }

    return output;
}

std::filesystem::path exeDirectory()
{
    return std::filesystem::path(g_app.exePath).parent_path();
}

std::filesystem::path currentServerDirectory()
{
    return std::filesystem::path(trim(getWindowTextString(g_app.serverDirEdit)));
}

std::filesystem::path currentServerConfigPath()
{
    return currentServerDirectory() / "server.cfg";
}

std::filesystem::path settingsPath()
{
    return exeDirectory() / "NFSLAN-native.ini";
}

std::wstring normalizePathForCompare(const std::filesystem::path& path)
{
    if (path.empty())
    {
        return L"";
    }

    std::error_code ec;
    const std::filesystem::path canonical = std::filesystem::weakly_canonical(path, ec);
    std::wstring normalized = ec ? path.lexically_normal().wstring() : canonical.wstring();
    std::transform(
        normalized.begin(),
        normalized.end(),
        normalized.begin(),
        [](wchar_t ch)
        {
            return towlower(ch);
        });
    return normalized;
}

bool pathsLookEquivalent(const std::filesystem::path& a, const std::filesystem::path& b)
{
    if (a.empty() || b.empty())
    {
        return false;
    }

    return normalizePathForCompare(a) == normalizePathForCompare(b);
}

int currentGameProfileIndex()
{
    const LRESULT selectedIndex = SendMessageW(g_app.gameCombo, CB_GETCURSEL, 0, 0);
    if (selectedIndex == kGameProfileUnderground2)
    {
        return kGameProfileUnderground2;
    }

    return kGameProfileMostWanted;
}

std::wstring gameProfileDisplayName(int profileIndex)
{
    if (profileIndex == kGameProfileUnderground2)
    {
        return L"Underground 2";
    }

    return L"Most Wanted";
}

std::wstring defaultServerNameForProfile(int profileIndex)
{
    if (profileIndex == kGameProfileUnderground2)
    {
        return L"UG2 Dedicated Server";
    }

    return L"MW Dedicated Server";
}

std::wstring profileFolderName(int profileIndex)
{
    if (profileIndex == kGameProfileUnderground2)
    {
        return L"U2";
    }

    return L"MW";
}

std::filesystem::path defaultServerDirectoryForProfile(int profileIndex)
{
    const std::filesystem::path profileDir = exeDirectory() / profileFolderName(profileIndex);
    std::error_code ec;
    if (std::filesystem::is_directory(profileDir, ec))
    {
        return profileDir;
    }

    return exeDirectory();
}

std::wstring workerLaunchModeLabel()
{
#if defined(NFSLAN_NATIVE_EMBED_WORKER)
    return L"embedded worker (single EXE)";
#else
    return L"external worker executable";
#endif
}

std::wstring relayLaunchModeLabel()
{
#if defined(NFSLAN_NATIVE_EMBED_RELAY)
    return L"embedded relay UI";
#else
    return L"not embedded";
#endif
}

std::wstring runtimeSummaryText()
{
    return L"Build: " + std::wstring(kUiBuildTag) + L"  |  Worker: " + workerLaunchModeLabel()
        + L"  |  Relay: " + relayLaunchModeLabel();
}

void refreshRuntimeSummaryLabel()
{
    if (g_app.runtimeSummaryLabel)
    {
        setWindowTextString(g_app.runtimeSummaryLabel, runtimeSummaryText());
    }
}

bool applyProfileDefaultsForSelectedGame(bool forceServerName, bool forceServerDirectory)
{
    const int selectedProfile = currentGameProfileIndex();
    const std::wstring oldDefaultServerName = defaultServerNameForProfile(g_app.lastGameProfile);
    const std::wstring newDefaultServerName = defaultServerNameForProfile(selectedProfile);

    const std::wstring currentServerName = trim(getWindowTextString(g_app.serverNameEdit));
    if (forceServerName
        || currentServerName.empty()
        || equalCaseInsensitive(currentServerName, oldDefaultServerName))
    {
        setWindowTextString(g_app.serverNameEdit, newDefaultServerName);
    }

    const std::filesystem::path selectedDefaultServerDir = defaultServerDirectoryForProfile(selectedProfile);
    const std::filesystem::path previousDefaultServerDir = defaultServerDirectoryForProfile(g_app.lastGameProfile);
    const std::filesystem::path currentServerDir = currentServerDirectory();

    bool shouldReplaceServerDirectory = forceServerDirectory;
    if (!shouldReplaceServerDirectory)
    {
        const std::wstring rawServerDir = trim(getWindowTextString(g_app.serverDirEdit));
        if (rawServerDir.empty())
        {
            shouldReplaceServerDirectory = true;
        }
        else
        {
            std::error_code ec;
            const bool currentExists = std::filesystem::exists(currentServerDir, ec);
            if (!currentExists)
            {
                shouldReplaceServerDirectory = true;
            }
            else if (pathsLookEquivalent(currentServerDir, previousDefaultServerDir))
            {
                shouldReplaceServerDirectory = true;
            }
        }
    }

    bool serverDirectoryChanged = false;
    if (shouldReplaceServerDirectory && !pathsLookEquivalent(currentServerDir, selectedDefaultServerDir))
    {
        setWindowTextString(g_app.serverDirEdit, selectedDefaultServerDir.wstring());
        serverDirectoryChanged = true;
    }

    g_app.lastGameProfile = selectedProfile;
    return serverDirectoryChanged;
}

void appendUiRuntimeContext()
{
    appendLogLine(L"UI build tag: " + std::wstring(kUiBuildTag));
    appendLogLine(L"UI executable: " + g_app.exePath);

    std::error_code ec;
    const std::filesystem::path workingDirectory = std::filesystem::current_path(ec);
    if (ec)
    {
        appendLogLine(L"Working directory: <unavailable>");
    }
    else
    {
        appendLogLine(L"Working directory: " + workingDirectory.wstring());
    }

    appendLogLine(L"Worker launch mode: " + workerLaunchModeLabel());
    appendLogLine(L"Relay launch mode: " + relayLaunchModeLabel());
    const std::filesystem::path patcherPath = exeDirectory() / "NFSLAN-U2-Patcher.exe";
    appendLogLine(
        std::wstring(L"U2 patch launcher: ")
        + (std::filesystem::exists(patcherPath) ? patcherPath.wstring() : L"<not found>"));
    appendLogLine(L"Selected profile: " + gameProfileDisplayName(currentGameProfileIndex()));
    appendLogLine(L"Server directory: " + currentServerDirectory().wstring());
    appendLogLine(L"Server config: " + currentServerConfigPath().wstring());
}

void showError(const std::wstring& message)
{
    MessageBoxW(g_app.window, message.c_str(), L"NFSLAN", MB_ICONERROR | MB_OK);
}

void showInfo(const std::wstring& message)
{
    MessageBoxW(g_app.window, message.c_str(), L"NFSLAN", MB_ICONINFORMATION | MB_OK);
}

std::wstring formatWin32Error(DWORD errorCode)
{
    wchar_t* buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD language = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    const DWORD messageLength = FormatMessageW(
        flags,
        nullptr,
        errorCode,
        language,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);
    if (messageLength == 0 || !buffer)
    {
        return L"Unknown error";
    }

    std::wstring message(buffer, buffer + messageLength);
    LocalFree(buffer);
    return trim(message);
}

bool tryParseIntRange(const std::wstring& text, int minValue, int maxValue, int* valueOut)
{
    const std::wstring trimmed = trim(text);
    if (trimmed.empty())
    {
        return false;
    }

    wchar_t* end = nullptr;
    const long parsed = std::wcstol(trimmed.c_str(), &end, 10);
    if (!end || *end != L'\0')
    {
        return false;
    }

    if (parsed < minValue || parsed > maxValue)
    {
        return false;
    }

    *valueOut = static_cast<int>(parsed);
    return true;
}

std::wstring normalizeIdentityTokenForMutex(const std::wstring& input)
{
    std::wstring out;
    out.reserve(input.size());

    for (wchar_t ch : input)
    {
        if ((ch >= L'0' && ch <= L'9')
            || (ch >= L'A' && ch <= L'Z')
            || (ch >= L'a' && ch <= L'z')
            || ch == L'_' || ch == L'-' || ch == L'.')
        {
            out.push_back(towupper(ch));
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

std::wstring buildServerIdentityMutexName(const std::wstring& lobbyIdent, int port)
{
    return L"Local\\NFSLAN_SERVER_IDENT_"
        + normalizeIdentityTokenForMutex(trim(lobbyIdent))
        + L"_"
        + std::to_wstring(port);
}

bool isServerIdentityLockedLocally(const std::wstring& lobbyIdent, int port)
{
    const std::wstring mutexName = buildServerIdentityMutexName(lobbyIdent, port);
    HANDLE mutexHandle = OpenMutexW(SYNCHRONIZE, FALSE, mutexName.c_str());
    if (!mutexHandle)
    {
        return false;
    }

    CloseHandle(mutexHandle);
    return true;
}

struct ScopedWsaSession
{
    bool started = false;

    ScopedWsaSession()
    {
        WSADATA wsadata{};
        started = (WSAStartup(MAKEWORD(2, 2), &wsadata) == 0);
    }

    ~ScopedWsaSession()
    {
        if (started)
        {
            WSACleanup();
        }
    }
};

bool isPortBusyLocalBind(int socketType, int protocol, uint16_t port, int* wsaErrorOut)
{
    SOCKET socketHandle = socket(AF_INET, socketType, protocol);
    if (socketHandle == INVALID_SOCKET)
    {
        if (wsaErrorOut)
        {
            *wsaErrorOut = WSAGetLastError();
        }
        return false;
    }

    BOOL exclusive = TRUE;
    setsockopt(
        socketHandle,
        SOL_SOCKET,
        SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&exclusive),
        sizeof(exclusive));

    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(port);
    bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    const int bindResult = bind(socketHandle, reinterpret_cast<const sockaddr*>(&bindAddr), sizeof(bindAddr));
    if (bindResult == SOCKET_ERROR)
    {
        const int err = WSAGetLastError();
        closesocket(socketHandle);

        if (wsaErrorOut)
        {
            *wsaErrorOut = err;
        }

        return (err == WSAEADDRINUSE || err == WSAEACCES);
    }

    closesocket(socketHandle);
    if (wsaErrorOut)
    {
        *wsaErrorOut = 0;
    }
    return false;
}

void refreshProfileSpecificControls()
{
    if (!g_app.u2StartModeEdit)
    {
        return;
    }

    const bool isU2Profile = (currentGameProfileIndex() == kGameProfileUnderground2);
    const BOOL editableWhenIdle = (!g_app.running && isU2Profile) ? TRUE : FALSE;
    const BOOL launchWhenIdle = (!g_app.running && isU2Profile) ? TRUE : FALSE;
    const BOOL launchAnyU2State = isU2Profile ? TRUE : FALSE;

    EnableWindow(g_app.u2StartModeEdit, editableWhenIdle);
    if (g_app.u2GameExeEdit)
    {
        EnableWindow(g_app.u2GameExeEdit, editableWhenIdle);
    }
    if (g_app.browseU2GameExeButton)
    {
        EnableWindow(g_app.browseU2GameExeButton, editableWhenIdle);
    }
    if (g_app.startU2SamePcButton)
    {
        EnableWindow(g_app.startU2SamePcButton, launchWhenIdle);
    }
    if (g_app.openU2PatcherButton)
    {
        EnableWindow(g_app.openU2PatcherButton, launchAnyU2State);
    }
}

bool validateProfileConfigForLaunch(const std::filesystem::path& serverDir, std::wstring* blockingErrorOut)
{
    const std::wstring configText = getWindowTextString(g_app.configEditor);
    const int profile = currentGameProfileIndex();
    const std::wstring expectedLobby = (profile == kGameProfileUnderground2) ? L"NFSU2NA" : L"NFSMWNA";

    std::vector<std::wstring> errors;
    std::vector<std::wstring> warnings;

    int port = 0;
    if (!tryParseIntRange(getConfigValue(configText, L"PORT"), 1, 65535, &port))
    {
        errors.push_back(L"PORT must be an integer in range 1..65535.");
    }

    const std::wstring addr = trim(getConfigValue(configText, L"ADDR"));
    if (addr.empty())
    {
        errors.push_back(L"ADDR must not be empty.");
    }

    const std::wstring lobbyIdent = trim(getConfigValue(configText, L"LOBBY_IDENT"));
    const std::wstring lobby = trim(getConfigValue(configText, L"LOBBY"));

    if (lobbyIdent.empty())
    {
        errors.push_back(L"LOBBY_IDENT is missing.");
    }
    else if (!equalCaseInsensitive(lobbyIdent, expectedLobby))
    {
        errors.push_back(
            L"LOBBY_IDENT must be " + expectedLobby + L" for selected profile, got '" + lobbyIdent + L"'.");
    }

    if (lobby.empty())
    {
        errors.push_back(L"LOBBY is missing.");
    }
    else if (!equalCaseInsensitive(lobby, expectedLobby))
    {
        errors.push_back(
            L"LOBBY must be " + expectedLobby + L" for selected profile, got '" + lobby + L"'.");
    }

    int u2Mode = 0;
    const std::wstring u2ModeText = trim(getConfigValue(configText, L"U2_START_MODE"));
    if (profile == kGameProfileUnderground2)
    {
        if (!tryParseIntRange(u2ModeText.empty() ? L"0" : u2ModeText, 0, 13, &u2Mode))
        {
            errors.push_back(L"U2_START_MODE must be an integer in range 0..13 for Underground 2.");
        }

        if (!trim(getConfigValue(configText, L"CADDR")).empty()
            || !trim(getConfigValue(configText, L"CPORT")).empty())
        {
            warnings.push_back(
                L"CADDR/CPORT are MW-oriented keys; they are usually ignored for Underground 2 profile.");
        }
    }
    else
    {
        if (!u2ModeText.empty() && !equalCaseInsensitive(u2ModeText, L"0"))
        {
            warnings.push_back(L"U2_START_MODE is set but selected profile is MW; worker will ignore it.");
        }

        if (!trim(getConfigValue(configText, L"MADDR")).empty()
            || !trim(getConfigValue(configText, L"RADDR")).empty()
            || !trim(getConfigValue(configText, L"MPORT")).empty()
            || !trim(getConfigValue(configText, L"RPORT")).empty())
        {
            warnings.push_back(
                L"MADDR/RADDR/MPORT/RPORT are UG2-oriented keys; verify MW AADDR/CADDR/APORT/CPORT are correct.");
        }

        const bool fixupsEnabled =
            parseBoolConfigValue(getConfigValue(configText, L"ENABLE_GAME_ADDR_FIXUPS"), true);
        if (!fixupsEnabled)
        {
            warnings.push_back(
                L"ENABLE_GAME_ADDR_FIXUPS=0 can break mixed local/public address join behavior on MW.");
        }
    }

    const std::wstring gamefile = trim(getConfigValue(configText, L"GAMEFILE"));
    if (!gamefile.empty())
    {
        std::filesystem::path gamefilePath = std::filesystem::path(gamefile);
        if (!gamefilePath.is_absolute())
        {
            gamefilePath = serverDir / gamefilePath;
        }

        std::error_code ec;
        if (!std::filesystem::exists(gamefilePath, ec))
        {
            warnings.push_back(L"GAMEFILE '" + gamefile + L"' does not exist in server directory.");
        }
    }
    else
    {
        warnings.push_back(L"GAMEFILE is not set; worker will try gamefile.bin/gameplay.bin automatically.");
    }

    if (port > 0 && !lobbyIdent.empty())
    {
        if (isServerIdentityLockedLocally(lobbyIdent, port))
        {
            errors.push_back(
                L"Another NFSLAN server instance with the same identity is already running "
                L"(LOBBY_IDENT=" + lobbyIdent + L", PORT=" + std::to_wstring(port) + L").");
        }
    }

    if (port > 0)
    {
        ScopedWsaSession wsa;
        if (!wsa.started)
        {
            warnings.push_back(L"Could not initialize Winsock for strict port preflight checks.");
        }
        else
        {
            int udp9999Err = 0;
            if (isPortBusyLocalBind(SOCK_DGRAM, IPPROTO_UDP, 9999, &udp9999Err))
            {
                const std::wstring details =
                    L"UDP port 9999 is already in use locally (WSA " + std::to_wstring(udp9999Err) + L").";
                errors.push_back(
                    details
                    + L" Stop in-game host/server or conflicting relay before launching.");
            }

            const uint16_t servicePort = static_cast<uint16_t>(port);
            if (servicePort != 9999)
            {
                int udpServiceErr = 0;
                if (isPortBusyLocalBind(SOCK_DGRAM, IPPROTO_UDP, servicePort, &udpServiceErr))
                {
                    errors.push_back(
                        L"Configured UDP service port " + std::to_wstring(servicePort)
                        + L" is already in use locally (WSA " + std::to_wstring(udpServiceErr) + L").");
                }
            }

            int tcpServiceErr = 0;
            if (isPortBusyLocalBind(SOCK_STREAM, IPPROTO_TCP, static_cast<uint16_t>(port), &tcpServiceErr))
            {
                errors.push_back(
                    L"Configured TCP service port " + std::to_wstring(port)
                    + L" is already in use locally (WSA " + std::to_wstring(tcpServiceErr) + L").");
            }
        }
    }

    for (const auto& warning : warnings)
    {
        appendLogLine(L"Preflight warning: " + warning);
    }

    if (errors.empty())
    {
        appendLogLine(L"Preflight validation passed for profile " + gameProfileDisplayName(profile) + L".");
        return true;
    }

    std::wstring message = L"Cannot start server due to config validation errors:\n";
    for (const auto& error : errors)
    {
        appendLogLine(L"Preflight error: " + error);
        message += L"- " + error + L"\n";
    }

    *blockingErrorOut = message;
    return false;
}

void setUiRunningState(bool running)
{
    g_app.running = running;

    EnableWindow(g_app.startButton, running ? FALSE : TRUE);
    EnableWindow(g_app.stopButton, running ? TRUE : FALSE);

    EnableWindow(g_app.gameCombo, running ? FALSE : TRUE);
    EnableWindow(g_app.serverNameEdit, running ? FALSE : TRUE);
    EnableWindow(g_app.serverDirEdit, running ? FALSE : TRUE);
    EnableWindow(GetDlgItem(g_app.window, kIdBrowseServerDir), running ? FALSE : TRUE);
    EnableWindow(g_app.portEdit, running ? FALSE : TRUE);
    EnableWindow(g_app.addrEdit, running ? FALSE : TRUE);
    EnableWindow(g_app.enableAddrFixupsCheck, running ? FALSE : TRUE);
    EnableWindow(g_app.disablePatchingCheck, running ? FALSE : TRUE);
    EnableWindow(GetDlgItem(g_app.window, kIdLoadConfig), running ? FALSE : TRUE);
    EnableWindow(GetDlgItem(g_app.window, kIdSaveConfig), running ? FALSE : TRUE);
    EnableWindow(g_app.configEditor, running ? FALSE : TRUE);

#if defined(NFSLAN_NATIVE_EMBED_WORKER)
    EnableWindow(g_app.workerPathEdit, FALSE);
    EnableWindow(GetDlgItem(g_app.window, kIdBrowseWorker), FALSE);
#else
    EnableWindow(g_app.workerPathEdit, running ? FALSE : TRUE);
    EnableWindow(GetDlgItem(g_app.window, kIdBrowseWorker), running ? FALSE : TRUE);
#endif

    refreshProfileSpecificControls();
}

bool readTextFile(const std::filesystem::path& path, std::wstring* outText)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        return false;
    }

    std::string bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    *outText = decodeBytes(bytes);
    return true;
}

bool writeTextFile(const std::filesystem::path& path, const std::wstring& text)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file)
    {
        return false;
    }

    const std::string bytes = toUtf8(text);
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return file.good();
}

void syncFieldsFromConfigEditor()
{
    const std::wstring configText = getWindowTextString(g_app.configEditor);

    const std::wstring portValue = getConfigValue(configText, L"PORT");
    if (!portValue.empty())
    {
        setWindowTextString(g_app.portEdit, portValue);
    }

    const std::wstring addrValue = getConfigValue(configText, L"ADDR");
    if (!addrValue.empty())
    {
        setWindowTextString(g_app.addrEdit, addrValue);
    }

    const std::wstring u2StartModeValue = trim(getConfigValue(configText, L"U2_START_MODE"));
    if (!u2StartModeValue.empty())
    {
        setWindowTextString(g_app.u2StartModeEdit, u2StartModeValue);
    }
    else
    {
        setWindowTextString(g_app.u2StartModeEdit, L"0");
    }

    const bool addrFixupsEnabled = parseBoolConfigValue(getConfigValue(configText, L"ENABLE_GAME_ADDR_FIXUPS"), true);
    SendMessageW(g_app.enableAddrFixupsCheck, BM_SETCHECK, addrFixupsEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
}

void applyFieldsToConfigEditor()
{
    std::wstring configText = getWindowTextString(g_app.configEditor);

    const std::wstring portValue = trim(getWindowTextString(g_app.portEdit));
    const std::wstring addrValue = trim(getWindowTextString(g_app.addrEdit));
    const std::wstring u2StartModeValue = trim(getWindowTextString(g_app.u2StartModeEdit));
    const std::wstring expectedLobby =
        (currentGameProfileIndex() == kGameProfileUnderground2) ? L"NFSU2NA" : L"NFSMWNA";

    if (!portValue.empty())
    {
        configText = upsertConfigValue(configText, L"PORT", portValue);
    }

    if (!addrValue.empty())
    {
        configText = upsertConfigValue(configText, L"ADDR", addrValue);
    }

    if (!u2StartModeValue.empty())
    {
        configText = upsertConfigValue(configText, L"U2_START_MODE", u2StartModeValue);
    }

    if (trim(getConfigValue(configText, L"LOBBY_IDENT")).empty())
    {
        configText = upsertConfigValue(configText, L"LOBBY_IDENT", expectedLobby);
    }

    if (trim(getConfigValue(configText, L"LOBBY")).empty())
    {
        configText = upsertConfigValue(configText, L"LOBBY", expectedLobby);
    }

    // Streamlined launcher flow: force-disable legacy same-machine emulation toggles.
    configText = upsertConfigValue(configText, L"FORCE_LOCAL", L"0");
    configText = upsertConfigValue(configText, L"LOCAL_EMULATION", L"0");

    const bool addrFixupsEnabled = (SendMessageW(g_app.enableAddrFixupsCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
    configText = upsertConfigValue(configText, L"ENABLE_GAME_ADDR_FIXUPS", addrFixupsEnabled ? L"1" : L"0");
    configText = upsertConfigValue(configText, L"LAN_DIAG", L"0");

    setWindowTextString(g_app.configEditor, configText);
}

void loadServerConfig(bool warnIfMissing)
{
    const std::filesystem::path configPath = currentServerConfigPath();

    std::wstring text;
    if (!readTextFile(configPath, &text))
    {
        if (warnIfMissing)
        {
            showError(L"Could not read server.cfg from selected server directory.");
        }
        return;
    }

    setWindowTextString(g_app.configEditor, text);
    syncFieldsFromConfigEditor();

    appendLogLine(L"Loaded config from " + configPath.wstring());
}

bool saveServerConfig(bool showErrors)
{
    const std::filesystem::path serverDir = currentServerDirectory();
    if (serverDir.empty() || !std::filesystem::exists(serverDir))
    {
        if (showErrors)
        {
            showError(L"Server directory does not exist.");
        }
        return false;
    }

    applyFieldsToConfigEditor();

    const std::filesystem::path configPath = currentServerConfigPath();
    const std::wstring text = getWindowTextString(g_app.configEditor);
    if (!writeTextFile(configPath, text))
    {
        if (showErrors)
        {
            showError(L"Failed to write server.cfg.");
        }
        return false;
    }

    appendLogLine(L"Saved config to " + configPath.wstring());
    return true;
}

std::wstring browseForDirectory(HWND owner)
{
    BROWSEINFOW bi{};
    bi.hwndOwner = owner;
    bi.lpszTitle = L"Select server directory";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX;

    LPITEMIDLIST item = SHBrowseForFolderW(&bi);
    if (!item)
    {
        return L"";
    }

    wchar_t path[MAX_PATH] = {};
    std::wstring result;

    if (SHGetPathFromIDListW(item, path))
    {
        result = path;
    }

    CoTaskMemFree(item);
    return result;
}

std::wstring browseForWorkerExecutable(HWND owner)
{
    wchar_t filePath[MAX_PATH] = {};

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    const wchar_t filter[] = L"Executable files (*.exe)\0*.exe\0All files\0*.*\0";
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (!GetOpenFileNameW(&ofn))
    {
        return L"";
    }

    return std::wstring(filePath);
}

std::wstring browseForU2GameExecutable(HWND owner)
{
    wchar_t filePath[MAX_PATH] = {};

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    const wchar_t filter[] =
        L"NFSU2 executable (speed2.exe)\0speed2.exe\0Executable files (*.exe)\0*.exe\0All files\0*.*\0";
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

void launchRelayUi()
{
#if defined(NFSLAN_NATIVE_EMBED_RELAY)
    const std::wstring commandLine = L"\"" + g_app.exePath + L"\" --relay-ui";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring mutableCommandLine = commandLine;
    mutableCommandLine.push_back(L'\0');

    const BOOL created = CreateProcessW(
        g_app.exePath.c_str(),
        mutableCommandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        exeDirectory().wstring().c_str(),
        &si,
        &pi);
    if (!created)
    {
        const DWORD errorCode = GetLastError();
        const std::wstring errorDetails =
            L"Failed to launch relay UI. Win32 error " + std::to_wstring(errorCode) + L": "
            + formatWin32Error(errorCode);
        appendLogLine(errorDetails);
        showError(errorDetails);
        return;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    appendLogLine(L"Opened embedded relay UI window.");
#else
    showError(L"Relay UI is not embedded in this build.");
#endif
}

void launchU2Patcher()
{
    if (currentGameProfileIndex() == kGameProfileUnderground2)
    {
        const std::filesystem::path gamePath = std::filesystem::path(trim(getWindowTextString(g_app.u2GameExeEdit)));
        if (!gamePath.empty() && std::filesystem::exists(gamePath))
        {
            int injectPort = 9900;
            const std::wstring portText = trim(getWindowTextString(g_app.portEdit));
            if (!portText.empty())
            {
                tryParseIntRange(portText, 1, 65535, &injectPort);
            }

            std::wstring injectIp = trim(getWindowTextString(g_app.addrEdit));
            if (injectIp.empty())
            {
                injectIp = L"127.0.0.1";
            }

            std::wstring detectedIp;
            if (tryResolveRunningWorkerInjectIpForPort(injectPort, &detectedIp))
            {
                if (injectIp != detectedIp)
                {
                    appendLogLine(
                        L"U2 patcher: overriding inject IP from "
                        + injectIp
                        + L" to worker listener "
                        + detectedIp
                        + L" on port "
                        + std::to_wstring(injectPort)
                        + L".");
                }
                injectIp = detectedIp;
            }
            else if (g_app.running)
            {
                appendLogLine(
                    L"U2 patcher: could not resolve worker listener address on port "
                    + std::to_wstring(injectPort)
                    + L"; using configured IP "
                    + injectIp
                    + L".");
            }

            const std::wstring injectName = L"NAME";
            launchU2PatcherForGame(gamePath, injectName, injectPort, injectIp);
            return;
        }
    }

    const std::filesystem::path patcherPath = exeDirectory() / "NFSLAN-U2-Patcher.exe";
    if (!std::filesystem::exists(patcherPath))
    {
        showError(
            L"NFSLAN-U2-Patcher.exe was not found next to this launcher.\n"
            L"Build/install the patcher target and place it in the same folder.");
        return;
    }

    std::wstring commandLine = L"\"" + patcherPath.wstring() + L"\"";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    commandLine.push_back(L'\0');
    const BOOL created = CreateProcessW(
        patcherPath.wstring().c_str(),
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        exeDirectory().wstring().c_str(),
        &si,
        &pi);
    if (!created)
    {
        const DWORD errorCode = GetLastError();
        const std::wstring errorDetails =
            L"Failed to launch U2 patcher. Win32 error " + std::to_wstring(errorCode) + L": "
            + formatWin32Error(errorCode);
        appendLogLine(errorDetails);
        showError(errorDetails);
        return;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    appendLogLine(L"Opened U2 self-filter patch launcher.");
}

void stopWorker()
{
    if (!g_app.running || !g_app.processHandle)
    {
        return;
    }

    appendLogLine(L"Stopping server process...");
    TerminateProcess(g_app.processHandle, 0);
}

void cleanupWorkerResources()
{
    KillTimer(g_app.window, kWorkerPollTimerId);

    flushPendingLog();

    if (g_app.pipeRead)
    {
        CloseHandle(g_app.pipeRead);
        g_app.pipeRead = nullptr;
    }

    if (g_app.pipeWrite)
    {
        CloseHandle(g_app.pipeWrite);
        g_app.pipeWrite = nullptr;
    }

    if (g_app.logReaderThread)
    {
        WaitForSingleObject(g_app.logReaderThread, 500);
        CloseHandle(g_app.logReaderThread);
        g_app.logReaderThread = nullptr;
    }

    if (g_app.processThread)
    {
        CloseHandle(g_app.processThread);
        g_app.processThread = nullptr;
    }

    if (g_app.processHandle)
    {
        CloseHandle(g_app.processHandle);
        g_app.processHandle = nullptr;
    }

    setUiRunningState(false);
}

bool validateStartInput(std::wstring* errorOut, bool requireServerDll = true)
{
    const std::wstring serverName = trim(getWindowTextString(g_app.serverNameEdit));
    if (serverName.empty())
    {
        *errorOut = L"Server name cannot be empty.";
        return false;
    }

    const std::filesystem::path serverDir = currentServerDirectory();
    if (serverDir.empty() || !std::filesystem::exists(serverDir))
    {
        *errorOut = L"Server directory does not exist.";
        return false;
    }

    const std::filesystem::path serverDll = serverDir / "server.dll";
    if (requireServerDll && !std::filesystem::exists(serverDll))
    {
        *errorOut = L"server.dll was not found in selected server directory.";
        return false;
    }

#if !defined(NFSLAN_NATIVE_EMBED_WORKER)
    const std::wstring workerPath = trim(getWindowTextString(g_app.workerPathEdit));
    if (workerPath.empty() || !std::filesystem::exists(std::filesystem::path(workerPath)))
    {
        *errorOut = L"Worker executable path is invalid.";
        return false;
    }
#endif

    return true;
}

std::wstring escapeForQuotedArg(const std::wstring& input)
{
    std::wstring escaped = input;
    std::replace(escaped.begin(), escaped.end(), L'"', L'\'');
    return escaped;
}

bool launchU2PatcherForGame(
    const std::filesystem::path& gameExePath,
    const std::wstring& injectName,
    int injectPort,
    const std::wstring& injectIp)
{
    const std::filesystem::path patcherPath = exeDirectory() / "NFSLAN-U2-Patcher.exe";
    if (!std::filesystem::exists(patcherPath))
    {
        showError(
            L"NFSLAN-U2-Patcher.exe was not found next to this launcher.\n"
            L"Build/install the patcher target and place it in the same folder.");
        return false;
    }

    std::wstring commandLine =
        L"\"" + patcherPath.wstring() + L"\""
        + L" --inject-name \"" + escapeForQuotedArg(injectName) + L"\""
        + L" --inject-port " + std::to_wstring(injectPort)
        + L" --inject-ip \"" + escapeForQuotedArg(injectIp) + L"\""
        + L" \"" + escapeForQuotedArg(gameExePath.wstring()) + L"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    commandLine.push_back(L'\0');
    const BOOL created = CreateProcessW(
        patcherPath.wstring().c_str(),
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        exeDirectory().wstring().c_str(),
        &si,
        &pi);
    if (!created)
    {
        const DWORD errorCode = GetLastError();
        const std::wstring errorDetails =
            L"Failed to launch U2 patcher. Win32 error " + std::to_wstring(errorCode) + L": "
            + formatWin32Error(errorCode);
        appendLogLine(errorDetails);
        showError(errorDetails);
        return false;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    appendLogLine(
        L"Launched U2 patcher for game "
        + gameExePath.wstring()
        + L" (inject name='"
        + injectName
        + L"', port="
        + std::to_wstring(injectPort)
        + L", ip="
        + injectIp
        + L", fallback stats='port|0').");
    return true;
}

DWORD WINAPI logReaderThreadProc(LPVOID)
{
    char buffer[1024] = {};
    DWORD readBytes = 0;

    while (ReadFile(g_app.pipeRead, buffer, sizeof(buffer), &readBytes, nullptr) && readBytes > 0)
    {
        const std::string chunk(buffer, buffer + readBytes);
        auto* wideChunk = new std::wstring(decodeBytes(chunk));
        PostMessageW(g_app.window, WM_APP_LOG_CHUNK, 0, reinterpret_cast<LPARAM>(wideChunk));
    }

    return 0;
}

void startWorker()
{
    if (g_app.running)
    {
        return;
    }

    std::wstring error;
    if (!validateStartInput(&error, true))
    {
        showError(error);
        return;
    }

    applyFieldsToConfigEditor();

    const std::filesystem::path serverDir = currentServerDirectory();
    if (!validateProfileConfigForLaunch(serverDir, &error))
    {
        showError(error);
        return;
    }

    if (!saveServerConfig(true))
    {
        return;
    }

    const std::wstring serverName = trim(getWindowTextString(g_app.serverNameEdit));
    const std::wstring u2ModeText = trim(getWindowTextString(g_app.u2StartModeEdit));
    const std::wstring profileName = gameProfileDisplayName(currentGameProfileIndex());

    std::wstring executablePath;
    std::wstring commandLine;

#if defined(NFSLAN_NATIVE_EMBED_WORKER)
    executablePath = g_app.exePath;
    commandLine = L"\"" + g_app.exePath + L"\" --worker \"" + escapeForQuotedArg(serverName) + L"\"";
#else
    executablePath = trim(getWindowTextString(g_app.workerPathEdit));
    commandLine = L"\"" + executablePath + L"\" \"" + escapeForQuotedArg(serverName) + L"\"";
#endif

    if (SendMessageW(g_app.disablePatchingCheck, BM_GETCHECK, 0, 0) == BST_CHECKED)
    {
        commandLine += L" -n";
    }

    if (currentGameProfileIndex() == kGameProfileUnderground2 && !u2ModeText.empty())
    {
        commandLine += L" --u2-mode " + u2ModeText;
    }

    appendLogLine(L"UI build tag: " + std::wstring(kUiBuildTag));
    appendLogLine(L"Profile: " + profileName);
    appendLogLine(L"Worker launch mode: " + workerLaunchModeLabel());
    appendLogLine(L"Server directory: " + serverDir.wstring());
    appendLogLine(L"Server config: " + currentServerConfigPath().wstring());

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&g_app.pipeRead, &g_app.pipeWrite, &sa, 0))
    {
        showError(L"Failed to create output pipe.");
        return;
    }

    if (!SetHandleInformation(g_app.pipeRead, HANDLE_FLAG_INHERIT, 0))
    {
        cleanupWorkerResources();
        showError(L"Failed to configure output pipe.");
        return;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = g_app.pipeWrite;
    si.hStdError = g_app.pipeWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};

    std::wstring mutableCommandLine = commandLine;
    mutableCommandLine.push_back(L'\0');

    const BOOL created = CreateProcessW(
        executablePath.c_str(),
        mutableCommandLine.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        serverDir.wstring().c_str(),
        &si,
        &pi);

    if (!created)
    {
        const DWORD errorCode = GetLastError();
        cleanupWorkerResources();
        const std::wstring errorDetails =
            L"Failed to start worker process. Win32 error " + std::to_wstring(errorCode) + L": "
            + formatWin32Error(errorCode);
        appendLogLine(errorDetails);
        showError(errorDetails);
        return;
    }

    g_app.processHandle = pi.hProcess;
    g_app.processThread = pi.hThread;

    CloseHandle(g_app.pipeWrite);
    g_app.pipeWrite = nullptr;

    g_app.logReaderThread = CreateThread(nullptr, 0, logReaderThreadProc, nullptr, 0, nullptr);

    setUiRunningState(true);
    SetTimer(g_app.window, kWorkerPollTimerId, 250, nullptr);

    appendLogLine(L"Starting " + commandLine);
    appendLogLine(L"Server started");
}

void startU2SamePcBundle()
{
    if (currentGameProfileIndex() != kGameProfileUnderground2)
    {
        showError(L"UG2 bundle is available only for Underground 2 profile.");
        return;
    }

    std::filesystem::path gameExePath = std::filesystem::path(trim(getWindowTextString(g_app.u2GameExeEdit)));
    if (gameExePath.empty() || !std::filesystem::exists(gameExePath))
    {
        const std::wstring selected = browseForU2GameExecutable(g_app.window);
        if (selected.empty())
        {
            return;
        }
        setWindowTextString(g_app.u2GameExeEdit, selected);
        gameExePath = std::filesystem::path(selected);
    }

    if (gameExePath.empty() || !std::filesystem::exists(gameExePath))
    {
        showError(L"Selected U2 game executable path is invalid.");
        return;
    }
    SendMessageW(g_app.enableAddrFixupsCheck, BM_SETCHECK, BST_CHECKED, 0);
    applyFieldsToConfigEditor();
    appendLogLine(
        L"UG2 bundle: launching real worker first, then patcher injects a visible entry that points to worker listener.");

    if (!g_app.running)
    {
        startWorker();
        if (!g_app.running)
        {
            appendLogLine(L"UG2 bundle aborted: worker failed to start.");
            return;
        }
    }

    int injectPort = 9900;
    const std::wstring portText = trim(getWindowTextString(g_app.portEdit));
    if (!portText.empty())
    {
        if (!tryParseIntRange(portText, 1, 65535, &injectPort))
        {
            showError(L"PORT must be in range 1..65535.");
            return;
        }
    }

    std::wstring injectIp = trim(getWindowTextString(g_app.addrEdit));
    if (injectIp.empty())
    {
        injectIp = L"127.0.0.1";
    }

    std::wstring detectedIp;
    if (tryResolveRunningWorkerInjectIpForPort(injectPort, &detectedIp))
    {
        if (injectIp != detectedIp)
        {
            appendLogLine(
                L"UG2 bundle: overriding inject IP from "
                + injectIp
                + L" to worker listener "
                + detectedIp
                + L" on port "
                + std::to_wstring(injectPort)
                + L".");
        }
        injectIp = detectedIp;
    }
    else
    {
        appendLogLine(
            L"UG2 bundle warning: could not resolve worker listener address on port "
            + std::to_wstring(injectPort)
            + L"; using configured IP "
            + injectIp
            + L".");
    }

    const std::wstring injectName = L"NAME";

    if (!launchU2PatcherForGame(gameExePath, injectName, injectPort, injectIp))
    {
        appendLogLine(L"UG2 bundle warning: server is running, but patcher launch failed.");
        return;
    }

    appendLogLine(L"UG2 bundle started: worker and patcher are active.");
}

void saveSettings()
{
    const std::wstring path = settingsPath().wstring();

    WritePrivateProfileStringW(L"launcher", L"gameIndex", std::to_wstring(SendMessageW(g_app.gameCombo, CB_GETCURSEL, 0, 0)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"serverName", trim(getWindowTextString(g_app.serverNameEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"serverDir", trim(getWindowTextString(g_app.serverDirEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"u2GameExe", trim(getWindowTextString(g_app.u2GameExeEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"port", trim(getWindowTextString(g_app.portEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"addr", trim(getWindowTextString(g_app.addrEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"u2StartMode", trim(getWindowTextString(g_app.u2StartModeEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(
        L"launcher",
        L"enableAddrFixups",
        (SendMessageW(g_app.enableAddrFixupsCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) ? L"1" : L"0",
        path.c_str());
    WritePrivateProfileStringW(
        L"launcher",
        L"disablePatching",
        (SendMessageW(g_app.disablePatchingCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) ? L"1" : L"0",
        path.c_str());

#if !defined(NFSLAN_NATIVE_EMBED_WORKER)
    WritePrivateProfileStringW(L"launcher", L"workerPath", trim(getWindowTextString(g_app.workerPathEdit)).c_str(), path.c_str());
#endif
}

std::wstring readIniValue(const std::wstring& key, const std::wstring& fallback)
{
    wchar_t buffer[2048] = {};
    GetPrivateProfileStringW(L"launcher", key.c_str(), fallback.c_str(), buffer, 2048, settingsPath().wstring().c_str());
    return std::wstring(buffer);
}

void loadSettings()
{
    const int gameIndex = _wtoi(readIniValue(L"gameIndex", L"0").c_str());
    const int normalizedGameIndex =
        (gameIndex == kGameProfileUnderground2) ? kGameProfileUnderground2 : kGameProfileMostWanted;
    SendMessageW(g_app.gameCombo, CB_SETCURSEL, normalizedGameIndex, 0);
    g_app.lastGameProfile = normalizedGameIndex;

    setWindowTextString(g_app.serverNameEdit, readIniValue(L"serverName", getWindowTextString(g_app.serverNameEdit)));
    setWindowTextString(g_app.serverDirEdit, readIniValue(L"serverDir", getWindowTextString(g_app.serverDirEdit)));
    setWindowTextString(g_app.u2GameExeEdit, readIniValue(L"u2GameExe", getWindowTextString(g_app.u2GameExeEdit)));
    setWindowTextString(g_app.portEdit, readIniValue(L"port", L"9900"));
    setWindowTextString(g_app.addrEdit, readIniValue(L"addr", L"0.0.0.0"));
    setWindowTextString(g_app.u2StartModeEdit, readIniValue(L"u2StartMode", L"0"));
    SendMessageW(
        g_app.enableAddrFixupsCheck,
        BM_SETCHECK,
        (readIniValue(L"enableAddrFixups", L"1") == L"1") ? BST_CHECKED : BST_UNCHECKED,
        0);

    const bool disablePatching = (readIniValue(L"disablePatching", L"0") == L"1");
    SendMessageW(g_app.disablePatchingCheck, BM_SETCHECK, disablePatching ? BST_CHECKED : BST_UNCHECKED, 0);

#if !defined(NFSLAN_NATIVE_EMBED_WORKER)
    setWindowTextString(g_app.workerPathEdit, readIniValue(L"workerPath", getWindowTextString(g_app.workerPathEdit)));
#endif

    const bool changedDir = applyProfileDefaultsForSelectedGame(false, false);
    if (changedDir)
    {
        appendLogLine(L"Profile default server directory applied: " + currentServerDirectory().wstring());
    }

    refreshProfileSpecificControls();
    refreshRuntimeSummaryLabel();
}

void updateDefaultsForCurrentGame(bool logChanges)
{
    const int selectedProfile = currentGameProfileIndex();
    const bool changedDir = applyProfileDefaultsForSelectedGame(false, false);
    if (changedDir)
    {
        loadServerConfig(false);
    }

    if (logChanges)
    {
        appendLogLine(L"Selected profile: " + gameProfileDisplayName(selectedProfile));
        if (changedDir)
        {
            appendLogLine(L"Server directory switched to profile default: " + currentServerDirectory().wstring());
        }
    }

    refreshProfileSpecificControls();
    refreshRuntimeSummaryLabel();
}

void createLabel(HWND parent, const wchar_t* text, int x, int y, int width, int height)
{
    CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE, x, y, width, height, parent, nullptr, nullptr, nullptr);
}

void applyDefaultFontToWindow(HWND window)
{
    SendMessageW(window, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
}

void createUi(HWND window)
{
    g_app.window = window;

    constexpr int left = 12;
    constexpr int labelWidth = 130;
    constexpr int fieldWidth = 560;
    constexpr int smallFieldWidth = 130;
    constexpr int buttonWidth = 90;
    constexpr int rowHeight = 24;
    constexpr int rowGap = 8;

    int y = 12;

    createLabel(window, L"Game profile", left, y + 4, labelWidth, rowHeight);
    g_app.gameCombo = CreateWindowExW(
        0,
        L"COMBOBOX",
        nullptr,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
        left + labelWidth,
        y,
        260,
        240,
        window,
        reinterpret_cast<HMENU>(kIdGameCombo),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.gameCombo);
    SendMessageW(g_app.gameCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Need for Speed Most Wanted (2005)"));
    SendMessageW(g_app.gameCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Need for Speed Underground 2"));
    SendMessageW(g_app.gameCombo, CB_SETCURSEL, 0, 0);

    y += rowHeight + rowGap;

    createLabel(window, L"Server name", left, y + 4, labelWidth, rowHeight);
    g_app.serverNameEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"MW Dedicated Server",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        left + labelWidth,
        y,
        fieldWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdServerName),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.serverNameEdit);

    y += rowHeight + rowGap;

    createLabel(window, L"Server directory", left, y + 4, labelWidth, rowHeight);
    g_app.serverDirEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        defaultServerDirectoryForProfile(kGameProfileMostWanted).wstring().c_str(),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        left + labelWidth,
        y,
        fieldWidth - buttonWidth - 8,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdServerDir),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.serverDirEdit);

    HWND browseServerDirButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Browse...",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        left + labelWidth + fieldWidth - buttonWidth,
        y,
        buttonWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdBrowseServerDir),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(browseServerDirButton);

    y += rowHeight + rowGap;

    createLabel(window, L"Worker executable", left, y + 4, labelWidth, rowHeight);

#if defined(NFSLAN_NATIVE_EMBED_WORKER)
    g_app.workerPathEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"(embedded in this executable)",
        WS_CHILD | WS_VISIBLE,
        left + labelWidth,
        y,
        fieldWidth - buttonWidth - 8,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdWorkerPath),
        nullptr,
        nullptr);
#else
    g_app.workerPathEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        (exeDirectory() / "NFSLAN.exe").wstring().c_str(),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        left + labelWidth,
        y,
        fieldWidth - buttonWidth - 8,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdWorkerPath),
        nullptr,
        nullptr);
#endif
    applyDefaultFontToWindow(g_app.workerPathEdit);

    HWND browseWorkerButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Browse...",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        left + labelWidth + fieldWidth - buttonWidth,
        y,
        buttonWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdBrowseWorker),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(browseWorkerButton);

#if defined(NFSLAN_NATIVE_EMBED_WORKER)
    EnableWindow(g_app.workerPathEdit, FALSE);
    EnableWindow(browseWorkerButton, FALSE);
#endif

    y += rowHeight + rowGap;

    createLabel(window, L"U2 game EXE", left, y + 4, labelWidth, rowHeight);
    g_app.u2GameExeEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        left + labelWidth,
        y,
        fieldWidth - buttonWidth - 8,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdU2GameExe),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.u2GameExeEdit);

    g_app.browseU2GameExeButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Browse...",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        left + labelWidth + fieldWidth - buttonWidth,
        y,
        buttonWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdBrowseU2GameExe),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.browseU2GameExeButton);

    y += rowHeight + rowGap;

    g_app.runtimeSummaryLabel = CreateWindowExW(
        0,
        L"STATIC",
        runtimeSummaryText().c_str(),
        WS_CHILD | WS_VISIBLE,
        left,
        y + 4,
        960,
        rowHeight,
        window,
        nullptr,
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.runtimeSummaryLabel);

    y += rowHeight + rowGap;

    createLabel(window, L"U2_START_MODE", left, y + 4, labelWidth, rowHeight);
    g_app.u2StartModeEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"0",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        left + labelWidth,
        y,
        70,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdU2StartMode),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.u2StartModeEdit);

    createLabel(window, L"(Underground 2 only, range 0..13)", left + labelWidth + 84, y + 4, 360, rowHeight);

    y += rowHeight + rowGap;

    createLabel(window, L"PORT", left, y + 4, 40, rowHeight);
    g_app.portEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"9900",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        left + 40,
        y,
        smallFieldWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdPort),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.portEdit);

    createLabel(window, L"ADDR", left + 200, y + 4, 50, rowHeight);
    g_app.addrEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"0.0.0.0",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        left + 250,
        y,
        210,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdAddr),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.addrEdit);

    y += rowHeight + rowGap;

    g_app.enableAddrFixupsCheck = CreateWindowExW(
        0,
        L"BUTTON",
        L"ENABLE_GAME_ADDR_FIXUPS",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        left,
        y,
        250,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdEnableAddrFixups),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.enableAddrFixupsCheck);
    SendMessageW(g_app.enableAddrFixupsCheck, BM_SETCHECK, BST_CHECKED, 0);

    g_app.disablePatchingCheck = CreateWindowExW(
        0,
        L"BUTTON",
        L"Disable binary patching (-n)",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        left + 270,
        y,
        260,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdDisablePatching),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.disablePatchingCheck);

    y += rowHeight + rowGap;

    HWND loadConfigButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Load cfg",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        left,
        y,
        buttonWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdLoadConfig),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(loadConfigButton);

    HWND saveConfigButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Save cfg",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        left + buttonWidth + 8,
        y,
        buttonWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdSaveConfig),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(saveConfigButton);

    const int startButtonX = left + 2 * (buttonWidth + 8);
    const int stopButtonX = startButtonX + buttonWidth + 8;
    const int samePcButtonX = stopButtonX + buttonWidth + 8;
    const int patcherButtonX = samePcButtonX + (buttonWidth + 40) + 8;

    g_app.startButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Start",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        startButtonX,
        y,
        buttonWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdStart),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.startButton);

    g_app.stopButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Stop",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        stopButtonX,
        y,
        buttonWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdStop),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.stopButton);

    g_app.startU2SamePcButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"UG2 Bundle",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        samePcButtonX,
        y,
        buttonWidth + 40,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdStartU2SamePc),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.startU2SamePcButton);

    g_app.openU2PatcherButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"U2 patcher",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        patcherButtonX,
        y,
        buttonWidth + 30,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdOpenU2Patcher),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.openU2PatcherButton);

    y += rowHeight + rowGap;

    createLabel(window, L"server.cfg", left, y + 4, labelWidth, rowHeight);
    y += rowHeight;

    g_app.configEditor = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
        left,
        y,
        960,
        220,
        window,
        reinterpret_cast<HMENU>(kIdConfigEditor),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.configEditor);

    y += 220 + rowGap;

    createLabel(window, L"Logs", left, y + 4, labelWidth, rowHeight);
    y += rowHeight;

    g_app.logView = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
        left,
        y,
        960,
        250,
        window,
        reinterpret_cast<HMENU>(kIdLogView),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.logView);

    setUiRunningState(false);
}

LRESULT handleCommand(HWND window, WPARAM wParam)
{
    const int controlId = LOWORD(wParam);
    const int commandCode = HIWORD(wParam);

    switch (controlId)
    {
    case kIdGameCombo:
        if (commandCode == CBN_SELCHANGE)
        {
            updateDefaultsForCurrentGame(true);
        }
        return 0;

    case kIdEnableAddrFixups:
        if (commandCode == BN_CLICKED)
        {
            const bool enabled = (SendMessageW(g_app.enableAddrFixupsCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
            appendLogLine(
                std::wstring(L"ENABLE_GAME_ADDR_FIXUPS set to ") + (enabled ? L"1" : L"0") + L" in UI.");
            applyFieldsToConfigEditor();
        }
        return 0;

    case kIdU2StartMode:
        if (commandCode == EN_KILLFOCUS)
        {
            const std::wstring raw = trim(getWindowTextString(g_app.u2StartModeEdit));
            int parsed = 0;
            if (!raw.empty() && !tryParseIntRange(raw, 0, 13, &parsed))
            {
                setWindowTextString(g_app.u2StartModeEdit, L"0");
                appendLogLine(L"U2_START_MODE must be 0..13. Reset to 0.");
            }
            applyFieldsToConfigEditor();
        }
        return 0;

    case kIdBrowseServerDir:
    {
        const std::wstring selected = browseForDirectory(window);
        if (!selected.empty())
        {
            setWindowTextString(g_app.serverDirEdit, selected);
            loadServerConfig(false);
        }
        return 0;
    }

    case kIdBrowseWorker:
#if !defined(NFSLAN_NATIVE_EMBED_WORKER)
    {
        const std::wstring selected = browseForWorkerExecutable(window);
        if (!selected.empty())
        {
            setWindowTextString(g_app.workerPathEdit, selected);
        }
        return 0;
    }
#else
        return 0;
#endif

    case kIdBrowseU2GameExe:
    {
        const std::wstring selected = browseForU2GameExecutable(window);
        if (!selected.empty())
        {
            setWindowTextString(g_app.u2GameExeEdit, selected);
        }
        return 0;
    }

    case kIdLoadConfig:
        loadServerConfig(true);
        return 0;

    case kIdSaveConfig:
        if (saveServerConfig(true))
        {
            showInfo(L"server.cfg saved.");
        }
        return 0;

    case kIdStart:
        startWorker();
        return 0;

    case kIdStartU2SamePc:
        startU2SamePcBundle();
        return 0;

    case kIdStop:
        stopWorker();
        return 0;

    case kIdOpenU2Patcher:
        launchU2Patcher();
        return 0;

    default:
        return 0;
    }
}

LRESULT CALLBACK windowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        createUi(window);
        loadSettings();
        loadServerConfig(false);
        appendLogLine(L"Native Win32 UI initialized");
        appendUiRuntimeContext();
        return 0;

    case WM_COMMAND:
        return handleCommand(window, wParam);

    case WM_TIMER:
        if (wParam == kWorkerPollTimerId && g_app.running && g_app.processHandle)
        {
            if (WaitForSingleObject(g_app.processHandle, 0) == WAIT_OBJECT_0)
            {
                DWORD exitCode = 0;
                GetExitCodeProcess(g_app.processHandle, &exitCode);
                appendLogLine(L"Worker exited with code " + std::to_wstring(exitCode));
                cleanupWorkerResources();
            }
        }
        return 0;

    case WM_APP_LOG_CHUNK:
    {
        auto* chunk = reinterpret_cast<std::wstring*>(lParam);
        if (chunk)
        {
            appendLogChunk(*chunk);
            delete chunk;
        }
        return 0;
    }

    case WM_CLOSE:
        if (g_app.running)
        {
            stopWorker();
            WaitForSingleObject(g_app.processHandle, 2000);
            cleanupWorkerResources();
        }
        saveSettings();
        DestroyWindow(window);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(window, message, wParam, lParam);
    }
}

#if defined(NFSLAN_NATIVE_EMBED_WORKER)
int runEmbeddedWorkerMode()
{
    int argcW = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    if (!argvW)
    {
        return -1;
    }

    std::vector<std::string> storage;
    storage.emplace_back("NFSLAN");

    for (int i = 2; i < argcW; ++i)
    {
        storage.push_back(toUtf8(argvW[i]));
    }

    std::vector<char*> argv;
    argv.reserve(storage.size());
    for (auto& s : storage)
    {
        argv.push_back(s.data());
    }

    LocalFree(argvW);
    return NFSLANWorkerMain(static_cast<int>(argv.size()), argv.data());
}
#endif

bool shouldRunWorkerMode()
{
#if defined(NFSLAN_NATIVE_EMBED_WORKER)
    int argcW = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    if (!argvW)
    {
        return false;
    }

    const bool workerMode = (argcW > 1 && wcscmp(argvW[1], L"--worker") == 0);
    LocalFree(argvW);
    return workerMode;
#else
    return false;
#endif
}

bool shouldRunRelayMode()
{
#if defined(NFSLAN_NATIVE_EMBED_RELAY)
    int argcW = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    if (!argvW)
    {
        return false;
    }

    const bool relayMode = (argcW > 1 && wcscmp(argvW[1], L"--relay-ui") == 0);
    LocalFree(argvW);
    return relayMode;
#else
    return false;
#endif
}

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int showCommand)
{
    wchar_t executablePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, executablePath, MAX_PATH);
    g_app.exePath = executablePath;

#if defined(NFSLAN_NATIVE_EMBED_RELAY)
    if (shouldRunRelayMode())
    {
        return NFSLANRelayMain(instance, showCommand);
    }
#endif

#if defined(NFSLAN_NATIVE_EMBED_WORKER)
    if (shouldRunWorkerMode())
    {
        return runEmbeddedWorkerMode();
    }
#endif

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = windowProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kWindowClassName;

    RegisterClassExW(&wc);

    std::wstring windowTitle;
#if defined(NFSLAN_NATIVE_EMBED_WORKER)
    windowTitle = L"NFSLAN Native Server Manager (Embedded Worker) [" + std::wstring(kUiBuildTag) + L"]";
#else
    windowTitle = L"NFSLAN Native Server Manager [" + std::wstring(kUiBuildTag) + L"]";
#endif

    HWND window = CreateWindowExW(
        0,
        kWindowClassName,
        windowTitle.c_str(),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        1000,
        960,
        nullptr,
        nullptr,
        instance,
        nullptr);

    if (!window)
    {
        CoUninitialize();
        return -1;
    }

    ShowWindow(window, showCommand);
    UpdateWindow(window);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CoUninitialize();
    return static_cast<int>(msg.wParam);
}
