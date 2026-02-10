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

namespace
{
constexpr wchar_t kWindowClassName[] = L"NFSLANNativeWin32Window";
constexpr UINT kWorkerPollTimerId = 100;
constexpr UINT WM_APP_LOG_CHUNK = WM_APP + 1;
constexpr wchar_t kUiBuildTag[] = L"2026-02-10-native-ui-rework-1";
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
    kIdPort,
    kIdAddr,
    kIdForceLocal,
    kIdEnableAddrFixups,
    kIdDisablePatching,
    kIdLoadConfig,
    kIdSaveConfig,
    kIdStart,
    kIdStop,
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
    HWND portEdit = nullptr;
    HWND addrEdit = nullptr;
    HWND forceLocalCheck = nullptr;
    HWND enableAddrFixupsCheck = nullptr;
    HWND disablePatchingCheck = nullptr;
    HWND configEditor = nullptr;
    HWND logView = nullptr;
    HWND runtimeSummaryLabel = nullptr;
    HWND startButton = nullptr;
    HWND stopButton = nullptr;

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

std::wstring runtimeSummaryText()
{
    return L"Build: " + std::wstring(kUiBuildTag) + L"  |  Worker mode: " + workerLaunchModeLabel();
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
    EnableWindow(g_app.forceLocalCheck, running ? FALSE : TRUE);
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

    const bool forceLocalEnabled = parseBoolConfigValue(getConfigValue(configText, L"FORCE_LOCAL"), false);
    SendMessageW(g_app.forceLocalCheck, BM_SETCHECK, forceLocalEnabled ? BST_CHECKED : BST_UNCHECKED, 0);

    const bool addrFixupsEnabled = parseBoolConfigValue(getConfigValue(configText, L"ENABLE_GAME_ADDR_FIXUPS"), true);
    SendMessageW(g_app.enableAddrFixupsCheck, BM_SETCHECK, addrFixupsEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
}

void applyFieldsToConfigEditor()
{
    std::wstring configText = getWindowTextString(g_app.configEditor);

    const std::wstring portValue = trim(getWindowTextString(g_app.portEdit));
    const std::wstring addrValue = trim(getWindowTextString(g_app.addrEdit));

    if (!portValue.empty())
    {
        configText = upsertConfigValue(configText, L"PORT", portValue);
    }

    if (!addrValue.empty())
    {
        configText = upsertConfigValue(configText, L"ADDR", addrValue);
    }

    const bool forceLocalEnabled = (SendMessageW(g_app.forceLocalCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
    configText = upsertConfigValue(configText, L"FORCE_LOCAL", forceLocalEnabled ? L"1" : L"0");

    const bool addrFixupsEnabled = (SendMessageW(g_app.enableAddrFixupsCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
    configText = upsertConfigValue(configText, L"ENABLE_GAME_ADDR_FIXUPS", addrFixupsEnabled ? L"1" : L"0");

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

bool validateStartInput(std::wstring* errorOut)
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
    if (!std::filesystem::exists(serverDll))
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
    if (!validateStartInput(&error))
    {
        showError(error);
        return;
    }

    if (!saveServerConfig(true))
    {
        return;
    }

    const std::wstring serverName = trim(getWindowTextString(g_app.serverNameEdit));
    const std::filesystem::path serverDir = currentServerDirectory();
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

    if (SendMessageW(g_app.forceLocalCheck, BM_GETCHECK, 0, 0) == BST_CHECKED)
    {
        commandLine += L" --same-machine";
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

void saveSettings()
{
    const std::wstring path = settingsPath().wstring();

    WritePrivateProfileStringW(L"launcher", L"gameIndex", std::to_wstring(SendMessageW(g_app.gameCombo, CB_GETCURSEL, 0, 0)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"serverName", trim(getWindowTextString(g_app.serverNameEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"serverDir", trim(getWindowTextString(g_app.serverDirEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"port", trim(getWindowTextString(g_app.portEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"launcher", L"addr", trim(getWindowTextString(g_app.addrEdit)).c_str(), path.c_str());
    WritePrivateProfileStringW(
        L"launcher",
        L"forceLocal",
        (SendMessageW(g_app.forceLocalCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) ? L"1" : L"0",
        path.c_str());
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
    setWindowTextString(g_app.portEdit, readIniValue(L"port", L"9900"));
    setWindowTextString(g_app.addrEdit, readIniValue(L"addr", L"0.0.0.0"));
    SendMessageW(
        g_app.forceLocalCheck,
        BM_SETCHECK,
        (readIniValue(L"forceLocal", L"0") == L"1") ? BST_CHECKED : BST_UNCHECKED,
        0);
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

    g_app.forceLocalCheck = CreateWindowExW(
        0,
        L"BUTTON",
        L"Same-machine mode (--same-machine)",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        left + 470,
        y,
        230,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdForceLocal),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.forceLocalCheck);
    SendMessageW(g_app.forceLocalCheck, BM_SETCHECK, BST_UNCHECKED, 0);

    g_app.enableAddrFixupsCheck = CreateWindowExW(
        0,
        L"BUTTON",
        L"ENABLE_GAME_ADDR_FIXUPS",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        left + 710,
        y,
        250,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdEnableAddrFixups),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.enableAddrFixupsCheck);
    SendMessageW(g_app.enableAddrFixupsCheck, BM_SETCHECK, BST_CHECKED, 0);

    y += rowHeight + rowGap;

    g_app.disablePatchingCheck = CreateWindowExW(
        0,
        L"BUTTON",
        L"Disable binary patching (-n)",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        left,
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

    g_app.startButton = CreateWindowExW(
        0,
        L"BUTTON",
        L"Start",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        left + 2 * (buttonWidth + 8),
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
        left + 3 * (buttonWidth + 8),
        y,
        buttonWidth,
        rowHeight,
        window,
        reinterpret_cast<HMENU>(kIdStop),
        nullptr,
        nullptr);
    applyDefaultFontToWindow(g_app.stopButton);

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

    case kIdForceLocal:
        if (commandCode == BN_CLICKED)
        {
            const bool enabled = (SendMessageW(g_app.forceLocalCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
            if (enabled)
            {
                SendMessageW(g_app.enableAddrFixupsCheck, BM_SETCHECK, BST_CHECKED, 0);
                setWindowTextString(g_app.addrEdit, L"127.0.0.1");
                appendLogLine(L"Same-machine mode enabled: FORCE_LOCAL=1, ADDR=127.0.0.1, ENABLE_GAME_ADDR_FIXUPS=1");
            }
            else
            {
                appendLogLine(L"Same-machine mode disabled in UI.");
            }
            applyFieldsToConfigEditor();
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

    case kIdStop:
        stopWorker();
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

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int showCommand)
{
    wchar_t executablePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, executablePath, MAX_PATH);
    g_app.exePath = executablePath;

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
        910,
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
