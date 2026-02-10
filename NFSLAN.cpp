// NFS LAN server launcher for Most Wanted (2005) and Underground 2
// by Xan/Tenjoin

#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <regex>
#include <fstream>
#include <sstream>
#include <optional>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <signal.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
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
};

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
        << "  --local-host    Alias for --same-machine\n";
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
        else
        {
            std::cerr << "NFSLAN: WARNING - unknown option '" << arg << "' ignored.\n";
        }
    }

    *optionsOut = options;
    return true;
}

bool ApplyServerConfigCompatibility(const WorkerLaunchOptions& options)
{
    const std::filesystem::path configPath = "server.cfg";
    if (!std::filesystem::exists(configPath))
    {
        std::cerr << "NFSLAN: WARNING - server.cfg not found. Running with server.dll defaults.\n";
        return true;
    }

    std::string configText;
    if (!ReadTextFile(configPath, &configText))
    {
        std::cerr << "ERROR: Failed to read server.cfg.\n";
        return false;
    }

    bool changed = false;
    const auto currentFixups = GetConfigValue(configText, "ENABLE_GAME_ADDR_FIXUPS");
    if (!currentFixups.has_value())
    {
        configText = UpsertConfigValue(configText, "ENABLE_GAME_ADDR_FIXUPS", "1");
        changed = true;
        std::cout << "NFSLAN: Added ENABLE_GAME_ADDR_FIXUPS=1 (recommended).\n";
    }

    if (options.sameMachineMode)
    {
        if (!IsTruthy(GetConfigValue(configText, "FORCE_LOCAL").value_or("0")))
        {
            configText = UpsertConfigValue(configText, "FORCE_LOCAL", "1");
            changed = true;
            std::cout << "NFSLAN: Same-machine mode enabled -> FORCE_LOCAL=1\n";
        }

        if (!IsTruthy(GetConfigValue(configText, "ENABLE_GAME_ADDR_FIXUPS").value_or("0")))
        {
            configText = UpsertConfigValue(configText, "ENABLE_GAME_ADDR_FIXUPS", "1");
            changed = true;
            std::cout << "NFSLAN: Same-machine mode enabled -> ENABLE_GAME_ADDR_FIXUPS=1\n";
        }
    }

    std::string gamefileValue = TrimAscii(GetConfigValue(configText, "GAMEFILE").value_or("gamefile.bin"));
    if (gamefileValue.empty())
    {
        gamefileValue = "gamefile.bin";
    }

    if (!std::filesystem::exists(std::filesystem::path(gamefileValue)))
    {
        if (std::filesystem::exists("gameplay.bin"))
        {
            if (!EqualsIgnoreCase(gamefileValue, "gameplay.bin"))
            {
                configText = UpsertConfigValue(configText, "GAMEFILE", "gameplay.bin");
                changed = true;
            }
            std::cout << "NFSLAN: GAMEFILE '" << gamefileValue
                      << "' not found; using gameplay.bin fallback.\n";
        }
        else
        {
            std::cout << "NFSLAN: WARNING - GAMEFILE '" << gamefileValue
                      << "' not found. Missing game report data may cause tier/points errors.\n";
        }
    }

    const std::string addrValue = TrimAscii(GetConfigValue(configText, "ADDR").value_or(""));
    if (!addrValue.empty())
    {
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
    }

    const std::string portValue = TrimAscii(GetConfigValue(configText, "PORT").value_or(""));
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

bool bIsUnderground2Server(uintptr_t base)
{
    // base is usually 10000000 but it's better safe than sorry
    hook::details::set_process_base(base);

    // 100013FB in MW, 100013EC in UG2
    uintptr_t defServerNamePtr = reinterpret_cast<uintptr_t>(hook::pattern("6A 03 68 66 76 64 61 53").get_first(0)) + 0x12;
    char* defServerName = *(char**)defServerNamePtr;
    if ((strstr(defServerName, "Underground 2") == nullptr) && (defServerName != nullptr))
        return false;
    return true;
}

void SigInterruptHandler(int signum)
{
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

    WorkerLaunchOptions options;
    if (!ParseWorkerLaunchOptions(argc, argv, &options))
    {
        return -1;
    }

    bDisablePatching = options.disablePatching;
    if (options.sameMachineMode)
    {
        std::cout << "NFSLAN: Same-machine mode enabled.\n";
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

    if (!ApplyServerConfigCompatibility(options))
    {
        return -1;
    }

    if (!bDisablePatching)
    {
        std::cout << "NFSLAN: Patching the server to work on any network...\n";

        if (bIsUnderground2Server((uintptr_t)serverdll))
            PatchServerUG2((uintptr_t)serverdll);
        else
            PatchServerMW((uintptr_t)serverdll);
    }

    signal(SIGINT, SigInterruptHandler);
    signal(SIGTERM, SigInterruptHandler);

    if (!StartServer(options.serverName.data(), 0, nullptr, nullptr))
    {
        std::cerr << "ERROR: could not launch server! StartServer returned false!\n";
        return -1;
    }

    if (!IsServerRunning())
    {
        std::cerr << "ERROR: could not launch server! StartServer returned true but IsServerRunning returned false!\n";
        return -1;
    }

    std::cout << "NFSLAN: Server started. To stop gracefully, send CTRL+C to the console\n";
    while (IsServerRunning()) { Sleep(1); }
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
