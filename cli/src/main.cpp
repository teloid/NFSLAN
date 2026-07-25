// nfslan-server: portable standalone LAN server for NFS Underground 2 and
// Most Wanted.
//
// Unlike the Windows worker (NFSLAN.cpp), this binary does not load the game's
// server.dll — it speaks the protocol itself, so it runs natively on macOS,
// Linux and Windows on any CPU architecture.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "nfslan/beacon.hpp"
#include "nfslan/config.hpp"
#include "nfslan/discovery.hpp"
#include "nfslan/lobby.hpp"
#include "nfslan/net.hpp"

namespace {

std::atomic<bool> gStopRequested{false};

void handleSignal(int) { gStopRequested.store(true); }

void printUsage(const char* program) {
    std::printf(
        "nfslan-server - standalone LAN server for NFS Underground 2 / Most Wanted\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  --name <text>        Server name shown in the game's LAN list\n"
        "  --game <u2|mw>       Which game to advertise (default: u2)\n"
        "  --ident <IDENT>      Protocol ident, e.g. NFSU2NA, NFSU2, NFSMWNA\n"
        "                       Clients hide servers whose ident does not match\n"
        "                       their build. Defaults from --game.\n"
        "  --port <n>           Lobby port advertised to clients (default: 9900)\n"
        "  --discovery-port <n> LAN discovery port (default: 9999)\n"
        "  --addr <ip>          Address to advertise (default: auto-detect)\n"
        "  --config <path>      Read settings from a server.cfg (default: ./server.cfg\n"
        "                       when present)\n"
        "  --interval <ms>      Beacon announce interval (default: 1000)\n"
        "  --no-broadcast       Only answer queries, never announce unsolicited\n"
        "  --no-loopback        Do not announce to 127.0.0.1 (breaks same-PC play)\n"
        "  --discover [secs]    Do not serve; listen for other servers and print\n"
        "                       what is on the LAN (default: 5 seconds)\n"
        "  --no-lobby           Do not listen on the lobby port at all\n"
        "  --ack-unknown        Acknowledge lobby verbs with no handler, so a client keeps\n                       walking its state machine and reveals the next request\n  --capture <path>     Append the lobby handshake hex dump to a file.\n"
        "                       Use this to reverse the session protocol: point a\n"
        "                       real client at the server and read the transcript.\n"
        "  --verbose            Log every packet decision\n"
        "  --help               Show this help\n"
        "\n"
        "Examples:\n"
        "  %s --name \"Living Room\" --game u2\n"
        "  %s --game mw --ident NFSMWNA --port 9900\n"
        "  %s --discover 10\n",
        program, program, program, program);
}

// Minimal argument parsing: returns false when the program should exit.
struct Options {
    nfslan::ServerConfig config;
    std::string configPath;
    bool configPathExplicit = false;
    bool discoverOnly = false;
    int discoverSeconds = 5;
    bool showHelp = false;
    bool runLobby = true;
    bool captureOnly = false;
    bool ackUnknown = false;
    std::string capturePath;

    // Set when the flag was given, so CLI wins over the config file.
    bool nameFromCli = false;
    bool identFromCli = false;
    bool gameFromCli = false;
    bool portFromCli = false;
    bool discoveryPortFromCli = false;
    bool addrFromCli = false;
    bool intervalFromCli = false;
    bool broadcastFromCli = false;
    bool loopbackFromCli = false;
};

bool parseArguments(int argc, char** argv, Options* options, std::string* error) {
    const auto needsValue = [&](int index, const char* flag) -> bool {
        if (index + 1 >= argc) {
            *error = std::string("missing value for ") + flag;
            return false;
        }
        return true;
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            options->showHelp = true;
            return true;
        } else if (arg == "--name") {
            if (!needsValue(i, "--name")) return false;
            options->config.serverName = argv[++i];
            options->nameFromCli = true;
        } else if (arg == "--game") {
            if (!needsValue(i, "--game")) return false;
            const std::string value = argv[++i];
            const auto game = nfslan::parseGame(value);
            if (!game) {
                *error = "unknown --game '" + value + "' (expected u2 or mw)";
                return false;
            }
            options->config.game = *game;
            options->gameFromCli = true;
        } else if (arg == "--ident") {
            if (!needsValue(i, "--ident")) return false;
            options->config.lobbyIdent = argv[++i];
            options->identFromCli = true;
        } else if (arg == "--port") {
            if (!needsValue(i, "--port")) return false;
            const int value = std::atoi(argv[++i]);
            if (value <= 0 || value > 65535) {
                *error = "--port must be between 1 and 65535";
                return false;
            }
            options->config.lobbyPort = static_cast<std::uint16_t>(value);
            options->portFromCli = true;
        } else if (arg == "--discovery-port") {
            if (!needsValue(i, "--discovery-port")) return false;
            const int value = std::atoi(argv[++i]);
            if (value <= 0 || value > 65535) {
                *error = "--discovery-port must be between 1 and 65535";
                return false;
            }
            options->config.discoveryPort = static_cast<std::uint16_t>(value);
            options->discoveryPortFromCli = true;
        } else if (arg == "--addr") {
            if (!needsValue(i, "--addr")) return false;
            options->config.advertisedAddress = argv[++i];
            options->addrFromCli = true;
        } else if (arg == "--config") {
            if (!needsValue(i, "--config")) return false;
            options->configPath = argv[++i];
            options->configPathExplicit = true;
        } else if (arg == "--interval") {
            if (!needsValue(i, "--interval")) return false;
            const int value = std::atoi(argv[++i]);
            if (value < 100) {
                *error = "--interval must be at least 100 ms";
                return false;
            }
            options->config.beaconIntervalMs = value;
            options->intervalFromCli = true;
        } else if (arg == "--no-broadcast") {
            options->config.announceToBroadcast = false;
            options->broadcastFromCli = true;
        } else if (arg == "--no-loopback") {
            options->config.announceToLoopback = false;
            options->loopbackFromCli = true;
        } else if (arg == "--discover") {
            options->discoverOnly = true;
            // Optional numeric argument.
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                const int value = std::atoi(argv[++i]);
                if (value > 0) {
                    options->discoverSeconds = value;
                }
            }
        } else if (arg == "--no-lobby") {
            options->runLobby = false;
        } else if (arg == "--ack-unknown") {
            options->ackUnknown = true;
        } else if (arg == "--capture-only") {
            options->captureOnly = true;
        } else if (arg == "--capture") {
            if (!needsValue(i, "--capture")) return false;
            options->capturePath = argv[++i];
        } else if (arg == "--verbose" || arg == "-v") {
            options->config.verbose = true;
        } else {
            *error = "unknown option '" + arg + "' (try --help)";
            return false;
        }
    }

    return true;
}

// Re-applies CLI flags on top of a config file so explicit flags always win.
void reapplyCliOverrides(const Options& cli, nfslan::ServerConfig* config) {
    if (cli.nameFromCli) config->serverName = cli.config.serverName;
    if (cli.identFromCli) config->lobbyIdent = cli.config.lobbyIdent;
    if (cli.gameFromCli) config->game = cli.config.game;
    if (cli.portFromCli) config->lobbyPort = cli.config.lobbyPort;
    if (cli.discoveryPortFromCli) config->discoveryPort = cli.config.discoveryPort;
    if (cli.addrFromCli) config->advertisedAddress = cli.config.advertisedAddress;
    if (cli.intervalFromCli) config->beaconIntervalMs = cli.config.beaconIntervalMs;
    if (cli.broadcastFromCli) config->announceToBroadcast = cli.config.announceToBroadcast;
    if (cli.loopbackFromCli) config->announceToLoopback = cli.config.announceToLoopback;
    if (cli.config.verbose) config->verbose = true;
}

int runDiscovery(const Options& options) {
    std::printf("Listening for NFS LAN servers on UDP %u for %d seconds...\n",
                options.config.discoveryPort, options.discoverSeconds);

    nfslan::UdpSocket socket;
    if (!socket.open()) {
        std::fprintf(stderr, "error: %s\n", socket.lastError().c_str());
        return 1;
    }
    socket.setReuseAddress(true);
    socket.setBroadcast(true);
    if (!socket.bind(options.config.discoveryPort)) {
        std::fprintf(stderr, "error: %s\n", socket.lastError().c_str());
        return 1;
    }
    socket.setReceiveTimeout(200);

    // Prompt anything already running to identify itself immediately.
    const auto query = nfslan::encodeDiscoveryQuery();
    for (std::uint32_t address : nfslan::broadcastAddresses()) {
        socket.sendTo({address, options.config.discoveryPort}, query.data(), query.size());
    }
    socket.sendTo({nfslan::kAddrLoopback, options.config.discoveryPort}, query.data(), query.size());

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(options.discoverSeconds);
    std::vector<std::string> seen;

    while (std::chrono::steady_clock::now() < deadline && !gStopRequested.load()) {
        auto datagram = socket.receive(nfslan::kBeaconLength * 2);
        if (!datagram) {
            continue;
        }

        const auto beacon = nfslan::decodeBeacon(datagram->data);
        if (!beacon) {
            if (options.config.verbose) {
                std::printf("  (ignored %zu bytes from %s)\n", datagram->data.size(),
                            datagram->from.toString().c_str());
            }
            continue;
        }

        const std::string key = datagram->from.toString() + "/" + beacon->name;
        bool alreadySeen = false;
        for (const std::string& existing : seen) {
            if (existing == key) {
                alreadySeen = true;
                break;
            }
        }
        if (alreadySeen) {
            continue;
        }
        seen.push_back(key);

        std::printf("  %-24s ident=%-8s port=%-5s from %s\n", beacon->name.c_str(),
                    beacon->ident.c_str(),
                    beacon->advertisedPort() ? std::to_string(*beacon->advertisedPort()).c_str() : "?",
                    nfslan::ipv4ToString(datagram->from.address).c_str());
    }

    if (seen.empty()) {
        std::printf("No servers answered.\n");
    } else {
        std::printf("\n%zu server(s) found.\n", seen.size());
    }
    return 0;
}

int runServer(const nfslan::ServerConfig& config, const Options& options) {
    // Resolve the address we advertise, purely for the status banner: clients
    // connect back to the source address of our beacon, so this is advisory.
    std::string advertised = config.advertisedAddress;
    if (advertised.empty()) {
        if (auto detected = nfslan::preferredLocalAddress()) {
            advertised = nfslan::ipv4ToString(*detected);
        } else {
            advertised = "127.0.0.1";
            std::printf(
                "warning: could not detect a LAN address; only same-machine clients will "
                "connect\n");
        }
    }

    nfslan::DiscoverySettings settings;
    settings.ident = config.effectiveIdent();
    settings.serverName = config.serverName;
    settings.lobbyPort = config.lobbyPort;
    settings.discoveryPort = config.discoveryPort;
    settings.beaconIntervalMs = config.beaconIntervalMs;
    settings.announceToLoopback = config.announceToLoopback;
    settings.announceToBroadcast = config.announceToBroadcast;
    settings.verbose = config.verbose;

    nfslan::DiscoveryService discovery(settings, [](const std::string& message) {
        std::printf("  %s\n", message.c_str());
        std::fflush(stdout);
    });

    if (!discovery.start()) {
        std::fprintf(stderr, "error: could not start LAN discovery: %s\n",
                     discovery.lastError().c_str());
        if (discovery.lastError().find("dress already in use") != std::string::npos ||
            discovery.lastError().find("Address already in use") != std::string::npos) {
            std::fprintf(stderr,
                         "hint: something already holds UDP %u (another server, or the game "
                         "itself)\n",
                         config.discoveryPort);
        }
        return 1;
    }

    // The lobby listener is what a client dials after picking us out of the LAN
    // list. Without it the game hangs on "connecting to lobby" with nothing to
    // connect to, so run it by default even though it cannot serve a session yet.
    const auto logLine = [](const std::string& message) {
        std::printf("  %s\n", message.c_str());
        std::fflush(stdout);
    };

    nfslan::LobbySettings lobbySettings;
    lobbySettings.port = config.lobbyPort;
    lobbySettings.mode = options.captureOnly ? nfslan::LobbyMode::Capture : nfslan::LobbyMode::Serve;
    lobbySettings.capturePath = options.capturePath;
    lobbySettings.verbose = config.verbose;
    // The client reconnects to whatever we name in the "@dir" reply, so this has
    // to be an address it can reach — the same one we advertise.
    lobbySettings.redirectAddress = nfslan::parseIpv4(advertised).value_or(0);
    lobbySettings.redirectPort = config.lobbyPort;
    lobbySettings.ackUnknownTags = options.ackUnknown;

    nfslan::LobbyService lobby(lobbySettings, logLine);
    bool lobbyRunning = false;
    if (options.runLobby) {
        lobbyRunning = lobby.start();
        if (!lobbyRunning) {
            std::fprintf(stderr, "warning: could not listen on lobby port %u: %s\n",
                         config.lobbyPort, lobby.lastError().c_str());
        }
    }

    std::printf("nfslan-server running\n");
    std::printf("  game        %s\n", std::string(nfslan::toString(config.game)).c_str());
    std::printf("  name        %s\n", config.serverName.c_str());
    std::printf("  ident       %s\n", settings.ident.c_str());
    std::printf("  address     %s\n", advertised.c_str());
    std::printf("  discovery   UDP %u, announcing every %d ms%s\n", config.discoveryPort,
                config.beaconIntervalMs, config.announceToBroadcast ? "" : " (queries only)");
    if (lobbyRunning) {
        std::printf("  lobby       TCP %u, %s%s\n", config.lobbyPort,
                    options.captureOnly ? "capture only (no replies)" : "answering handshake",
                    options.capturePath.empty() ? "" : (" -> " + options.capturePath).c_str());
        std::printf(
            "\nNote: the handshake is answered up to the point where the client asks to\n"
            "authenticate; the persona/room/game flow after that is not implemented, so a\n"
            "client gets past 'connecting to lobby' but cannot start a race yet.\n");
    } else {
        std::printf("  lobby       not listening (clients will hang on connect)\n");
    }
    std::printf("\nPress Ctrl+C to stop.\n\n");
    std::fflush(stdout);

    auto lastReport = std::chrono::steady_clock::now();
    std::uint64_t lastAnswered = 0;

    while (!gStopRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        const auto now = std::chrono::steady_clock::now();
        if (now - lastReport >= std::chrono::seconds(10)) {
            const std::uint64_t answered = discovery.stats().queriesAnswered.load();
            if (answered != lastAnswered) {
                std::printf("  %llu discovery quer%s answered\n",
                            static_cast<unsigned long long>(answered), answered == 1 ? "y" : "ies");
                std::fflush(stdout);
                lastAnswered = answered;
            }
            lastReport = now;
        }
    }

    std::printf("\nStopping...\n");
    discovery.stop();
    if (lobbyRunning) {
        lobby.stop();
    }

    std::printf("  announcements sent   %llu\n",
                static_cast<unsigned long long>(discovery.stats().announcementsSent.load()));
    std::printf("  queries answered     %llu\n",
                static_cast<unsigned long long>(discovery.stats().queriesAnswered.load()));
    std::printf("  other servers seen   %llu\n",
                static_cast<unsigned long long>(discovery.stats().foreignBeaconsSeen.load()));
    if (lobbyRunning) {
        std::printf("  lobby connections    %llu\n",
                    static_cast<unsigned long long>(lobby.stats().connectionsAccepted.load()));
        std::printf("  lobby bytes received %llu\n",
                    static_cast<unsigned long long>(lobby.stats().bytesReceived.load()));
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    std::string error;

    if (!parseArguments(argc, argv, &options, &error)) {
        std::fprintf(stderr, "error: %s\n", error.c_str());
        return 2;
    }
    if (options.showHelp) {
        printUsage(argv[0]);
        return 0;
    }

    nfslan::NetStartup netStartup;
    if (!netStartup.ok()) {
        std::fprintf(stderr, "error: %s\n", netStartup.error().c_str());
        return 1;
    }

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    // A config file is optional: use ./server.cfg when it happens to be there,
    // but only complain about a missing file the user named explicitly.
    nfslan::ServerConfig config = options.config;
    const std::string configPath = options.configPathExplicit ? options.configPath : "server.cfg";
    auto loaded = nfslan::loadServerConfigFile(configPath, options.config);
    if (!loaded.ok) {
        std::fprintf(stderr, "error: %s\n", loaded.error.c_str());
        return 1;
    }
    config = loaded.config;
    reapplyCliOverrides(options, &config);

    for (const std::string& warning : loaded.warnings) {
        const bool missingFile = warning.find("not found") != std::string::npos;
        if (missingFile && !options.configPathExplicit) {
            continue;  // no server.cfg in cwd is perfectly normal
        }
        std::printf("warning: %s\n", warning.c_str());
    }

    if (options.discoverOnly) {
        Options discoverOptions = options;
        discoverOptions.config = config;
        return runDiscovery(discoverOptions);
    }

    return runServer(config, options);
}
