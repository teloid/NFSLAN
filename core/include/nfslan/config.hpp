// server.cfg reader.
//
// The stock format is one KEY=VALUE per line with '#' comments, as shipped with
// the games. We read the keys that matter to a LAN server and ignore the rest,
// so an untouched stock server.cfg works unchanged.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "nfslan/beacon.hpp"

namespace nfslan {

// Everything the native server needs to run, after defaults are applied.
struct ServerConfig {
    Game game = Game::Underground2;

    std::string serverName = "NFSLAN Server";
    std::string lobbyIdent;  // empty -> defaultIdentFor(game)

    // Address advertised to clients. Empty or 0.0.0.0 means "detect the LAN
    // address at startup", which is what stock configs express as %%bind(...).
    std::string advertisedAddress;

    std::uint16_t lobbyPort = kDefaultLobbyPort;
    std::uint16_t discoveryPort = kDefaultDiscoveryPort;

    // Announce interval for unsolicited beacons.
    int beaconIntervalMs = 1000;

    // Also send beacons to 127.0.0.1 so a client on this machine can see the
    // server. Harmless on a dedicated host, required for same-PC play.
    bool announceToLoopback = true;

    // Send beacons to the interface broadcast addresses as well as answering
    // queries. Stock behaviour; turn off for a query-only (quiet) server.
    bool announceToBroadcast = true;

    bool verbose = false;

    // Keys we parsed but do not act on, kept so tooling can round-trip a file.
    std::map<std::string, std::string> extra;

    std::string effectiveIdent() const {
        return lobbyIdent.empty() ? defaultIdentFor(game) : lobbyIdent;
    }
};

// Parsed result of a config load: the config plus any warnings worth printing.
struct ConfigLoadResult {
    ServerConfig config;
    std::vector<std::string> warnings;
    bool ok = true;
    std::string error;
};

// Parses server.cfg text. Never fails on unknown keys; warns on malformed
// values and falls back to the default for that key.
ConfigLoadResult parseServerConfig(const std::string& text, const ServerConfig& defaults = {});

// Reads and parses a server.cfg from disk. A missing file is not an error: the
// result carries defaults and a warning.
ConfigLoadResult loadServerConfigFile(const std::string& path, const ServerConfig& defaults = {});

// Splits "KEY=VALUE" lines into a map, preserving the original case of values
// and upper-casing keys. Exposed for tests and tooling.
std::map<std::string, std::string> parseKeyValueLines(const std::string& text);

// Guesses which game a directory holds by looking for its executable and
// server.dll, so `--game` can usually be omitted.
std::optional<Game> detectGameFromDirectory(const std::string& directory);

}  // namespace nfslan
