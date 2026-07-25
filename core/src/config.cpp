#include "nfslan/config.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace nfslan {
namespace {

std::string trim(const std::string& text) {
    std::size_t begin = 0;
    std::size_t end = text.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(text[begin]))) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
        --end;
    }
    return text.substr(begin, end - begin);
}

std::string upper(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return text;
}

bool equalsIgnoreCase(const std::string& a, const std::string& b) {
    return a.size() == b.size() && upper(a) == upper(b);
}

bool startsWithIgnoreCase(const std::string& text, const std::string& prefix) {
    return text.size() >= prefix.size() && upper(text.substr(0, prefix.size())) == upper(prefix);
}

bool isTruthy(const std::string& value) {
    const std::string normalized = upper(trim(value));
    return normalized == "1" || normalized == "TRUE" || normalized == "YES" || normalized == "ON";
}

std::optional<std::uint16_t> parsePort(const std::string& value) {
    const std::string text = trim(value);
    if (text.empty()) {
        return std::nullopt;
    }
    for (char c : text) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return std::nullopt;
        }
    }
    const unsigned long parsed = std::stoul(text);
    if (parsed == 0 || parsed > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(parsed);
}

// Stock configs write ADDR as a %%bind(...) expression the original server
// expanded at runtime. We treat that, and 0.0.0.0, as "auto-detect".
bool isAutoAddress(const std::string& value) {
    const std::string text = trim(value);
    return text.empty() || text == "0.0.0.0" || text.find("%%bind(") != std::string::npos;
}

const char* const kHandledKeys[] = {
    "SERVER_NAME", "NAME",      "LOBBY_IDENT",   "LOBBY",       "ADDR",
    "PORT",        "LAN_PORT",  "DISCOVERY_PORT", "BEACON_INTERVAL_MS",
    "ANNOUNCE_LOOPBACK", "ANNOUNCE_BROADCAST", "LAN_DIAG", "LAN_DIAGNOSTICS", "GAME",
};

bool isHandledKey(const std::string& key) {
    for (const char* known : kHandledKeys) {
        if (key == known) {
            return true;
        }
    }
    return false;
}

}  // namespace

std::map<std::string, std::string> parseKeyValueLines(const std::string& text) {
    std::map<std::string, std::string> values;
    std::istringstream stream(text);
    std::string line;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        const std::size_t separator = trimmed.find('=');
        if (separator == std::string::npos) {
            continue;
        }

        const std::string key = upper(trim(trimmed.substr(0, separator)));
        const std::string value = trim(trimmed.substr(separator + 1));
        if (!key.empty()) {
            values[key] = value;
        }
    }

    return values;
}

ConfigLoadResult parseServerConfig(const std::string& text, const ServerConfig& defaults) {
    ConfigLoadResult result;
    result.config = defaults;

    const std::map<std::string, std::string> values = parseKeyValueLines(text);
    const auto find = [&values](const char* key) -> std::optional<std::string> {
        const auto it = values.find(key);
        if (it == values.end()) {
            return std::nullopt;
        }
        return it->second;
    };

    if (auto game = find("GAME")) {
        if (auto parsed = parseGame(trim(*game))) {
            result.config.game = *parsed;
        } else {
            result.warnings.push_back("GAME='" + *game + "' is not recognised; keeping " +
                                      std::string(toString(result.config.game)));
        }
    }

    if (auto name = find("SERVER_NAME")) {
        if (!trim(*name).empty()) {
            result.config.serverName = trim(*name);
        }
    } else if (auto legacyName = find("NAME")) {
        if (!trim(*legacyName).empty()) {
            result.config.serverName = trim(*legacyName);
        }
    }

    // LOBBY_IDENT is a protocol identifier, not the display name: clients hide
    // servers whose ident does not match their build, so we validate the prefix
    // but never silently rewrite a deliberate choice.
    const std::string expectedPrefix =
        result.config.game == Game::Underground2 ? kIdentUg2 : kIdentMw;
    if (auto ident = find("LOBBY_IDENT")) {
        const std::string trimmedIdent = trim(*ident);
        if (trimmedIdent.empty()) {
            result.warnings.push_back("LOBBY_IDENT is empty; using " +
                                      defaultIdentFor(result.config.game));
        } else {
            result.config.lobbyIdent = trimmedIdent;
            if (!startsWithIgnoreCase(trimmedIdent, expectedPrefix)) {
                result.warnings.push_back("LOBBY_IDENT='" + trimmedIdent + "' does not start with '" +
                                          expectedPrefix + "'; " +
                                          std::string(toString(result.config.game)) +
                                          " clients will probably not list this server");
            }
        }
    }

    if (auto lobby = find("LOBBY")) {
        const std::string trimmedLobby = trim(*lobby);
        const std::string ident = result.config.effectiveIdent();
        if (!trimmedLobby.empty() && !equalsIgnoreCase(trimmedLobby, ident)) {
            result.warnings.push_back("LOBBY='" + trimmedLobby + "' differs from LOBBY_IDENT='" +
                                      ident + "'; clients match on LOBBY_IDENT");
        }
    }

    if (auto addr = find("ADDR")) {
        result.config.advertisedAddress = isAutoAddress(*addr) ? std::string() : trim(*addr);
    }

    if (auto port = find("PORT")) {
        if (auto parsed = parsePort(*port)) {
            result.config.lobbyPort = *parsed;
        } else {
            result.warnings.push_back("PORT='" + *port + "' is not a valid port; using " +
                                      std::to_string(result.config.lobbyPort));
        }
    }

    // LAN_PORT is the fork's own name for the discovery port; accept both.
    for (const char* key : {"DISCOVERY_PORT", "LAN_PORT"}) {
        if (auto port = find(key)) {
            if (auto parsed = parsePort(*port)) {
                result.config.discoveryPort = *parsed;
            } else {
                result.warnings.push_back(std::string(key) + "='" + *port +
                                          "' is not a valid port; using " +
                                          std::to_string(result.config.discoveryPort));
            }
        }
    }

    if (auto interval = find("BEACON_INTERVAL_MS")) {
        const std::string text = trim(*interval);
        bool digits = !text.empty();
        for (char c : text) {
            digits = digits && std::isdigit(static_cast<unsigned char>(c));
        }
        if (digits) {
            const int parsed = std::stoi(text);
            // Below ~100ms this is a broadcast flood with no upside.
            result.config.beaconIntervalMs = std::max(100, parsed);
        } else {
            result.warnings.push_back("BEACON_INTERVAL_MS='" + text + "' is not a number; using " +
                                      std::to_string(result.config.beaconIntervalMs));
        }
    }

    if (auto value = find("ANNOUNCE_LOOPBACK")) {
        result.config.announceToLoopback = isTruthy(*value);
    }
    if (auto value = find("ANNOUNCE_BROADCAST")) {
        result.config.announceToBroadcast = isTruthy(*value);
    }
    if (auto value = find("LAN_DIAG")) {
        result.config.verbose = result.config.verbose || isTruthy(*value);
    }
    if (auto value = find("LAN_DIAGNOSTICS")) {
        result.config.verbose = result.config.verbose || isTruthy(*value);
    }

    for (const auto& [key, value] : values) {
        if (!isHandledKey(key)) {
            result.config.extra[key] = value;
        }
    }

    return result;
}

ConfigLoadResult loadServerConfigFile(const std::string& path, const ServerConfig& defaults) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        ConfigLoadResult result;
        result.config = defaults;
        result.warnings.push_back("server.cfg not found at '" + path + "'; using defaults");
        return result;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        ConfigLoadResult result;
        result.config = defaults;
        result.ok = false;
        result.error = "could not open '" + path + "'";
        return result;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    return parseServerConfig(buffer.str(), defaults);
}

std::optional<Game> detectGameFromDirectory(const std::string& directory) {
    std::error_code ec;
    if (!std::filesystem::is_directory(directory, ec)) {
        return std::nullopt;
    }

    bool sawUg2 = false;
    bool sawMw = false;
    for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_regular_file()) {
            continue;
        }
        const std::string name = upper(entry.path().filename().string());
        if (name == "SPEED2.EXE") {
            sawUg2 = true;
        } else if (name == "SPEED.EXE") {
            sawMw = true;
        }
    }

    if (sawUg2 && !sawMw) {
        return Game::Underground2;
    }
    if (sawMw && !sawUg2) {
        return Game::MostWanted;
    }
    return std::nullopt;
}

}  // namespace nfslan
