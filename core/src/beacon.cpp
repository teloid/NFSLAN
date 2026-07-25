#include "nfslan/beacon.hpp"

#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace nfslan {
namespace {

// Tab counts as text here: the transport field is tab-separated
// ("TCP:~1:1024\tUDP:~1:1024"), so rejecting it would truncate that field.
bool isFieldText(std::uint8_t value) {
    return (value >= 32 && value <= 126) || value == '\t';
}

// Reads a NUL-terminated ASCII field, stopping at the first NUL, the first
// non-text byte, or the field width — whichever comes first.
std::string readField(const std::uint8_t* data, std::size_t length, std::size_t offset,
                      std::size_t maxLength) {
    if (!data || offset >= length) {
        return {};
    }
    const std::size_t bound = std::min(maxLength, length - offset);
    std::string out;
    out.reserve(bound);
    for (std::size_t i = 0; i < bound; ++i) {
        const std::uint8_t value = data[offset + i];
        if (value == 0 || !isFieldText(value)) {
            break;
        }
        out.push_back(static_cast<char>(value));
    }
    return out;
}

void writeField(std::uint8_t* data, std::size_t length, std::size_t offset, std::size_t maxLength,
                const std::string& value) {
    if (!data || offset >= length || maxLength == 0) {
        return;
    }
    const std::size_t bound = std::min(maxLength, length - offset);
    if (bound == 0) {
        return;
    }
    // Reserve one byte for the terminator so the field is always NUL-ended.
    const std::size_t copyLength = std::min(value.size(), bound - 1);
    if (copyLength > 0) {
        std::memcpy(data + offset, value.data(), copyLength);
    }
    data[offset + copyLength] = 0;
}

bool hasMagic(const std::uint8_t* data, std::size_t length) {
    return data && length >= 9 && data[0] == 'g' && data[1] == 'E' && data[2] == 'A';
}


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

}  // namespace

std::string_view toString(Game game) {
    return game == Game::Underground2 ? "Underground2" : "MostWanted";
}

std::optional<Game> parseGame(std::string_view text) {
    if (text == "u2" || text == "U2" || text == "underground2" || text == "Underground2") {
        return Game::Underground2;
    }
    if (text == "mw" || text == "MW" || text == "mostwanted" || text == "MostWanted") {
        return Game::MostWanted;
    }
    return std::nullopt;
}

std::optional<std::uint16_t> Beacon::advertisedPort() const {
    const std::size_t separator = stats.find('|');
    const std::string portText = trim(separator == std::string::npos ? stats : stats.substr(0, separator));
    if (portText.empty()) {
        return std::nullopt;
    }
    for (char c : portText) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return std::nullopt;
        }
    }
    const unsigned long parsed = std::stoul(portText);
    if (parsed == 0 || parsed > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(parsed);
}

bool isBeacon(const std::uint8_t* data, std::size_t length) {
    if (!hasMagic(data, length) || length != kBeaconLength) {
        return false;
    }
    // Byte 3 is the advertise interval, not a type tag — stock receivers do not
    // check it, so neither do we. A '?' in the ident field means query.
    if (data[kBeaconIdentOffset] == '?') {
        return false;
    }
    // Stock receivers treat "has a non-empty name" as the announcement test.
    return data[kBeaconNameOffset] != 0;
}

bool isDiscoveryQuery(const std::uint8_t* data, std::size_t length) {
    if (!hasMagic(data, length)) {
        return false;
    }
    return data[kBeaconIdentOffset] == '?';
}

std::array<std::uint8_t, kBeaconLength> encodeBeacon(const std::string& ident,
                                                     const std::string& name, std::uint16_t port,
                                                     int players, const std::string& transport,
                                                     std::uint8_t advertiseInterval) {
    std::array<std::uint8_t, kBeaconLength> packet{};
    packet[0] = 'g';
    packet[1] = 'E';
    packet[2] = 'A';
    packet[kBeaconIntervalOffset] = advertiseInterval;

    const std::string effectiveIdent = trim(ident).empty() ? kIdentUg2NorthAmerica : trim(ident);
    const std::string effectiveName = trim(name).empty() ? "NFSLAN Server" : trim(name);
    const std::uint16_t effectivePort = port == 0 ? kDefaultLobbyPort : port;
    const std::string stats =
        std::to_string(effectivePort) + "|" + std::to_string(players < 0 ? 0 : players);

    writeField(packet.data(), packet.size(), kBeaconIdentOffset, kBeaconIdentMax, effectiveIdent);
    writeField(packet.data(), packet.size(), kBeaconNameOffset, kBeaconNameMax, effectiveName);
    writeField(packet.data(), packet.size(), kBeaconStatsOffset, kBeaconStatsMax, stats);
    writeField(packet.data(), packet.size(), kBeaconTransportOffset, kBeaconTransportMax, transport);

    return packet;
}

std::array<std::uint8_t, kBeaconLength> encodeWithdrawal(const std::string& ident,
                                                         const std::string& name,
                                                         std::uint16_t port) {
    // Same packet with an empty transport field: receivers drop the row at once.
    return encodeBeacon(ident, name, port, 0, std::string());
}

std::array<std::uint8_t, kBeaconLength> encodeDiscoveryQuery() {
    std::array<std::uint8_t, kBeaconLength> packet{};
    packet[0] = 'g';
    packet[1] = 'E';
    packet[2] = 'A';
    packet[kBeaconIdentOffset] = '?';
    return packet;
}

std::optional<Beacon> decodeBeacon(const std::uint8_t* data, std::size_t length) {
    if (!isBeacon(data, length)) {
        return std::nullopt;
    }

    Beacon beacon;
    beacon.ident = readField(data, length, kBeaconIdentOffset, kBeaconIdentMax);
    beacon.name = readField(data, length, kBeaconNameOffset, kBeaconNameMax);
    beacon.stats = readField(data, length, kBeaconStatsOffset, kBeaconStatsMax);
    beacon.transport = readField(data, length, kBeaconTransportOffset, kBeaconTransportMax);
    beacon.advertiseInterval = data[kBeaconIntervalOffset];
    return beacon;
}

std::optional<int> Beacon::playerCount() const {
    const std::size_t separator = stats.find('|');
    if (separator == std::string::npos) {
        return std::nullopt;
    }
    const std::string text = trim(stats.substr(separator + 1));
    if (text.empty()) {
        return std::nullopt;
    }
    for (char c : text) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return std::nullopt;
        }
    }
    return std::stoi(text);
}

bool rewriteBeaconIdent(std::uint8_t* data, std::size_t length, const std::string& ident) {
    if (!isBeacon(data, length)) {
        return false;
    }
    const std::string effective = trim(ident);
    if (effective.empty()) {
        return false;
    }
    // Clear the whole field first so a shorter ident cannot leave stale bytes.
    std::memset(data + kBeaconIdentOffset, 0, kBeaconIdentMax);
    writeField(data, length, kBeaconIdentOffset, kBeaconIdentMax, effective);
    return true;
}

std::string defaultIdentFor(Game game) {
    return game == Game::Underground2 ? kIdentUg2NorthAmerica : kIdentMwNorthAmerica;
}

std::string hexPreview(const std::uint8_t* data, std::size_t length, std::size_t bytes) {
    if (!data || length == 0) {
        return {};
    }
    const std::size_t count = std::min(length, bytes);
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < count; ++i) {
        if (i > 0) {
            stream << ' ';
        }
        stream << std::setw(2) << static_cast<int>(data[i]);
    }
    return stream.str();
}

}  // namespace nfslan
