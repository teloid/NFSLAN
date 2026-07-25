// Underground 2 / Most Wanted LAN discovery beacon codec.
//
// Wire format (0x180 bytes, UDP port 9999). Field widths come from the stock
// receiver's own stack layout, which partitions the packet exactly:
// 4 + 4 + 0x20 + 0x20 + 0xC0 + 0x78 = 0x180.
//
//   0x000  3     'g' 'E' 'A'          magic
//   0x003  1     re-advertise interval in seconds (stock sends 3). NOT a
//                message-type magic: stock receivers never validate this byte,
//                and it drives row expiry as 1000 + interval * 2000 ms.
//   0x004  4     id word (zero in stock beacons)
//   0x008  0x20  ident, ASCII + NUL   "NFSU2NA", "NFSMWNA", ...
//                                     on a *query* this field is just "?"
//   0x028  0x20  server name, ASCII + NUL
//   0x048  0xC0  stats, ASCII         "<port>|<players>", e.g. "9900|0"
//   0x108  0x78  transport, ASCII     "TCP:~1:1024\tUDP:~1:1024"
//
// Everything outside those fields stays zero, which is what stock servers send.
// An EMPTY transport field is a withdraw signal: receivers expire the row at
// once, and stock servers send exactly that as a goodbye on shutdown.
//
// Comparisons on ident/name/stats are case-insensitive in stock receivers.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nfslan {

constexpr std::size_t kBeaconLength = 0x180;
constexpr std::size_t kBeaconIntervalOffset = 0x03;
constexpr std::size_t kBeaconIdOffset = 0x04;
constexpr std::size_t kBeaconIdentOffset = 0x08;
constexpr std::size_t kBeaconIdentMax = 0x20;
constexpr std::size_t kBeaconNameOffset = 0x28;
constexpr std::size_t kBeaconNameMax = 0x20;
constexpr std::size_t kBeaconStatsOffset = 0x48;
constexpr std::size_t kBeaconStatsMax = 0xC0;
constexpr std::size_t kBeaconTransportOffset = 0x108;
constexpr std::size_t kBeaconTransportMax = 0x78;

// What stock servers put in the interval byte. Row expiry on the receiving side
// is 1000 + interval * 2000 ms, so this also sets how long a server lingers in
// a client's list after it goes away.
constexpr std::uint8_t kDefaultAdvertiseInterval = 3;

constexpr std::uint16_t kDefaultDiscoveryPort = 9999;
constexpr std::uint16_t kDefaultLobbyPort = 9900;
constexpr std::uint16_t kDefaultLocalChallengePort = 9901;

constexpr char kIdentUg2NorthAmerica[] = "NFSU2NA";
constexpr char kIdentUg2[] = "NFSU2";
constexpr char kIdentMwNorthAmerica[] = "NFSMWNA";
constexpr char kIdentMw[] = "NFSMW";

constexpr char kDefaultTransportCaps[] = "TCP:~1:1024\tUDP:~1:1024";

// Which game a server is advertising. Chooses default idents and, later, which
// lobby dialect the server speaks.
enum class Game {
    Underground2,
    MostWanted,
};

std::string_view toString(Game game);
std::optional<Game> parseGame(std::string_view text);

// The subset of a beacon that carries meaning.
struct Beacon {
    std::string ident;      // e.g. "NFSU2NA" — clients filter the LAN list on this
    std::string name;       // visible server name
    std::string stats;      // raw stats field, "<port>|<players>"
    std::string transport;  // transport capabilities; empty means "withdrawn"
    std::uint8_t advertiseInterval = kDefaultAdvertiseInterval;

    // Parsed out of `stats` when it looks like "<port>|<players>".
    std::optional<std::uint16_t> advertisedPort() const;
    std::optional<int> playerCount() const;

    // A goodbye beacon: the server is telling receivers to drop the row now.
    bool isWithdrawal() const { return transport.empty(); }
};

// True when `data` is a well-formed beacon *announcement*: 'gEA' magic, a
// non-empty name, and not a query. Deliberately does NOT check byte 3 — that is
// the advertise interval, and stock receivers accept any value.
bool isBeacon(const std::uint8_t* data, std::size_t length);

// True when `data` is a discovery *query* — clients broadcast these to ask who
// is out there. Queries carry the 'gEA' magic with '?' at offset 8.
bool isDiscoveryQuery(const std::uint8_t* data, std::size_t length);

// Builds the 0x180-byte announcement a client expects to see.
// `players` goes into the second half of the stats field; pass the live count.
std::array<std::uint8_t, kBeaconLength> encodeBeacon(
    const std::string& ident, const std::string& name, std::uint16_t port, int players = 0,
    const std::string& transport = kDefaultTransportCaps,
    std::uint8_t advertiseInterval = kDefaultAdvertiseInterval);

// Builds the goodbye beacon: identical, but with an empty transport field, which
// tells receivers to drop the row immediately instead of waiting for expiry.
std::array<std::uint8_t, kBeaconLength> encodeWithdrawal(const std::string& ident,
                                                         const std::string& name,
                                                         std::uint16_t port);

// Builds the query a client broadcasts to discover servers.
std::array<std::uint8_t, kBeaconLength> encodeDiscoveryQuery();

// Decodes a beacon; returns nullopt when isBeacon() would be false.
std::optional<Beacon> decodeBeacon(const std::uint8_t* data, std::size_t length);

inline std::optional<Beacon> decodeBeacon(const std::vector<std::uint8_t>& data) {
    return decodeBeacon(data.data(), data.size());
}

// Rewrites the ident field of an existing beacon in place, which is how the
// Windows worker makes a stock server visible to a differently-localised
// client. Returns false when `data` is not a beacon.
bool rewriteBeaconIdent(std::uint8_t* data, std::size_t length, const std::string& ident);

// The default ident for a game, used when server.cfg does not specify one.
std::string defaultIdentFor(Game game);

// Space-separated hex dump of the first `bytes` bytes, for diagnostics.
std::string hexPreview(const std::uint8_t* data, std::size_t length, std::size_t bytes = 64);

}  // namespace nfslan
