// Underground 2 / Most Wanted LAN discovery beacon codec.
//
// Wire format (0x180 bytes, UDP port 9999), as modelled by the Windows worker
// in NFSLAN.cpp and confirmed against captured traffic:
//
//   0x000  'g' 'E' 'A' 0x03      magic; byte 3 is 0x03 on a beacon
//   0x008  ident, 8 bytes        ASCII, NUL-padded: "NFSU2NA", "NFSMWNA", ...
//                                on a *query* byte 0x008 is '?' instead
//   0x028  server name, 32 bytes ASCII, NUL-padded
//   0x048  stats, up to 0xC0     ASCII "<port>|<flags>", e.g. "9900|0"
//   0x108  transport, 0x40       ASCII "TCP:~1:1024\tUDP:~1:1024"
//
// Everything outside those fields stays zero, which is what stock servers send.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nfslan {

constexpr std::size_t kBeaconLength = 0x180;
constexpr std::size_t kBeaconIdentOffset = 0x08;
constexpr std::size_t kBeaconIdentMax = 0x08;
constexpr std::size_t kBeaconNameOffset = 0x28;
constexpr std::size_t kBeaconNameMax = 0x20;
constexpr std::size_t kBeaconStatsOffset = 0x48;
constexpr std::size_t kBeaconStatsMax = 0xC0;
constexpr std::size_t kBeaconTransportOffset = 0x108;
constexpr std::size_t kBeaconTransportMax = 0x40;

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
    std::string stats;      // raw stats field, usually "<port>|0"
    std::string transport;  // transport capabilities string

    // Parsed out of `stats` when it looks like "<port>|<flags>".
    std::optional<std::uint16_t> advertisedPort() const;
};

// True when `data` is a well-formed beacon *announcement* (magic + 0x03 + an
// ident starting with "NFS"). Length must be exactly kBeaconLength.
bool isBeacon(const std::uint8_t* data, std::size_t length);

// True when `data` is a discovery *query* — clients broadcast these to ask who
// is out there. Queries carry the 'gEA' magic with '?' at offset 8.
bool isDiscoveryQuery(const std::uint8_t* data, std::size_t length);

// Builds the 0x180-byte announcement a client expects to see.
std::array<std::uint8_t, kBeaconLength> encodeBeacon(const std::string& ident,
                                                     const std::string& name, std::uint16_t port,
                                                     const std::string& transport = kDefaultTransportCaps);

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
