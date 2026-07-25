// Protocol codec tests. No network, no fixtures — pure encode/decode checks
// against the wire format the games actually use.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "nfslan/beacon.hpp"
#include "nfslan/config.hpp"
#include "nfslan/net.hpp"

namespace {

int gFailures = 0;
int gChecks = 0;

void check(bool condition, const std::string& what) {
    ++gChecks;
    if (!condition) {
        ++gFailures;
        std::printf("  FAIL: %s\n", what.c_str());
    }
}

void checkEqualStr(const std::string& actual, const std::string& expected, const std::string& what) {
    ++gChecks;
    if (actual != expected) {
        ++gFailures;
        std::printf("  FAIL: %s (got '%s', want '%s')\n", what.c_str(), actual.c_str(),
                    expected.c_str());
    }
}

void checkEqualInt(long long actual, long long expected, const std::string& what) {
    ++gChecks;
    if (actual != expected) {
        ++gFailures;
        std::printf("  FAIL: %s (got %lld, want %lld)\n", what.c_str(), actual, expected);
    }
}

void testBeaconRoundTrip() {
    std::printf("beacon: round trip\n");

    const auto packet = nfslan::encodeBeacon("NFSU2NA", "Teloid's Garage", 9900);

    checkEqualInt(static_cast<long long>(packet.size()), 0x180, "beacon is 0x180 bytes");
    check(packet[0] == 'g' && packet[1] == 'E' && packet[2] == 'A', "magic is 'gEA'");
    checkEqualInt(packet[3], 0x03, "byte 3 is 0x03");
    check(nfslan::isBeacon(packet.data(), packet.size()), "encoded packet is a beacon");
    check(!nfslan::isDiscoveryQuery(packet.data(), packet.size()), "beacon is not a query");

    const auto decoded = nfslan::decodeBeacon(packet.data(), packet.size());
    check(decoded.has_value(), "beacon decodes");
    if (decoded) {
        checkEqualStr(decoded->ident, "NFSU2NA", "ident round trips");
        checkEqualStr(decoded->name, "Teloid's Garage", "name round trips");
        checkEqualStr(decoded->stats, "9900|0", "stats carry '<port>|0'");
        checkEqualStr(decoded->transport, "TCP:~1:1024\tUDP:~1:1024", "transport caps round trip");
        check(decoded->advertisedPort().has_value(), "advertised port parses");
        if (decoded->advertisedPort()) {
            checkEqualInt(*decoded->advertisedPort(), 9900, "advertised port is 9900");
        }
    }
}

void testBeaconFieldOffsets() {
    std::printf("beacon: field offsets match the wire format\n");

    const auto packet = nfslan::encodeBeacon("NFSMWNA", "MW Host", 9900);

    // Fields must sit at exactly these offsets or clients will not parse them.
    check(std::memcmp(packet.data() + 0x08, "NFSMWNA", 7) == 0, "ident at 0x08");
    check(std::memcmp(packet.data() + 0x28, "MW Host", 7) == 0, "name at 0x28");
    check(std::memcmp(packet.data() + 0x48, "9900|0", 6) == 0, "stats at 0x48");
    check(std::memcmp(packet.data() + 0x108, "TCP:", 4) == 0, "transport at 0x108");

    // Gaps between fields stay zero, as in stock beacons.
    bool gapIsZero = true;
    for (std::size_t i = 0x10; i < 0x28; ++i) {
        gapIsZero = gapIsZero && packet[i] == 0;
    }
    check(gapIsZero, "gap between ident and name is zero-filled");
}

void testBeaconTruncationAndPadding() {
    std::printf("beacon: over-long fields are truncated safely\n");

    const std::string longName(200, 'A');
    const auto packet = nfslan::encodeBeacon("NFSU2NA", longName, 9900);

    check(nfslan::isBeacon(packet.data(), packet.size()), "still a valid beacon");
    const auto decoded = nfslan::decodeBeacon(packet.data(), packet.size());
    check(decoded.has_value(), "over-long name still decodes");
    if (decoded) {
        // 0x20-byte field, one byte reserved for the terminator.
        checkEqualInt(static_cast<long long>(decoded->name.size()), 0x1F,
                      "name truncated to field width");
    }
    // Truncation must not bleed into the next field.
    check(std::memcmp(packet.data() + 0x48, "9900|0", 6) == 0, "stats survive name truncation");
}

void testDiscoveryQuery() {
    std::printf("beacon: discovery query\n");

    const auto query = nfslan::encodeDiscoveryQuery();
    check(nfslan::isDiscoveryQuery(query.data(), query.size()), "query is recognised");
    check(!nfslan::isBeacon(query.data(), query.size()), "query is not a beacon");
    checkEqualInt(query[0x08], '?', "'?' sits at offset 8");
}

void testBeaconRejection() {
    std::printf("beacon: malformed input is rejected\n");

    check(!nfslan::isBeacon(nullptr, 0), "null is not a beacon");

    std::vector<std::uint8_t> tooShort(16, 0);
    tooShort[0] = 'g';
    tooShort[1] = 'E';
    tooShort[2] = 'A';
    check(!nfslan::isBeacon(tooShort.data(), tooShort.size()), "short packet is not a beacon");

    auto wrongMagic = nfslan::encodeBeacon("NFSU2NA", "x", 9900);
    wrongMagic[0] = 'X';
    check(!nfslan::isBeacon(wrongMagic.data(), wrongMagic.size()), "bad magic is rejected");

    auto wrongType = nfslan::encodeBeacon("NFSU2NA", "x", 9900);
    wrongType[3] = 0x01;
    check(!nfslan::isBeacon(wrongType.data(), wrongType.size()), "bad type byte is rejected");

    auto wrongIdent = nfslan::encodeBeacon("NFSU2NA", "x", 9900);
    std::memcpy(wrongIdent.data() + 0x08, "XXXX", 4);
    check(!nfslan::isBeacon(wrongIdent.data(), wrongIdent.size()), "non-NFS ident is rejected");
}

void testIdentRewrite() {
    std::printf("beacon: ident rewrite (region compatibility)\n");

    auto packet = nfslan::encodeBeacon("NFSU2NA", "Host", 9900);
    check(nfslan::rewriteBeaconIdent(packet.data(), packet.size(), "NFSU2"), "rewrite succeeds");

    const auto decoded = nfslan::decodeBeacon(packet.data(), packet.size());
    check(decoded.has_value(), "rewritten beacon decodes");
    if (decoded) {
        // The longer old value must not leave a trailing "NA" behind.
        checkEqualStr(decoded->ident, "NFSU2", "ident fully replaced");
        checkEqualStr(decoded->name, "Host", "name untouched by rewrite");
    }

    auto notABeacon = nfslan::encodeDiscoveryQuery();
    check(!nfslan::rewriteBeaconIdent(notABeacon.data(), notABeacon.size(), "NFSU2"),
          "rewrite refuses non-beacons");
}

void testConfigParsing() {
    std::printf("config: server.cfg parsing\n");

    const std::string text =
        "# NFSLAN test config\n"
        "SERVER_NAME=Living Room\r\n"
        "LOBBY_IDENT=NFSU2NA\n"
        "LOBBY=NFSU2NA\n"
        "PORT=9900\n"
        "ADDR=0.0.0.0\n"
        "PINGTIME=20\n"
        "\n"
        "; semicolon comment\n"
        "BEACON_INTERVAL_MS=500\n";

    const auto result = nfslan::parseServerConfig(text);
    check(result.ok, "parse succeeds");
    checkEqualStr(result.config.serverName, "Living Room", "SERVER_NAME parsed, CR stripped");
    checkEqualStr(result.config.effectiveIdent(), "NFSU2NA", "ident parsed");
    checkEqualInt(result.config.lobbyPort, 9900, "PORT parsed");
    checkEqualInt(result.config.beaconIntervalMs, 500, "BEACON_INTERVAL_MS parsed");
    check(result.config.advertisedAddress.empty(), "ADDR=0.0.0.0 means auto-detect");
    check(result.config.extra.count("PINGTIME") == 1, "unknown stock keys are preserved");
    checkEqualInt(static_cast<long long>(result.warnings.size()), 0, "clean config warns nothing");
}

void testConfigDefaultsAndWarnings() {
    std::printf("config: defaults and warnings\n");

    const auto empty = nfslan::parseServerConfig("");
    checkEqualInt(empty.config.lobbyPort, 9900, "default lobby port is 9900");
    checkEqualInt(empty.config.discoveryPort, 9999, "default discovery port is 9999");
    checkEqualStr(empty.config.effectiveIdent(), "NFSU2NA", "default ident is NFSU2NA");

    // A mismatched ident is the single most common reason a server stays hidden,
    // so it must warn rather than silently "work".
    const auto mismatch = nfslan::parseServerConfig("GAME=mw\nLOBBY_IDENT=NFSU2NA\n");
    check(!mismatch.warnings.empty(), "MW config with U2 ident warns");
    checkEqualStr(std::string(nfslan::toString(mismatch.config.game)), "MostWanted", "GAME=mw parsed");

    const auto badPort = nfslan::parseServerConfig("PORT=notaport\n");
    check(!badPort.warnings.empty(), "invalid PORT warns");
    checkEqualInt(badPort.config.lobbyPort, 9900, "invalid PORT falls back to default");

    const auto bindExpr = nfslan::parseServerConfig("ADDR=%%bind(eth0)\n");
    check(bindExpr.config.advertisedAddress.empty(), "%%bind() means auto-detect");

    const auto lobbyMismatch = nfslan::parseServerConfig("LOBBY_IDENT=NFSU2NA\nLOBBY=NFSU2\n");
    check(!lobbyMismatch.warnings.empty(), "LOBBY != LOBBY_IDENT warns");
}

void testAddressHelpers() {
    std::printf("net: address helpers\n");

    const auto parsed = nfslan::parseIpv4("192.168.1.98");
    check(parsed.has_value(), "dotted quad parses");
    if (parsed) {
        checkEqualInt(*parsed, 0xC0A80162, "parsed to host byte order");
        checkEqualStr(nfslan::ipv4ToString(*parsed), "192.168.1.98", "round trips to string");
    }

    check(!nfslan::parseIpv4("not.an.ip").has_value(), "garbage is rejected");
    check(!nfslan::parseIpv4("").has_value(), "empty is rejected");
    checkEqualStr(nfslan::ipv4ToString(nfslan::kAddrLoopback), "127.0.0.1", "loopback constant");
    checkEqualStr(nfslan::ipv4ToString(nfslan::kAddrBroadcast), "255.255.255.255",
                  "broadcast constant");

    const nfslan::Endpoint endpoint{nfslan::kAddrLoopback, 9900};
    checkEqualStr(endpoint.toString(), "127.0.0.1:9900", "endpoint formats host:port");

    // Must always offer somewhere to broadcast, even with no usable interfaces.
    check(!nfslan::broadcastAddresses().empty(), "broadcast address list is never empty");
}

}  // namespace

int main() {
    std::printf("NFSLAN protocol tests\n\n");

    testBeaconRoundTrip();
    testBeaconFieldOffsets();
    testBeaconTruncationAndPadding();
    testDiscoveryQuery();
    testBeaconRejection();
    testIdentRewrite();
    testConfigParsing();
    testConfigDefaultsAndWarnings();
    testAddressHelpers();

    std::printf("\n%d checks, %d failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
