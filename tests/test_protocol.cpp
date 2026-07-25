// Protocol codec tests. No network, no fixtures — pure encode/decode checks
// against the wire format the games actually use.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "nfslan/beacon.hpp"
#include "nfslan/config.hpp"
#include "nfslan/net.hpp"
#include "nfslan/titan.hpp"

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
    checkEqualInt(packet[3], 3, "byte 3 is the advertise interval (stock sends 3)");
    check(nfslan::isBeacon(packet.data(), packet.size()), "encoded packet is a beacon");
    check(!nfslan::isDiscoveryQuery(packet.data(), packet.size()), "beacon is not a query");

    const auto decoded = nfslan::decodeBeacon(packet.data(), packet.size());
    check(decoded.has_value(), "beacon decodes");
    if (decoded) {
        checkEqualStr(decoded->ident, "NFSU2NA", "ident round trips");
        checkEqualStr(decoded->name, "Teloid's Garage", "name round trips");
        checkEqualStr(decoded->stats, "9900|0", "stats carry '<port>|<players>'");
        checkEqualStr(decoded->transport, "TCP:~1:1024\tUDP:~1:1024", "transport caps round trip");
        check(decoded->advertisedPort().has_value(), "advertised port parses");
        if (decoded->advertisedPort()) {
            checkEqualInt(*decoded->advertisedPort(), 9900, "advertised port is 9900");
        }
        check(decoded->playerCount().has_value(), "player count parses");
        if (decoded->playerCount()) {
            checkEqualInt(*decoded->playerCount(), 0, "empty server reports 0 players");
        }
        check(!decoded->isWithdrawal(), "a live beacon is not a withdrawal");
    }

    // The interval byte is not a type tag: stock receivers never validate it, so
    // a beacon with a different interval must still decode.
    const auto slowBeacon = nfslan::encodeBeacon("NFSU2NA", "Slow", 9900, 2, "TCP:~1:1024", 30);
    check(nfslan::isBeacon(slowBeacon.data(), slowBeacon.size()),
          "beacon with interval 30 is still a beacon");
    const auto slowDecoded = nfslan::decodeBeacon(slowBeacon.data(), slowBeacon.size());
    check(slowDecoded.has_value(), "non-stock interval still decodes");
    if (slowDecoded) {
        checkEqualInt(slowDecoded->advertiseInterval, 30, "interval round trips");
        if (slowDecoded->playerCount()) {
            checkEqualInt(*slowDecoded->playerCount(), 2, "player count round trips");
        }
    }
}

void testWithdrawal() {
    std::printf("beacon: withdrawal (goodbye) beacon\n");

    const auto packet = nfslan::encodeWithdrawal("NFSU2NA", "Going Away", 9900);
    check(nfslan::isBeacon(packet.data(), packet.size()), "withdrawal is still a valid beacon");

    const auto decoded = nfslan::decodeBeacon(packet.data(), packet.size());
    check(decoded.has_value(), "withdrawal decodes");
    if (decoded) {
        // An empty transport field is what tells receivers to drop the row now.
        check(decoded->transport.empty(), "transport field is empty");
        check(decoded->isWithdrawal(), "recognised as a withdrawal");
        checkEqualStr(decoded->name, "Going Away", "name still present so the row can be matched");
    }
    checkEqualInt(packet[0x108], 0, "transport field starts with NUL on the wire");
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

    // A nameless packet is what stock receivers ignore, and it is how a query is
    // distinguished from an announcement.
    auto noName = nfslan::encodeBeacon("NFSU2NA", "x", 9900);
    noName[nfslan::kBeaconNameOffset] = 0;
    check(!nfslan::isBeacon(noName.data(), noName.size()), "beacon with no name is rejected");

    // An unfamiliar ident must still parse: idents vary by region and by mod,
    // and rejecting them would hide servers the game itself would list.
    auto foreignIdent = nfslan::encodeBeacon("NFSPS2X", "x", 9900);
    check(nfslan::isBeacon(foreignIdent.data(), foreignIdent.size()),
          "unfamiliar ident is still accepted");
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

    const auto parsed = nfslan::parseIpv4("192.168.1.20");
    check(parsed.has_value(), "dotted quad parses");
    if (parsed) {
        checkEqualInt(*parsed, 0xC0A80114, "parsed to host byte order");
        checkEqualStr(nfslan::ipv4ToString(*parsed), "192.168.1.20", "round trips to string");
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

void testTitanFraming() {
    std::printf("titan: 12-byte big-endian header\n");

    // Tags are 4CCs whose bytes appear on the wire in reading order.
    checkEqualInt(nfslan::kTagDirectory, 0x40646972, "'@dir' packs to 0x40646972");
    checkEqualInt(nfslan::kTagTicket, 0x40746963, "'@tic' packs to 0x40746963");
    checkEqualInt(nfslan::kTagPing, 0x7E706E67, "'~png' packs to 0x7E706E67");
    checkEqualStr(nfslan::titanTagToString(nfslan::kTagDirectory), "@dir", "tag renders back");

    nfslan::TitanMessage message;
    message.tag = nfslan::kTagDirectory;
    message.code = nfslan::kCodeSuccess;
    message.body = "ADDR=192.168.1.10\tPORT=9900";

    const auto encoded = nfslan::encodeTitan(message);

    // Header must be big-endian, and the length counts the header and the NUL.
    check(encoded[0] == '@' && encoded[1] == 'd' && encoded[2] == 'i' && encoded[3] == 'r',
          "tag is written in ASCII order");
    checkEqualInt(encoded[8], 0, "length byte 0 (big-endian)");
    checkEqualInt(encoded[9], 0, "length byte 1");
    checkEqualInt(encoded[10], 0, "length byte 2");
    checkEqualInt(encoded[11], 12 + 27 + 1, "length byte 3 = 12 + body + NUL");
    checkEqualInt(static_cast<long long>(encoded.size()), 12 + 27 + 1, "frame size matches length");
    checkEqualInt(encoded.back(), 0, "body is NUL-terminated on the wire");

    const auto decoded = nfslan::decodeTitan(encoded);
    check(decoded.has_value(), "frame decodes");
    if (decoded) {
        checkEqualInt(decoded->tag, nfslan::kTagDirectory, "tag round trips");
        checkEqualInt(decoded->code, 0, "code round trips");
        checkEqualStr(decoded->body, "ADDR=192.168.1.10\tPORT=9900",
                      "body round trips without the NUL");
    }

    // An empty body is a 12-byte frame — this is the "@tic" reply that makes a
    // client disable encryption, so the size matters.
    nfslan::TitanMessage bare;
    bare.tag = nfslan::kTagTicket;
    const auto bareEncoded = nfslan::encodeTitan(bare);
    checkEqualInt(static_cast<long long>(bareEncoded.size()), 12, "empty body is a 12-byte frame");
    check(bareEncoded.size() != 0x54, "reply is not 84 bytes, so the client drops encryption");
}

void testTitanPartialAndRejection() {
    std::printf("titan: partial frames and non-Titan data\n");

    nfslan::TitanMessage message;
    message.tag = nfslan::kTagDirectory;
    message.body = "ADDR=192.168.1.10\tPORT=9900";
    const auto encoded = nfslan::encodeTitan(message);

    // A short read must not decode: TCP delivers frames in pieces.
    check(!nfslan::decodeTitan(encoded.data(), 8).has_value(), "8 bytes is not a frame");
    check(!nfslan::decodeTitan(encoded.data(), encoded.size() - 1).has_value(),
          "one byte short does not decode");
    check(nfslan::decodeTitan(encoded.data(), encoded.size()).has_value(),
          "the complete frame does decode");

    // The length field is how a real server tells Titan from the HTTP that is
    // multiplexed onto the same port.
    const auto claimed = nfslan::titanFrameLength(encoded.data(), encoded.size());
    check(claimed.has_value(), "frame length is readable from the header");
    if (claimed) {
        checkEqualInt(*claimed, static_cast<long long>(encoded.size()), "claimed length is exact");
    }

    const std::string http = "GET /sm/status HTTP/1.0\r\n\r\n";
    const auto* httpBytes = reinterpret_cast<const std::uint8_t*>(http.data());
    check(!nfslan::looksLikeTitan(httpBytes, http.size()), "an HTTP request is not Titan");

    std::vector<std::uint8_t> absurd(12, 0xFF);  // claims a ~4 GB frame
    check(!nfslan::looksLikeTitan(absurd.data(), absurd.size()), "an absurd length is not Titan");
}

void testTitanErrorCodes() {
    std::printf("titan: error replies\n");

    // Error codes are themselves 4CCs, and the client shows the body as the
    // message. Replying success to something we cannot fulfil is what hangs the
    // game, so these have to encode correctly.
    checkEqualStr(nfslan::titanTagToString(nfslan::kErrorNotFound), "nfnd", "'nfnd' renders");
    checkEqualStr(nfslan::titanTagToString(nfslan::kErrorMustAuth), "maut", "'maut' renders");
    check(nfslan::kErrorNotFound != nfslan::kCodeSuccess, "an error code is not success");

    nfslan::TitanMessage reply;
    reply.tag = nfslan::kTagAuth;
    reply.code = nfslan::kErrorNotFound;
    reply.body = "not implemented";

    const auto encoded = nfslan::encodeTitan(reply);
    const auto decoded = nfslan::decodeTitan(encoded);
    check(decoded.has_value(), "error reply decodes");
    if (decoded) {
        checkEqualInt(decoded->tag, nfslan::kTagAuth, "error keeps the request tag");
        checkEqualInt(decoded->code, nfslan::kErrorNotFound, "error code survives");
        checkEqualStr(decoded->body, "not implemented", "error message survives");
        // describe() renders a non-zero code as its 4CC, not as a number.
        check(decoded->describe().find("nfnd") != std::string::npos,
              "describe() shows the error code as text");
    }
}

void testTagFields() {
    std::printf("titan: TagField bodies\n");

    const std::string body = nfslan::tagFieldBuild({{"ADDR", "192.168.1.10"}, {"PORT", "9900"}});
    checkEqualStr(body, "ADDR=192.168.1.10\tPORT=9900", "pairs are TAB-separated");

    const auto addr = nfslan::tagFieldFind(body, "ADDR");
    check(addr.has_value(), "ADDR is found");
    if (addr) {
        checkEqualStr(*addr, "192.168.1.10", "ADDR value parses");
    }
    const auto port = nfslan::tagFieldFind(body, "PORT");
    check(port.has_value(), "PORT is found");
    if (port) {
        checkEqualStr(*port, "9900", "PORT value parses");
    }

    // Key matching is case-insensitive in real parsers.
    check(nfslan::tagFieldFind(body, "addr").has_value(), "keys match case-insensitively");
    check(!nfslan::tagFieldFind(body, "NOPE").has_value(), "absent key returns nothing");

    // A key must not match a suffix of a longer key.
    const std::string tricky = "XADDR=1.2.3.4\tPORT=1";
    check(!nfslan::tagFieldFind(tricky, "ADDR").has_value(),
          "ADDR does not match inside XADDR");

    // Real bodies also arrive newline-separated; any byte under 0x20 separates.
    const auto fromNewlines = nfslan::tagFieldFind("ADDR=10.0.0.1\nPORT=9900\n", "PORT");
    check(fromNewlines.has_value(), "newline-separated bodies still parse");
    if (fromNewlines) {
        checkEqualStr(*fromNewlines, "9900", "value stops at the separator");
    }

    // The client reads "DIRECT" to decide whether to skip the redirect, so a
    // reply that means "reconnect here" must not contain it.
    check(!nfslan::tagFieldFind(body, "DIRECT").has_value(),
          "redirect reply carries no DIRECT key");
}

}  // namespace

int main() {
    std::printf("NFSLAN protocol tests\n\n");

    testBeaconRoundTrip();
    testWithdrawal();
    testBeaconFieldOffsets();
    testBeaconTruncationAndPadding();
    testDiscoveryQuery();
    testBeaconRejection();
    testIdentRewrite();
    testConfigParsing();
    testConfigDefaultsAndWarnings();
    testAddressHelpers();
    testTitanFraming();
    testTitanPartialAndRejection();
    testTitanErrorCodes();
    testTagFields();

    std::printf("\n%d checks, %d failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
