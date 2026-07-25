// EA "Titan" / ProtoAries message framing — the lobby protocol on TCP 9900.
//
// Fixed 12-byte header, all fields BIG-ENDIAN, no padding:
//
//   [0..3]   4-char ASCII tag, e.g. "@dir", "@tic", "~png", "+usr", "auth"
//   [4..7]   code. On a request: a caller tag (echoed as the reply tag when
//            negative). On a reply: 0 for success, else a 4-char ASCII error
//            code such as "nfnd". On "~png": a millisecond tick.
//   [8..11]  TOTAL length, INCLUDING these 12 bytes.
//   [12..]   body, length - 12 bytes, NUL-terminated with the NUL counted in
//            the length.
//
// The body is a DirtySDK TagField list: KEY=VALUE pairs separated by TAB (0x09).
// Real parsers treat any byte below 0x21 as a separator, which is why newline
// bodies also work, but a byte-faithful server emits TAB.
//
// Tag case is semantic, not cosmetic: lowercase (and '@'-prefixed) tags are
// client-to-lobby, and the lobby XORs a tag with 0x20202020 to flip it to
// uppercase when forwarding server-to-server. Never compare tags
// case-insensitively — compare the raw 32-bit value.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nfslan {

constexpr std::size_t kTitanHeaderSize = 12;

// Body pairs are TAB-separated on the wire.
constexpr char kTitanFieldSeparator = '\t';

// Packs a 4-character tag into the value that appears on the wire, so that
// titanTag("@dir") == 0x40646972 and the bytes read '@','d','i','r'.
constexpr std::uint32_t titanTag(const char (&tag)[5]) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(tag[0])) << 24) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(tag[1])) << 16) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(tag[2])) << 8) |
           static_cast<std::uint32_t>(static_cast<unsigned char>(tag[3]));
}

// Tags a LAN server actually needs to recognise.
constexpr std::uint32_t kTagDirectory = titanTag("@dir");  // where should I connect?
constexpr std::uint32_t kTagTicket = titanTag("@tic");     // crypto offer
constexpr std::uint32_t kTagTicketPre = titanTag("?tic");  // encrypted-session opener
constexpr std::uint32_t kTagPing = titanTag("~png");       // keepalive, server-initiated
constexpr std::uint32_t kTagAddress = titanTag("addr");    // client reports its own address
constexpr std::uint32_t kTagSessionKey = titanTag("skey");
constexpr std::uint32_t kTagAuth = titanTag("auth");

// Reply code meaning success. Anything else is a 4-char ASCII error code, and
// the client shows the reply body as the error message.
constexpr std::uint32_t kCodeSuccess = 0;

// Error codes the stock servers use. Replying with one of these makes a client
// fail cleanly; replying success to a request we cannot actually fulfil leaves
// it waiting forever, which hangs the game's menus.
constexpr std::uint32_t kErrorNotFound = titanTag("nfnd");
constexpr std::uint32_t kErrorMissingField = titanTag("miss");
constexpr std::uint32_t kErrorUnknownUser = titanTag("uusr");
constexpr std::uint32_t kErrorMustAuth = titanTag("maut");
constexpr std::uint32_t kErrorAlreadyInGame = titanTag("ingm");
constexpr std::uint32_t kErrorUnknownRoom = titanTag("urom");
constexpr std::uint32_t kErrorDuplicate = titanTag("dupl");
constexpr std::uint32_t kErrorNotOwner = titanTag("nown");

// Renders a tag back to its four characters, for logs.
std::string titanTagToString(std::uint32_t tag);

struct TitanMessage {
    std::uint32_t tag = 0;
    std::uint32_t code = 0;
    std::string body;  // without the trailing NUL

    std::string describe() const;
};

// Encodes a message, including the trailing NUL that the length accounts for.
std::vector<std::uint8_t> encodeTitan(const TitanMessage& message);

// How many bytes the frame starting at `data` claims to be, or nullopt when
// fewer than 12 bytes are available. Use this to know how much more to read.
std::optional<std::uint32_t> titanFrameLength(const std::uint8_t* data, std::size_t length);

// True when the header looks like Titan rather than the HTTP that shares this
// port: a plausible total length of at least 12 bytes. Real servers treat
// anything else as HTTP and match "GET /sm/"-style prefixes instead.
bool looksLikeTitan(const std::uint8_t* data, std::size_t length, std::uint32_t maxFrame = 0x10000);

// Decodes one complete frame. Returns nullopt when the buffer is short or the
// header is not plausible.
std::optional<TitanMessage> decodeTitan(const std::uint8_t* data, std::size_t length);

inline std::optional<TitanMessage> decodeTitan(const std::vector<std::uint8_t>& data) {
    return decodeTitan(data.data(), data.size());
}

// --- TagField bodies --------------------------------------------------------

// Reads a key out of a TagField body. Key matching is case-insensitive; the
// value runs to the next byte below 0x20. Returns nullopt when absent.
std::optional<std::string> tagFieldFind(const std::string& body, const std::string& key);

// Builds a TAB-separated body from ordered pairs.
std::string tagFieldBuild(const std::vector<std::pair<std::string, std::string>>& pairs);

}  // namespace nfslan
