#include "nfslan/titan.hpp"

#include <cctype>
#include <cstring>

namespace nfslan {
namespace {

std::uint32_t readBigEndian32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) | static_cast<std::uint32_t>(data[3]);
}

void writeBigEndian32(std::uint8_t* data, std::uint32_t value) {
    data[0] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    data[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    data[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    data[3] = static_cast<std::uint8_t>(value & 0xFF);
}

char printableOrDot(std::uint32_t byte) {
    const auto value = static_cast<std::uint8_t>(byte & 0xFF);
    return (value >= 32 && value <= 126) ? static_cast<char>(value) : '.';
}

bool equalsIgnoreCase(const char* a, std::size_t aLength, const std::string& b) {
    if (aLength != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < aLength; ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::string titanTagToString(std::uint32_t tag) {
    std::string out(4, '.');
    out[0] = printableOrDot(tag >> 24);
    out[1] = printableOrDot(tag >> 16);
    out[2] = printableOrDot(tag >> 8);
    out[3] = printableOrDot(tag);
    return out;
}

std::string TitanMessage::describe() const {
    std::string out = titanTagToString(tag);
    if (code == kCodeSuccess) {
        out += " code=0";
    } else {
        // A non-zero code on a reply is itself a 4-char ASCII error code.
        out += " code=" + titanTagToString(code);
    }
    if (!body.empty()) {
        // Show TABs as spaces so a one-line log stays readable.
        std::string readable = body;
        for (char& c : readable) {
            if (c == kTitanFieldSeparator) {
                c = ' ';
            }
        }
        out += " body='" + readable + "'";
    }
    return out;
}

std::vector<std::uint8_t> encodeTitan(const TitanMessage& message) {
    // The trailing NUL is part of the body on the wire and is counted in the
    // total length, which is how real encoders do it (strlen + 1 + 12).
    const std::size_t bodyBytes = message.body.empty() ? 0 : message.body.size() + 1;
    const std::size_t total = kTitanHeaderSize + bodyBytes;

    std::vector<std::uint8_t> out(total, 0);
    writeBigEndian32(out.data() + 0, message.tag);
    writeBigEndian32(out.data() + 4, message.code);
    writeBigEndian32(out.data() + 8, static_cast<std::uint32_t>(total));
    if (bodyBytes > 0) {
        std::memcpy(out.data() + kTitanHeaderSize, message.body.data(), message.body.size());
        // out[total - 1] is already 0 from the fill.
    }
    return out;
}

std::optional<std::uint32_t> titanFrameLength(const std::uint8_t* data, std::size_t length) {
    if (!data || length < kTitanHeaderSize) {
        return std::nullopt;
    }
    return readBigEndian32(data + 8);
}

bool looksLikeTitan(const std::uint8_t* data, std::size_t length, std::uint32_t maxFrame) {
    const auto claimed = titanFrameLength(data, length);
    if (!claimed) {
        return false;
    }
    // Real servers use exactly this test to split Titan from the HTTP that is
    // multiplexed onto the same port: a total length below the header size, or
    // beyond the receive buffer, means "not Titan".
    return *claimed >= kTitanHeaderSize && *claimed <= maxFrame;
}

std::optional<TitanMessage> decodeTitan(const std::uint8_t* data, std::size_t length) {
    if (!looksLikeTitan(data, length)) {
        return std::nullopt;
    }
    const std::uint32_t total = *titanFrameLength(data, length);
    if (length < total) {
        return std::nullopt;  // frame not fully arrived yet
    }

    TitanMessage message;
    message.tag = readBigEndian32(data + 0);
    message.code = readBigEndian32(data + 4);

    if (total > kTitanHeaderSize) {
        const std::size_t bodyBytes = total - kTitanHeaderSize;
        const auto* begin = reinterpret_cast<const char*>(data + kTitanHeaderSize);
        // Drop the trailing NUL the sender counted in the length.
        const std::size_t used = (bodyBytes > 0 && begin[bodyBytes - 1] == '\0') ? bodyBytes - 1
                                                                                : bodyBytes;
        message.body.assign(begin, used);
    }
    return message;
}

std::optional<std::string> tagFieldFind(const std::string& body, const std::string& key) {
    if (body.empty() || key.empty()) {
        return std::nullopt;
    }

    const char* data = body.data();
    const std::size_t length = body.size();

    for (std::size_t i = 0; i < length; ++i) {
        if (data[i] != '=' && data[i] != ':') {
            continue;
        }

        // Walk back over the key: it ends at the separator and starts after the
        // previous control byte (or at the buffer start).
        std::size_t keyEnd = i;
        std::size_t keyBegin = keyEnd;
        while (keyBegin > 0 && static_cast<unsigned char>(data[keyBegin - 1]) >= 0x21) {
            --keyBegin;
        }
        if (!equalsIgnoreCase(data + keyBegin, keyEnd - keyBegin, key)) {
            continue;
        }

        std::size_t valueBegin = i + 1;
        if (valueBegin < length && data[valueBegin] == ' ') {
            ++valueBegin;  // one leading space is skipped
        }
        std::size_t valueEnd = valueBegin;
        while (valueEnd < length && static_cast<unsigned char>(data[valueEnd]) >= 0x20) {
            ++valueEnd;
        }
        return body.substr(valueBegin, valueEnd - valueBegin);
    }

    return std::nullopt;
}

std::string tagFieldBuild(const std::vector<std::pair<std::string, std::string>>& pairs) {
    std::string out;
    for (const auto& [key, value] : pairs) {
        if (key.empty()) {
            continue;
        }
        if (!out.empty()) {
            out.push_back(kTitanFieldSeparator);
        }
        out += key;
        out.push_back('=');
        out += value;
    }
    return out;
}

}  // namespace nfslan
