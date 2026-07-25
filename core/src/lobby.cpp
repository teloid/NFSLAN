#include "nfslan/lobby.hpp"

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>

#include "nfslan/beacon.hpp"  // hexPreview

namespace nfslan {
namespace {

constexpr int kAcceptTimeoutMs = 200;
constexpr int kReceiveTimeoutMs = 500;
constexpr std::size_t kReadChunk = 4096;

}  // namespace

std::string formatHexDump(const std::uint8_t* data, std::size_t length, const std::string& indent) {
    if (!data || length == 0) {
        return {};
    }

    std::ostringstream out;
    for (std::size_t offset = 0; offset < length; offset += 16) {
        const std::size_t lineLength = std::min<std::size_t>(16, length - offset);

        out << indent << std::hex << std::setfill('0') << std::setw(4) << offset << "  ";

        for (std::size_t i = 0; i < 16; ++i) {
            if (i < lineLength) {
                out << std::setw(2) << static_cast<int>(data[offset + i]) << ' ';
            } else {
                out << "   ";
            }
            if (i == 7) {
                out << ' ';
            }
        }

        out << " |";
        for (std::size_t i = 0; i < lineLength; ++i) {
            const std::uint8_t value = data[offset + i];
            out << (value >= 32 && value <= 126 ? static_cast<char>(value) : '.');
        }
        out << "|\n";
    }

    return out.str();
}

LobbyService::LobbyService(LobbySettings settings, LogFn log)
    : settings_(std::move(settings)), log_(std::move(log)) {}

LobbyService::~LobbyService() { stop(); }

bool LobbyService::start() {
    if (running_.load()) {
        return true;
    }

    if (!listener_.listen(settings_.port)) {
        lastError_ = listener_.lastError();
        return false;
    }

    stopRequested_.store(false);
    running_.store(true);
    acceptThread_ = std::thread([this] { runAccept(); });
    lastError_.clear();
    return true;
}

void LobbyService::stop() {
    if (!running_.load()) {
        return;
    }

    stopRequested_.store(true);
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }

    // Connection threads observe stopRequested_ and exit on their own; join
    // them before tearing down so their logging cannot outlive this object.
    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> guard(connectionThreadsMutex_);
        threads.swap(connectionThreads_);
    }
    for (std::thread& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    listener_.close();
    running_.store(false);
}

void LobbyService::runAccept() {
    while (!stopRequested_.load()) {
        auto connection = listener_.accept(kAcceptTimeoutMs);
        if (!connection) {
            if (!listener_.lastError().empty() && log_) {
                log_("lobby: " + listener_.lastError());
            }
            continue;
        }

        stats_.connectionsAccepted.fetch_add(1);
        if (log_) {
            log_("lobby: connection from " + connection->peer().toString());
        }

        // Reap finished threads so a long-running server does not accumulate
        // joinable handles for every connection it ever saw.
        {
            std::lock_guard<std::mutex> guard(connectionThreadsMutex_);
            connectionThreads_.emplace_back(
                [this, conn = std::move(*connection)]() mutable { handleConnection(std::move(conn)); });
        }
    }
}

void LobbyService::handleConnection(TcpConnection connection) {
    const Endpoint peer = connection.peer();
    connection.setNoDelay(true);
    connection.setReceiveTimeout(kReceiveTimeoutMs);

    std::vector<std::uint8_t> chunk(kReadChunk);
    std::vector<std::uint8_t> pending;  // accumulates partial frames
    std::uint64_t totalForConnection = 0;

    while (!stopRequested_.load()) {
        const int received = connection.receive(chunk.data(), chunk.size());

        if (received == -2) {
            continue;  // idle; the client may still be waiting on us
        }
        if (received == 0) {
            if (log_) {
                log_("lobby: " + peer.toString() + " closed the connection after " +
                     std::to_string(totalForConnection) + " bytes");
            }
            break;
        }
        if (received < 0) {
            if (log_ && !connection.lastError().empty()) {
                log_("lobby: " + peer.toString() + ": " + connection.lastError());
            }
            break;
        }

        totalForConnection += static_cast<std::uint64_t>(received);
        stats_.bytesReceived.fetch_add(static_cast<std::uint64_t>(received));
        recordBytes(peer, chunk.data(), static_cast<std::size_t>(received));

        // Capture mode never replies: the point is to observe the client's
        // unprompted handshake, including its retries and timeouts.
        if (settings_.mode != LobbyMode::Serve) {
            continue;
        }

        pending.insert(pending.end(), chunk.begin(), chunk.begin() + received);
        if (!processFrames(connection, pending)) {
            break;
        }
    }

    connection.close();
}

bool LobbyService::processFrames(TcpConnection& connection, std::vector<std::uint8_t>& buffer) {
    while (buffer.size() >= kTitanHeaderSize) {
        if (!looksLikeTitan(buffer.data(), buffer.size())) {
            // Not Titan — real servers fall back to HTTP here, which a LAN
            // server has no use for. Log and drop the connection rather than
            // desynchronising the stream.
            if (log_) {
                log_("lobby: non-Titan data, dropping connection: " +
                     hexPreview(buffer.data(), buffer.size(), 16));
            }
            return false;
        }

        const std::uint32_t total = *titanFrameLength(buffer.data(), buffer.size());
        if (buffer.size() < total) {
            return true;  // wait for the rest of this frame
        }

        const auto request = decodeTitan(buffer.data(), total);
        buffer.erase(buffer.begin(), buffer.begin() + total);
        if (!request) {
            return false;
        }

        stats_.framesDecoded.fetch_add(1);
        if (log_) {
            log_("lobby: <- " + request->describe());
        }
        if (!respondTo(connection, *request)) {
            return false;
        }
    }
    return true;
}

bool LobbyService::respondTo(TcpConnection& connection, const TitanMessage& request) {
    TitanMessage reply;
    // Requests are answered under the same tag, with code 0 for success. A
    // negative caller tag would be echoed as the reply tag instead.
    reply.tag = request.tag;
    reply.code = kCodeSuccess;

    switch (request.tag) {
        case kTagTicket:
            // The client enables encryption only if this reply body is exactly
            // 84 bytes. Anything else turns it off, which is what we want on a
            // LAN: no RC4, no MD5 MACs, no key exchange.
            reply.body.clear();
            break;

        case kTagDirectory: {
            // Tell the client where the lobby is. It disconnects after this and
            // reconnects to the address we name, so naming an unreachable
            // address (or 0, which it reads as "server down") strands it here.
            if (settings_.redirectAddress == 0) {
                if (log_) {
                    log_("lobby: no reachable redirect address configured; the client "
                         "will report the server as down");
                }
                return false;
            }
            reply.body = tagFieldBuild({
                {"ADDR", ipv4ToString(settings_.redirectAddress)},
                {"PORT", std::to_string(settings_.redirectPort)},
            });
            break;
        }

        case kTagPing:
            // Keepalive is normally server-initiated; echo anything we get.
            reply.body = request.body;
            break;

        case kTagAddress:
        case kTagSessionKey:
            // Informational: the client tells us its own address, and offers a
            // session key we ignore because encryption is off. A bare success is
            // what the real server sends.
            reply.body.clear();
            break;

        default:
            if (!settings_.ackUnknownTags) {
                stats_.unhandledTags.fetch_add(1);
                if (log_) {
                    log_("lobby: no handler for " + titanTagToString(request.tag) +
                         "; session handshake stops here (see docs/PROTOCOL.md)");
                }
                return true;
            }
            // Exploration mode: acknowledge anything so the client keeps walking
            // its state machine and reveals the next request. A bare success is
            // wrong for verbs whose replies carry required fields, so this is a
            // discovery tool, not correct behaviour.
            stats_.unhandledTags.fetch_add(1);
            reply.body.clear();
            if (log_) {
                log_("lobby: acking unmapped " + titanTagToString(request.tag) +
                     " to see what the client asks next");
            }
            break;
    }

    const auto encoded = encodeTitan(reply);
    if (!connection.sendAll(encoded.data(), encoded.size())) {
        if (log_) {
            log_("lobby: reply failed: " + connection.lastError());
        }
        return false;
    }

    stats_.repliesSent.fetch_add(1);
    if (log_) {
        log_("lobby: -> " + reply.describe());
    }
    return true;
}

void LobbyService::recordBytes(const Endpoint& peer, const std::uint8_t* data, std::size_t length) {
    stats_.messagesLogged.fetch_add(1);

    std::ostringstream entry;
    entry << "lobby: " << length << " bytes from " << peer.toString() << "\n"
          << formatHexDump(data, length);

    const std::string text = entry.str();
    if (log_) {
        log_(text);
    }

    if (settings_.capturePath.empty()) {
        return;
    }

    std::lock_guard<std::mutex> guard(captureMutex_);
    std::ofstream file(settings_.capturePath, std::ios::app);
    if (file) {
        file << text << '\n';
    }
}

}  // namespace nfslan
