#include "nfslan/lobby.hpp"

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>

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

    std::vector<std::uint8_t> buffer(kReadChunk);
    std::uint64_t totalForConnection = 0;

    while (!stopRequested_.load()) {
        const int received = connection.receive(buffer.data(), buffer.size());

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
        recordBytes(peer, buffer.data(), static_cast<std::size_t>(received));

        // Capture mode never replies: the point is to observe the client's
        // unprompted handshake, including any retries and timeouts.
        if (settings_.mode == LobbyMode::Serve) {
            // Not implemented — the dialect is not mapped yet. Staying silent
            // here is deliberate; see docs/PROTOCOL.md "Open questions".
        }
    }

    connection.close();
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
