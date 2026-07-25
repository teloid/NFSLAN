// Lobby listener for the advertised session port (TCP 9900 by default).
//
// The client connects here after picking a server out of the LAN list. The
// dialect spoken on this socket is not fully mapped yet (see docs/PROTOCOL.md),
// so the service has two modes:
//
//   Capture  — accept, log every byte the client sends, reply with nothing.
//              This is how the handshake gets reverse engineered: point a real
//              client at it and read the transcript.
//   Serve    — respond using whatever the protocol layer knows. Incomplete.
//
// Capture mode is deliberately the default until Serve can carry a client all
// the way into a session, because a wrong reply is harder to debug than silence.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "nfslan/net.hpp"

namespace nfslan {

enum class LobbyMode {
    Capture,
    Serve,
};

struct LobbySettings {
    std::uint16_t port = 9900;
    LobbyMode mode = LobbyMode::Capture;

    // Where to append the capture transcript. Empty means log only.
    std::string capturePath;

    bool verbose = false;
};

struct LobbyStats {
    std::atomic<std::uint64_t> connectionsAccepted{0};
    std::atomic<std::uint64_t> bytesReceived{0};
    std::atomic<std::uint64_t> messagesLogged{0};
};

class LobbyService {
public:
    using LogFn = std::function<void(const std::string&)>;

    explicit LobbyService(LobbySettings settings, LogFn log = {});
    ~LobbyService();

    LobbyService(const LobbyService&) = delete;
    LobbyService& operator=(const LobbyService&) = delete;

    bool start();
    void stop();
    bool isRunning() const { return running_.load(); }

    const LobbyStats& stats() const { return stats_; }
    const std::string& lastError() const { return lastError_; }

private:
    void runAccept();
    void handleConnection(TcpConnection connection);
    void recordBytes(const Endpoint& peer, const std::uint8_t* data, std::size_t length);

    LobbySettings settings_;
    LogFn log_;

    TcpListener listener_;
    std::thread acceptThread_;
    std::vector<std::thread> connectionThreads_;
    std::mutex connectionThreadsMutex_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};

    LobbyStats stats_;
    std::string lastError_;
    std::mutex captureMutex_;
};

// Renders bytes as an offset/hex/ASCII dump, the format used in capture logs.
std::string formatHexDump(const std::uint8_t* data, std::size_t length,
                          const std::string& indent = "    ");

}  // namespace nfslan
