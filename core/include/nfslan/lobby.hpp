// Lobby listener for the advertised session port (TCP 9900 by default).
//
// The client connects here after picking a server out of the LAN list, then
// drives an EA "Titan" exchange (see titan.hpp for the framing):
//
//   1. client -> "@tic"  body "RC4+MD5-V2"     offering encryption
//      server -> "@tic"  code 0                a reply body that is not exactly
//                                              84 bytes makes the client turn
//                                              encryption off, which is what a
//                                              LAN server wants.
//   2. client -> "@dir"  body <its parameters> asking where to connect
//      server -> "@dir"  code 0, body
//                "ADDR=<ip>\tPORT=<port>"      the client then DISCONNECTS and
//                                              reconnects to that address. An
//                                              ADDR of 0 makes it give up and
//                                              report the server as down.
//   3. on the new connection the client sends "addr", then "skey", then "auth"
//      and the persona/room/game flow, which is not implemented.
//
// Two modes:
//   Capture  — accept and log, reply with nothing. Use this to observe a client.
//   Serve    — answer steps 1 and 2, so the client gets past "connecting to
//              lobby" and reaches step 3, then log what it asks for next.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "nfslan/net.hpp"
#include "nfslan/titan.hpp"

namespace nfslan {

enum class LobbyMode {
    Capture,
    Serve,
};

struct LobbySettings {
    std::uint16_t port = 9900;
    LobbyMode mode = LobbyMode::Capture;

    // The address to hand back in the "@dir" reply. Clients reconnect here, so
    // it must be an address the client can reach — not 0.0.0.0 and, unless the
    // client is on this machine, not 127.0.0.1.
    std::uint32_t redirectAddress = 0;
    std::uint16_t redirectPort = 9900;

    // Reply success to tags with no real handler, so the client keeps walking
    // its state machine and reveals the next request. A discovery aid — the
    // replies are not correct for verbs whose bodies carry required fields.
    bool ackUnknownTags = false;

    // Where to append the capture transcript. Empty means log only.
    std::string capturePath;

    bool verbose = false;
};

struct LobbyStats {
    std::atomic<std::uint64_t> connectionsAccepted{0};
    std::atomic<std::uint64_t> bytesReceived{0};
    std::atomic<std::uint64_t> messagesLogged{0};
    std::atomic<std::uint64_t> framesDecoded{0};
    std::atomic<std::uint64_t> repliesSent{0};
    std::atomic<std::uint64_t> unhandledTags{0};
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

    // Consumes whole Titan frames from `buffer`, replying where we can. Returns
    // false when the connection should be closed.
    bool processFrames(TcpConnection& connection, std::vector<std::uint8_t>& buffer);
    bool respondTo(TcpConnection& connection, const TitanMessage& request);

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
