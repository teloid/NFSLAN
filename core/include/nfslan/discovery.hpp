// LAN discovery service: makes the server appear in the game's LAN server list.
//
// Two behaviours, both on UDP `discoveryPort` (9999 by default):
//   * answer  — a client broadcasts a 'gEA?' query; we reply with our beacon
//               directly to the sender.
//   * announce — we periodically broadcast our beacon unsolicited, which is
//               what stock servers do and what clients that never query rely on.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

#include "nfslan/beacon.hpp"
#include "nfslan/net.hpp"

namespace nfslan {

struct DiscoverySettings {
    std::string ident = kIdentUg2NorthAmerica;
    std::string serverName = "NFSLAN Server";

    // Port advertised inside the beacon's stats field — where clients connect.
    std::uint16_t lobbyPort = kDefaultLobbyPort;

    std::uint16_t discoveryPort = kDefaultDiscoveryPort;
    int beaconIntervalMs = 1000;

    bool announceToLoopback = true;
    bool announceToBroadcast = true;
    bool verbose = false;
};

// Counters for status output and tests.
struct DiscoveryStats {
    std::atomic<std::uint64_t> queriesAnswered{0};
    std::atomic<std::uint64_t> announcementsSent{0};
    std::atomic<std::uint64_t> foreignBeaconsSeen{0};
};

class DiscoveryService {
public:
    using LogFn = std::function<void(const std::string&)>;

    explicit DiscoveryService(DiscoverySettings settings, LogFn log = {});
    ~DiscoveryService();

    DiscoveryService(const DiscoveryService&) = delete;
    DiscoveryService& operator=(const DiscoveryService&) = delete;

    // Binds the discovery port and starts the service thread. On failure the
    // reason is in lastError().
    bool start();
    void stop();
    bool isRunning() const { return running_.load(); }

    const DiscoveryStats& stats() const { return stats_; }
    const std::string& lastError() const { return lastError_; }

    // The beacon this service currently sends. Rebuilt when settings change.
    const DiscoverySettings& settings() const { return settings_; }

private:
    void run();
    void sendAnnouncements();
    void handleDatagram(const Datagram& datagram);

    DiscoverySettings settings_;
    LogFn log_;

    UdpSocket socket_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};

    DiscoveryStats stats_;
    std::string lastError_;
};

}  // namespace nfslan
