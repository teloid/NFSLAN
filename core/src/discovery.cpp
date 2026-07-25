#include "nfslan/discovery.hpp"

#include <chrono>

namespace nfslan {
namespace {

constexpr int kReceiveTimeoutMs = 200;

}  // namespace

DiscoveryService::DiscoveryService(DiscoverySettings settings, LogFn log)
    : settings_(std::move(settings)), log_(std::move(log)) {}

DiscoveryService::~DiscoveryService() { stop(); }

bool DiscoveryService::start() {
    if (running_.load()) {
        return true;
    }

    if (!socket_.open()) {
        lastError_ = socket_.lastError();
        return false;
    }
    // Sharing the discovery port matters: on a same-machine setup the game
    // itself may also be bound to 9999.
    socket_.setReuseAddress(true);
    socket_.setBroadcast(true);

    if (!socket_.bind(settings_.discoveryPort)) {
        lastError_ = socket_.lastError();
        socket_.close();
        return false;
    }

    // A short timeout keeps the loop responsive to stop() without a self-pipe.
    socket_.setReceiveTimeout(kReceiveTimeoutMs);

    stopRequested_.store(false);
    running_.store(true);
    thread_ = std::thread([this] { run(); });
    lastError_.clear();
    return true;
}

void DiscoveryService::stop() {
    if (!running_.load()) {
        return;
    }
    stopRequested_.store(true);
    if (thread_.joinable()) {
        thread_.join();
    }
    // Say goodbye before closing so clients drop us from their list immediately
    // instead of showing a dead server until the row expires.
    sendWithdrawal();
    socket_.close();
    running_.store(false);
}

void DiscoveryService::sendWithdrawal() {
    if (!socket_.isOpen()) {
        return;
    }
    const auto packet =
        encodeWithdrawal(settings_.ident, settings_.serverName, settings_.lobbyPort);

    if (settings_.announceToBroadcast) {
        for (std::uint32_t address : broadcastAddresses()) {
            socket_.sendTo({address, settings_.discoveryPort}, packet.data(), packet.size());
        }
    }
    if (settings_.announceToLoopback) {
        socket_.sendTo({kAddrLoopback, settings_.discoveryPort}, packet.data(), packet.size());
    }
}

void DiscoveryService::run() {
    using clock = std::chrono::steady_clock;
    auto nextAnnounce = clock::now();

    while (!stopRequested_.load()) {
        if (settings_.beaconIntervalMs > 0 && clock::now() >= nextAnnounce) {
            sendAnnouncements();
            nextAnnounce = clock::now() + std::chrono::milliseconds(settings_.beaconIntervalMs);
        }

        if (auto datagram = socket_.receive(kBeaconLength * 2)) {
            handleDatagram(*datagram);
        } else if (!socket_.lastError().empty() && log_) {
            log_("discovery: " + socket_.lastError());
        }
    }
}

void DiscoveryService::sendAnnouncements() {
    const auto packet = encodeBeacon(settings_.ident, settings_.serverName, settings_.lobbyPort,
                                     playerCount_.load());

    const auto send = [&](std::uint32_t address) {
        const Endpoint target{address, settings_.discoveryPort};
        if (socket_.sendTo(target, packet.data(), packet.size())) {
            stats_.announcementsSent.fetch_add(1);
        } else if (log_ && settings_.verbose) {
            log_("discovery: announce to " + target.toString() + " failed: " + socket_.lastError());
        }
    };

    if (settings_.announceToBroadcast) {
        for (std::uint32_t address : broadcastAddresses()) {
            send(address);
        }
    }
    if (settings_.announceToLoopback) {
        send(kAddrLoopback);
    }
}

void DiscoveryService::handleDatagram(const Datagram& datagram) {
    const std::uint8_t* data = datagram.data.data();
    const std::size_t length = datagram.data.size();

    if (isDiscoveryQuery(data, length)) {
        // Stock servers answer a query by pulling their next broadcast forward
        // rather than replying directly. Unicasting straight back is a superset
        // of that and is what makes same-machine discovery reliable.
        const auto packet = encodeBeacon(settings_.ident, settings_.serverName,
                                         settings_.lobbyPort, playerCount_.load());
        if (socket_.sendTo(datagram.from, packet.data(), packet.size())) {
            stats_.queriesAnswered.fetch_add(1);
            if (log_ && settings_.verbose) {
                log_("discovery: answered query from " + datagram.from.toString());
            }
        } else if (log_) {
            log_("discovery: reply to " + datagram.from.toString() + " failed: " +
                 socket_.lastError());
        }
        return;
    }

    if (isBeacon(data, length)) {
        // Our own broadcasts come back to us; only note the ones that aren't ours.
        const auto beacon = decodeBeacon(data, length);
        if (beacon && beacon->name != settings_.serverName) {
            stats_.foreignBeaconsSeen.fetch_add(1);
            if (log_ && settings_.verbose) {
                log_("discovery: saw '" + beacon->name + "' (ident " + beacon->ident + ") from " +
                     datagram.from.toString());
            }
        }
        return;
    }

    if (log_ && settings_.verbose) {
        log_("discovery: ignored " + std::to_string(length) + " bytes from " +
             datagram.from.toString() + ": " + hexPreview(data, length, 16));
    }
}

}  // namespace nfslan
