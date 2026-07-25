// Portable BSD/Winsock socket wrappers for NFSLAN.
//
// Replaces the Winsock-only Network.h. Everything here compiles on macOS,
// Linux and Windows; platform differences are confined to net.cpp.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nfslan {

// One-shot Winsock init/teardown. A no-op on POSIX, so it is always safe (and
// expected) to instantiate one of these in main() before touching sockets.
class NetStartup {
public:
    NetStartup();
    ~NetStartup();

    NetStartup(const NetStartup&) = delete;
    NetStartup& operator=(const NetStartup&) = delete;

    bool ok() const { return ok_; }
    const std::string& error() const { return error_; }

private:
    bool ok_ = false;
    std::string error_;
};

// An IPv4 endpoint in host byte order, so comparisons and logging stay obvious.
struct Endpoint {
    std::uint32_t address = 0;  // host byte order; 0 == INADDR_ANY
    std::uint16_t port = 0;

    std::string toString() const;

    friend bool operator==(const Endpoint& a, const Endpoint& b) {
        return a.address == b.address && a.port == b.port;
    }
};

// "192.168.1.10" -> Endpoint{...}. Rejects anything that is not dotted-quad
// IPv4; hostnames are resolved by resolveHost() instead.
std::optional<std::uint32_t> parseIpv4(const std::string& text);
std::string ipv4ToString(std::uint32_t address);

// Resolves a hostname or dotted-quad to a single IPv4 address.
std::optional<std::uint32_t> resolveHost(const std::string& host);

// Best-effort discovery of the LAN-facing IPv4 address of this machine. Uses a
// connect() on a UDP socket to a public address, which picks the interface the
// routing table prefers without sending a packet.
std::optional<std::uint32_t> preferredLocalAddress();

// All usable IPv4 broadcast addresses, one per up/broadcast-capable interface.
// Falls back to 255.255.255.255 when interface enumeration is unavailable.
std::vector<std::uint32_t> broadcastAddresses();

constexpr std::uint32_t kAddrAny = 0x00000000u;
constexpr std::uint32_t kAddrLoopback = 0x7F000001u;
constexpr std::uint32_t kAddrBroadcast = 0xFFFFFFFFu;

// Result of a datagram read.
struct Datagram {
    std::vector<std::uint8_t> data;
    Endpoint from;
};

class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket();

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&& other) noexcept;
    UdpSocket& operator=(UdpSocket&& other) noexcept;

    bool open();
    void close();
    bool isOpen() const;

    // SO_REUSEADDR (plus SO_REUSEPORT where it exists) must be set before
    // bind() for multiple listeners on the discovery port to coexist.
    bool setReuseAddress(bool enable);
    bool setBroadcast(bool enable);
    bool setReceiveTimeout(int milliseconds);

    bool bind(std::uint16_t port, std::uint32_t address = kAddrAny);

    bool sendTo(const Endpoint& to, const void* data, std::size_t length);
    bool sendTo(const Endpoint& to, const std::vector<std::uint8_t>& data) {
        return sendTo(to, data.data(), data.size());
    }

    // Returns std::nullopt on timeout or error; check lastError() to tell them
    // apart (it is empty after a clean timeout).
    std::optional<Datagram> receive(std::size_t maxLength = 2048);

    const std::string& lastError() const { return lastError_; }

private:
#ifdef _WIN32
    std::uintptr_t handle_ = ~std::uintptr_t(0);
#else
    int handle_ = -1;
#endif
    std::string lastError_;
};

class TcpConnection {
public:
    TcpConnection() = default;
    ~TcpConnection();

    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;
    TcpConnection(TcpConnection&& other) noexcept;
    TcpConnection& operator=(TcpConnection&& other) noexcept;

    void close();
    bool isOpen() const;

    bool setNoDelay(bool enable);
    bool setReceiveTimeout(int milliseconds);

    // Returns bytes read, 0 on orderly shutdown, -1 on error, -2 on timeout.
    int receive(void* buffer, std::size_t length);
    bool sendAll(const void* data, std::size_t length);
    bool sendAll(const std::string& text) { return sendAll(text.data(), text.size()); }

    const Endpoint& peer() const { return peer_; }
    const std::string& lastError() const { return lastError_; }

private:
    friend class TcpListener;

#ifdef _WIN32
    std::uintptr_t handle_ = ~std::uintptr_t(0);
#else
    int handle_ = -1;
#endif
    Endpoint peer_;
    std::string lastError_;
};

class TcpListener {
public:
    TcpListener() = default;
    ~TcpListener();

    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    bool listen(std::uint16_t port, std::uint32_t address = kAddrAny, int backlog = 16);
    void close();
    bool isOpen() const;

    // Waits up to timeoutMs for an inbound connection. Returns an unset
    // optional on timeout or error.
    std::optional<TcpConnection> accept(int timeoutMs);

    const std::string& lastError() const { return lastError_; }

private:
#ifdef _WIN32
    std::uintptr_t handle_ = ~std::uintptr_t(0);
#else
    int handle_ = -1;
#endif
    std::string lastError_;
};

}  // namespace nfslan
