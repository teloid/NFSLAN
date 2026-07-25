#include "nfslan/net.hpp"

#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace nfslan {
namespace {

#ifdef _WIN32
using RawSocket = std::uintptr_t;
constexpr RawSocket kInvalidSocket = ~std::uintptr_t(0);

int lastSocketError() { return WSAGetLastError(); }
bool errorIsTimeout(int code) { return code == WSAETIMEDOUT || code == WSAEWOULDBLOCK; }
void closeRaw(RawSocket s) { ::closesocket(static_cast<SOCKET>(s)); }
#else
using RawSocket = int;
constexpr RawSocket kInvalidSocket = -1;

int lastSocketError() { return errno; }
bool errorIsTimeout(int code) { return code == EAGAIN || code == EWOULDBLOCK; }
void closeRaw(RawSocket s) { ::close(s); }
#endif

std::string describeError(int code) {
#ifdef _WIN32
    char* text = nullptr;
    const DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(code), 0, reinterpret_cast<char*>(&text), 0, nullptr);
    std::string out = length && text ? std::string(text, length) : ("error " + std::to_string(code));
    if (text) {
        LocalFree(text);
    }
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) {
        out.pop_back();
    }
    return out;
#else
    return std::strerror(code);
#endif
}

sockaddr_in makeSockaddr(const Endpoint& endpoint) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(endpoint.address);
    addr.sin_port = htons(endpoint.port);
    return addr;
}

Endpoint fromSockaddr(const sockaddr_in& addr) {
    Endpoint endpoint;
    endpoint.address = ntohl(addr.sin_addr.s_addr);
    endpoint.port = ntohs(addr.sin_port);
    return endpoint;
}

// select() on a single socket, so we get portable timeouts without going
// non-blocking everywhere. Returns 1 = ready, 0 = timeout, -1 = error.
int waitReadable(RawSocket handle, int timeoutMs) {
    fd_set readSet;
    FD_ZERO(&readSet);
#ifdef _WIN32
    FD_SET(static_cast<SOCKET>(handle), &readSet);
#else
    FD_SET(handle, &readSet);
#endif

    timeval timeout{};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;

#ifdef _WIN32
    return ::select(0, &readSet, nullptr, nullptr, &timeout);
#else
    return ::select(handle + 1, &readSet, nullptr, nullptr, &timeout);
#endif
}

bool applyReceiveTimeout(RawSocket handle, int milliseconds) {
#ifdef _WIN32
    DWORD value = static_cast<DWORD>(milliseconds);
    return ::setsockopt(static_cast<SOCKET>(handle), SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
#else
    timeval value{};
    value.tv_sec = milliseconds / 1000;
    value.tv_usec = (milliseconds % 1000) * 1000;
    return ::setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) == 0;
#endif
}

}  // namespace

// --- NetStartup -------------------------------------------------------------

NetStartup::NetStartup() {
#ifdef _WIN32
    WSADATA data{};
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        error_ = "WSAStartup failed: " + describeError(result);
        return;
    }
#endif
    ok_ = true;
}

NetStartup::~NetStartup() {
#ifdef _WIN32
    if (ok_) {
        WSACleanup();
    }
#endif
}

// --- Endpoint and address helpers ------------------------------------------

std::string Endpoint::toString() const {
    return ipv4ToString(address) + ":" + std::to_string(port);
}

std::string ipv4ToString(std::uint32_t address) {
    return std::to_string((address >> 24) & 0xFF) + "." + std::to_string((address >> 16) & 0xFF) +
           "." + std::to_string((address >> 8) & 0xFF) + "." + std::to_string(address & 0xFF);
}

std::optional<std::uint32_t> parseIpv4(const std::string& text) {
    if (text.empty()) {
        return std::nullopt;
    }
    in_addr parsed{};
    if (::inet_pton(AF_INET, text.c_str(), &parsed) != 1) {
        return std::nullopt;
    }
    return ntohl(parsed.s_addr);
}

std::optional<std::uint32_t> resolveHost(const std::string& host) {
    if (auto direct = parseIpv4(host)) {
        return direct;
    }
    if (host.empty()) {
        return std::nullopt;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* results = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &results) != 0 || !results) {
        return std::nullopt;
    }

    std::optional<std::uint32_t> found;
    for (addrinfo* it = results; it; it = it->ai_next) {
        if (it->ai_family == AF_INET && it->ai_addr) {
            found = ntohl(reinterpret_cast<sockaddr_in*>(it->ai_addr)->sin_addr.s_addr);
            break;
        }
    }
    ::freeaddrinfo(results);
    return found;
}

std::optional<std::uint32_t> preferredLocalAddress() {
    RawSocket probe = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (probe == kInvalidSocket) {
        return std::nullopt;
    }

    // Connecting a UDP socket sends nothing; it just asks the routing table
    // which local address would be used to reach this destination.
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(53);
    target.sin_addr.s_addr = htonl(0x08080808u);  // 8.8.8.8

    std::optional<std::uint32_t> result;
    if (::connect(probe, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 0) {
        sockaddr_in local{};
#ifdef _WIN32
        int length = sizeof(local);
#else
        socklen_t length = sizeof(local);
#endif
        if (::getsockname(probe, reinterpret_cast<sockaddr*>(&local), &length) == 0) {
            const std::uint32_t address = ntohl(local.sin_addr.s_addr);
            if (address != 0 && address != kAddrLoopback) {
                result = address;
            }
        }
    }

    closeRaw(probe);
    return result;
}

std::vector<std::uint32_t> broadcastAddresses() {
    std::vector<std::uint32_t> found;

#ifdef _WIN32
    ULONG size = 16 * 1024;
    std::vector<std::uint8_t> buffer(size);
    PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    ULONG result = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                                     GAA_FLAG_SKIP_DNS_SERVER,
                                        nullptr, adapters, &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                                   GAA_FLAG_SKIP_DNS_SERVER,
                                      nullptr, adapters, &size);
    }

    if (result == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                continue;
            }
            for (PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress; unicast;
                 unicast = unicast->Next) {
                if (!unicast->Address.lpSockaddr || unicast->Address.lpSockaddr->sa_family != AF_INET) {
                    continue;
                }
                const std::uint32_t address =
                    ntohl(reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr)->sin_addr.s_addr);
                const ULONG prefix = unicast->OnLinkPrefixLength;
                if (prefix == 0 || prefix > 32) {
                    continue;
                }
                const std::uint32_t mask =
                    prefix == 32 ? 0xFFFFFFFFu : ~((1u << (32 - prefix)) - 1u);
                found.push_back((address & mask) | ~mask);
            }
        }
    }
#else
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) == 0) {
        for (ifaddrs* it = list; it; it = it->ifa_next) {
            if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) {
                continue;
            }
            if (!(it->ifa_flags & IFF_UP) || !(it->ifa_flags & IFF_BROADCAST)) {
                continue;
            }
            if (it->ifa_flags & IFF_LOOPBACK) {
                continue;
            }
            if (it->ifa_dstaddr) {
                const std::uint32_t address =
                    ntohl(reinterpret_cast<sockaddr_in*>(it->ifa_dstaddr)->sin_addr.s_addr);
                if (address != 0) {
                    found.push_back(address);
                }
            }
        }
        ::freeifaddrs(list);
    }
#endif

    // Deduplicate, then guarantee at least the global broadcast address.
    std::vector<std::uint32_t> unique;
    for (std::uint32_t address : found) {
        bool seen = false;
        for (std::uint32_t existing : unique) {
            if (existing == address) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            unique.push_back(address);
        }
    }
    if (unique.empty()) {
        unique.push_back(kAddrBroadcast);
    }
    return unique;
}

// --- UdpSocket --------------------------------------------------------------

UdpSocket::~UdpSocket() { close(); }

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
    : handle_(other.handle_), lastError_(std::move(other.lastError_)) {
    other.handle_ = kInvalidSocket;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        lastError_ = std::move(other.lastError_);
        other.handle_ = kInvalidSocket;
    }
    return *this;
}

bool UdpSocket::isOpen() const { return handle_ != kInvalidSocket; }

bool UdpSocket::open() {
    close();
    const RawSocket created = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (created == kInvalidSocket) {
        lastError_ = "socket() failed: " + describeError(lastSocketError());
        return false;
    }
    handle_ = created;
    lastError_.clear();
    return true;
}

void UdpSocket::close() {
    if (handle_ != kInvalidSocket) {
        closeRaw(handle_);
        handle_ = kInvalidSocket;
    }
}

bool UdpSocket::setReuseAddress(bool enable) {
    if (!isOpen()) {
        lastError_ = "socket is not open";
        return false;
    }
    const int value = enable ? 1 : 0;
    bool ok = ::setsockopt(handle_, SOL_SOCKET, SO_REUSEADDR,
                           reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
#ifdef SO_REUSEPORT
    // macOS and the BSDs need SO_REUSEPORT as well before two processes may
    // share the discovery port; Linux accepts it too.
    if (ok) {
        ::setsockopt(handle_, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char*>(&value),
                     sizeof(value));
    }
#endif
    if (!ok) {
        lastError_ = "SO_REUSEADDR failed: " + describeError(lastSocketError());
    }
    return ok;
}

bool UdpSocket::setBroadcast(bool enable) {
    if (!isOpen()) {
        lastError_ = "socket is not open";
        return false;
    }
    const int value = enable ? 1 : 0;
    if (::setsockopt(handle_, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&value),
                     sizeof(value)) != 0) {
        lastError_ = "SO_BROADCAST failed: " + describeError(lastSocketError());
        return false;
    }
    return true;
}

bool UdpSocket::setReceiveTimeout(int milliseconds) {
    if (!isOpen()) {
        lastError_ = "socket is not open";
        return false;
    }
    if (!applyReceiveTimeout(handle_, milliseconds)) {
        lastError_ = "SO_RCVTIMEO failed: " + describeError(lastSocketError());
        return false;
    }
    return true;
}

bool UdpSocket::bind(std::uint16_t port, std::uint32_t address) {
    if (!isOpen()) {
        lastError_ = "socket is not open";
        return false;
    }
    Endpoint endpoint{address, port};
    const sockaddr_in addr = makeSockaddr(endpoint);
    if (::bind(handle_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        lastError_ = "bind(" + endpoint.toString() + ") failed: " + describeError(lastSocketError());
        return false;
    }
    return true;
}

bool UdpSocket::sendTo(const Endpoint& to, const void* data, std::size_t length) {
    if (!isOpen()) {
        lastError_ = "socket is not open";
        return false;
    }
    const sockaddr_in addr = makeSockaddr(to);
    const auto sent = ::sendto(handle_, static_cast<const char*>(data), static_cast<int>(length), 0,
                               reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    if (sent < 0 || static_cast<std::size_t>(sent) != length) {
        lastError_ = "sendto(" + to.toString() + ") failed: " + describeError(lastSocketError());
        return false;
    }
    return true;
}

std::optional<Datagram> UdpSocket::receive(std::size_t maxLength) {
    if (!isOpen()) {
        lastError_ = "socket is not open";
        return std::nullopt;
    }

    Datagram result;
    result.data.resize(maxLength);

    sockaddr_in from{};
#ifdef _WIN32
    int fromLength = sizeof(from);
#else
    socklen_t fromLength = sizeof(from);
#endif

    const auto received =
        ::recvfrom(handle_, reinterpret_cast<char*>(result.data.data()), static_cast<int>(maxLength),
                   0, reinterpret_cast<sockaddr*>(&from), &fromLength);
    if (received < 0) {
        const int code = lastSocketError();
        // A clean timeout is not an error; leave lastError_ empty to say so.
        lastError_ = errorIsTimeout(code) ? std::string() : ("recvfrom failed: " + describeError(code));
        return std::nullopt;
    }

    result.data.resize(static_cast<std::size_t>(received));
    result.from = fromSockaddr(from);
    lastError_.clear();
    return result;
}

// --- TcpConnection ----------------------------------------------------------

TcpConnection::~TcpConnection() { close(); }

TcpConnection::TcpConnection(TcpConnection&& other) noexcept
    : handle_(other.handle_), peer_(other.peer_), lastError_(std::move(other.lastError_)) {
    other.handle_ = kInvalidSocket;
}

TcpConnection& TcpConnection::operator=(TcpConnection&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        peer_ = other.peer_;
        lastError_ = std::move(other.lastError_);
        other.handle_ = kInvalidSocket;
    }
    return *this;
}

bool TcpConnection::isOpen() const { return handle_ != kInvalidSocket; }

void TcpConnection::close() {
    if (handle_ != kInvalidSocket) {
        closeRaw(handle_);
        handle_ = kInvalidSocket;
    }
}

bool TcpConnection::setNoDelay(bool enable) {
    if (!isOpen()) {
        lastError_ = "connection is not open";
        return false;
    }
    const int value = enable ? 1 : 0;
    if (::setsockopt(handle_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&value),
                     sizeof(value)) != 0) {
        lastError_ = "TCP_NODELAY failed: " + describeError(lastSocketError());
        return false;
    }
    return true;
}

bool TcpConnection::setReceiveTimeout(int milliseconds) {
    if (!isOpen()) {
        lastError_ = "connection is not open";
        return false;
    }
    if (!applyReceiveTimeout(handle_, milliseconds)) {
        lastError_ = "SO_RCVTIMEO failed: " + describeError(lastSocketError());
        return false;
    }
    return true;
}

int TcpConnection::receive(void* buffer, std::size_t length) {
    if (!isOpen()) {
        lastError_ = "connection is not open";
        return -1;
    }
    const auto received = ::recv(handle_, static_cast<char*>(buffer), static_cast<int>(length), 0);
    if (received < 0) {
        const int code = lastSocketError();
        if (errorIsTimeout(code)) {
            lastError_.clear();
            return -2;
        }
        lastError_ = "recv failed: " + describeError(code);
        return -1;
    }
    lastError_.clear();
    return static_cast<int>(received);
}

bool TcpConnection::sendAll(const void* data, std::size_t length) {
    if (!isOpen()) {
        lastError_ = "connection is not open";
        return false;
    }
    const char* cursor = static_cast<const char*>(data);
    std::size_t remaining = length;
    while (remaining > 0) {
        const auto sent = ::send(handle_, cursor, static_cast<int>(remaining), 0);
        if (sent <= 0) {
            const int code = lastSocketError();
            if (errorIsTimeout(code)) {
                continue;
            }
            lastError_ = "send failed: " + describeError(code);
            return false;
        }
        cursor += sent;
        remaining -= static_cast<std::size_t>(sent);
    }
    return true;
}

// --- TcpListener ------------------------------------------------------------

TcpListener::~TcpListener() { close(); }

bool TcpListener::isOpen() const { return handle_ != kInvalidSocket; }

void TcpListener::close() {
    if (handle_ != kInvalidSocket) {
        closeRaw(handle_);
        handle_ = kInvalidSocket;
    }
}

bool TcpListener::listen(std::uint16_t port, std::uint32_t address, int backlog) {
    close();

    const RawSocket created = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (created == kInvalidSocket) {
        lastError_ = "socket() failed: " + describeError(lastSocketError());
        return false;
    }

    const int reuse = 1;
    ::setsockopt(created, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
                 sizeof(reuse));

    Endpoint endpoint{address, port};
    const sockaddr_in addr = makeSockaddr(endpoint);
    if (::bind(created, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        lastError_ = "bind(" + endpoint.toString() + ") failed: " + describeError(lastSocketError());
        closeRaw(created);
        return false;
    }

    if (::listen(created, backlog) != 0) {
        lastError_ = "listen failed: " + describeError(lastSocketError());
        closeRaw(created);
        return false;
    }

    handle_ = created;
    lastError_.clear();
    return true;
}

std::optional<TcpConnection> TcpListener::accept(int timeoutMs) {
    if (!isOpen()) {
        lastError_ = "listener is not open";
        return std::nullopt;
    }

    const int ready = waitReadable(handle_, timeoutMs);
    if (ready == 0) {
        lastError_.clear();  // timeout, not an error
        return std::nullopt;
    }
    if (ready < 0) {
        lastError_ = "select failed: " + describeError(lastSocketError());
        return std::nullopt;
    }

    sockaddr_in from{};
#ifdef _WIN32
    int fromLength = sizeof(from);
#else
    socklen_t fromLength = sizeof(from);
#endif

    const RawSocket accepted = ::accept(handle_, reinterpret_cast<sockaddr*>(&from), &fromLength);
    if (accepted == kInvalidSocket) {
        lastError_ = "accept failed: " + describeError(lastSocketError());
        return std::nullopt;
    }

    TcpConnection connection;
    connection.handle_ = accepted;
    connection.peer_ = fromSockaddr(from);
    lastError_.clear();
    return connection;
}

}  // namespace nfslan
