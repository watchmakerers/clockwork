// soc:U: BSD sockets on the PC's own network, for Nintendo Network play (net/online.h). The game's
// NEX (server) and PIA (player to player) libraries talk UDP and TCP through it, so they reach the
// same servers and the same players as a 3DS would.
//
// Only active while online play is on; otherwise every call but Initialize fails, as before.
//
// Host sockets are always non-blocking. A guest socket left blocking waits by retrying, with the
// kernel lock released so the game's other threads keep running.
#include "service.h"

#include "log.h"
#include "memory.h"
#include "net/online.h"
#include "net/socket.h"
#include "platform.h"

#if !defined(_WIN32)
#include <cerrno>
#include <netinet/tcp.h>
#include <poll.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <set>
#include <thread>
#include <vector>

namespace hle {
namespace {

using Clock = std::chrono::steady_clock;
constexpr uint32_t ERR_UNAVAILABLE = 0xC8A12402;

// ---- the 3DS's socket constants (its libc's, not the PC's) ----
constexpr int G_AF_INET = 2;
constexpr int G_SOCK_STREAM = 1, G_SOCK_DGRAM = 2;
constexpr int G_MSG_OOB = 1, G_MSG_PEEK = 2, G_MSG_DONTWAIT = 4;
constexpr int G_F_GETFL = 3, G_F_SETFL = 4, G_O_NONBLOCK = 4;
constexpr int G_SOL_SOCKET = 0xFFFF;
constexpr int16_t G_POLLIN = 0x01, G_POLLPRI = 0x02, G_POLLHUP = 0x04, G_POLLERR = 0x08, G_POLLOUT = 0x10,
                  G_POLLNVAL = 0x20;

// 3DS errno values (alphabetical, from 1); calls return them negated
enum GErr : int32_t {
    G_EACCES = 2, G_EADDRINUSE = 3, G_EADDRNOTAVAIL = 4, G_EAFNOSUPPORT = 5, G_EAGAIN = 6, G_EALREADY = 7,
    G_EBADF = 8, G_ECONNABORTED = 13, G_ECONNREFUSED = 14, G_ECONNRESET = 15, G_EDESTADDRREQ = 17,
    G_EHOSTUNREACH = 23, G_EINPROGRESS = 26, G_EINTR = 27, G_EINVAL = 28, G_EIO = 29, G_EISCONN = 30,
    G_EMFILE = 33, G_EMSGSIZE = 35, G_ENETDOWN = 38, G_ENETRESET = 39, G_ENETUNREACH = 40, G_ENOBUFS = 42,
    G_ENOMEM = 49, G_ENOPROTOOPT = 51, G_ENOTCONN = 56, G_ENOTSOCK = 59, G_EOPNOTSUPP = 63, G_EPIPE = 66,
    G_EPROTONOSUPPORT = 68, G_EPROTOTYPE = 69, G_ETIMEDOUT = 76,
};

int last_error() {
#if defined(_WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool would_block(int e) {
#if defined(_WIN32)
    return e == WSAEWOULDBLOCK;
#else
    return e == EAGAIN || e == EWOULDBLOCK;
#endif
}

int32_t guest_errno(int e) {
#if defined(_WIN32)
    switch (e) {
    case WSAEWOULDBLOCK: return G_EAGAIN;
    case WSAEINPROGRESS: return G_EINPROGRESS;
    case WSAEALREADY: return G_EALREADY;
    case WSAENOTSOCK: return G_ENOTSOCK;
    case WSAEDESTADDRREQ: return G_EDESTADDRREQ;
    case WSAEMSGSIZE: return G_EMSGSIZE;
    case WSAEPROTOTYPE: return G_EPROTOTYPE;
    case WSAENOPROTOOPT: return G_ENOPROTOOPT;
    case WSAEPROTONOSUPPORT: return G_EPROTONOSUPPORT;
    case WSAEOPNOTSUPP: return G_EOPNOTSUPP;
    case WSAEAFNOSUPPORT: return G_EAFNOSUPPORT;
    case WSAEADDRINUSE: return G_EADDRINUSE;
    case WSAEADDRNOTAVAIL: return G_EADDRNOTAVAIL;
    case WSAENETDOWN: return G_ENETDOWN;
    case WSAENETUNREACH: return G_ENETUNREACH;
    case WSAENETRESET: return G_ENETRESET;
    case WSAECONNABORTED: return G_ECONNABORTED;
    case WSAECONNRESET: return G_ECONNRESET;
    case WSAENOBUFS: return G_ENOBUFS;
    case WSAEISCONN: return G_EISCONN;
    case WSAENOTCONN: return G_ENOTCONN;
    case WSAETIMEDOUT: return G_ETIMEDOUT;
    case WSAECONNREFUSED: return G_ECONNREFUSED;
    case WSAEHOSTUNREACH: return G_EHOSTUNREACH;
    case WSAEINVAL: return G_EINVAL;
    case WSAEACCES: return G_EACCES;
    case WSAEMFILE: return G_EMFILE;
    default: return G_EIO;
    }
#else
    switch (e) {
    case EAGAIN: return G_EAGAIN;
    case EINPROGRESS: return G_EINPROGRESS;
    case EALREADY: return G_EALREADY;
    case ENOTSOCK: return G_ENOTSOCK;
    case EDESTADDRREQ: return G_EDESTADDRREQ;
    case EMSGSIZE: return G_EMSGSIZE;
    case EPROTOTYPE: return G_EPROTOTYPE;
    case ENOPROTOOPT: return G_ENOPROTOOPT;
    case EPROTONOSUPPORT: return G_EPROTONOSUPPORT;
    case EOPNOTSUPP: return G_EOPNOTSUPP;
    case EAFNOSUPPORT: return G_EAFNOSUPPORT;
    case EADDRINUSE: return G_EADDRINUSE;
    case EADDRNOTAVAIL: return G_EADDRNOTAVAIL;
    case ENETDOWN: return G_ENETDOWN;
    case ENETUNREACH: return G_ENETUNREACH;
    case ENETRESET: return G_ENETRESET;
    case ECONNABORTED: return G_ECONNABORTED;
    case ECONNRESET: return G_ECONNRESET;
    case ENOBUFS: return G_ENOBUFS;
    case EISCONN: return G_EISCONN;
    case ENOTCONN: return G_ENOTCONN;
    case ETIMEDOUT: return G_ETIMEDOUT;
    case ECONNREFUSED: return G_ECONNREFUSED;
    case EHOSTUNREACH: return G_EHOSTUNREACH;
    case EINVAL: return G_EINVAL;
    case EACCES: return G_EACCES;
    case EMFILE: return G_EMFILE;
    case EPIPE: return G_EPIPE;
    case EINTR: return G_EINTR;
    case ENOMEM: return G_ENOMEM;
    case EBADF: return G_EBADF;
    default: return G_EIO;
    }
#endif
}

void set_nonblocking(net::socket_t s) {
#if defined(_WIN32)
    u_long on = 1;
    ioctlsocket(s, FIONBIO, &on);
#else
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
#endif
}

// waits up to `ms` for `s` to be readable (or writable); true if it is
bool wait_socket(net::socket_t s, bool write, int ms) {
#if defined(_WIN32)
    WSAPOLLFD p{s, short(write ? POLLWRNORM : POLLRDNORM), 0};
    return WSAPoll(&p, 1, ms) > 0;
#else
    pollfd p{s, short(write ? POLLOUT : POLLIN), 0};
    return ::poll(&p, 1, ms) > 0;
#endif
}

// ---- the 3DS's sockaddr_in: length, family, port (big-endian), address ----
struct GuestAddr {
    uint8_t len, family;
    uint16_t port; // network order
    uint32_t addr; // network order
};
static_assert(sizeof(GuestAddr) == 8);

bool to_host(const uint8_t *g, uint32_t size, sockaddr_in &out) {
    if (size < sizeof(GuestAddr)) return false;
    GuestAddr a;
    std::memcpy(&a, g, sizeof a);
    if (a.family != G_AF_INET) return false;
    out = {};
    out.sin_family = AF_INET;
    out.sin_port = a.port;
    out.sin_addr.s_addr = a.addr;
    return true;
}

// a guest sockaddr of `size` bytes (0x1C for sockaddr_storage) for `in`
std::vector<uint8_t> to_guest(const sockaddr_in &in, uint32_t size) {
    std::vector<uint8_t> out(std::min<uint32_t>(size, 0x1C), 0);
    GuestAddr a{8, G_AF_INET, in.sin_port, in.sin_addr.s_addr};
    std::memcpy(out.data(), &a, std::min<size_t>(out.size(), sizeof a));
    return out;
}

// the address this PC uses toward the internet (no packet is sent)
uint32_t local_address() {
    net::socket_t s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == net::NO_SOCKET) return htonl(0x7F000001);
    sockaddr_in to{};
    to.sin_family = AF_INET, to.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &to.sin_addr);
    sockaddr_in me{};
    socklen_t len = sizeof me;
    uint32_t ip = htonl(0x7F000001);
    if (connect(s, reinterpret_cast<sockaddr *>(&to), sizeof to) == 0 &&
        getsockname(s, reinterpret_cast<sockaddr *>(&me), &len) == 0)
        ip = me.sin_addr.s_addr;
    net::close_socket(s);
    return ip;
}

// Nimbus's socket patch on a 3DS sends the NAT check to Pretendo's servers; so does Clockwork
std::string rewrite_host(const std::string &name) {
    if (name == "nncs1.app.nintendowifi.net") return "nncs1.app.pretendo.cc";
    if (name == "nncs2.app.nintendowifi.net") return "nncs2.app.pretendo.cc";
    return name;
}

struct Socket {
    net::socket_t host = net::NO_SOCKET;
    int type = 0;
    bool nonblocking = false; // as the game set it
};

struct Soc : Service {
    std::map<int32_t, Socket> sockets;
    int32_t next_fd = 3;
    std::set<uint16_t> logged;

    Soc() : Service("soc:U") {}

    // a translate word after the normal ones
    static uint32_t tr(const Request &req, int i) { return req.in[1 + req.normal_count() + i]; }

    Socket *find(int32_t fd) {
        auto it = sockets.find(fd);
        return it == sockets.end() ? nullptr : &it->second;
    }

    // lets the game's other threads run while this one waits up to `ms` on host socket `s`
    static void wait(Request &req, net::socket_t s, bool write, int ms) {
        kernel::Thread *self = kernel::current_thread();
        kernel::release_cpu();
        req.lock->unlock();
        wait_socket(s, write, ms);
        req.lock->lock();
        kernel::reacquire_cpu(*req.lock, self);
    }

    // runs `op` (returning >= 0, or -1 with the error set) until it doesn't block, unless the
    // socket or this call is non-blocking; -> its result or a negated 3DS errno
    template <typename F> int32_t blocking(Request &req, int32_t fd, bool write, bool dontwait, F op) {
        for (;;) {
            Socket *s = find(fd);
            if (!s) return -G_EBADF;
            int r = op(*s);
            if (r >= 0) return r;
            int e = last_error();
            if (!would_block(e) || s->nonblocking || dontwait) return -guest_errno(e);
            wait(req, s->host, write, 20);
        }
    }

    void reply_ret(Request &req, int32_t ret) {
        auto r = req.reply(2, 0);
        r.push(uint32_t(ret));
    }

    void handle(Request &req) override {
        if (logged.insert(req.id()).second) LOG("soc: first call of %#06x", req.id());
        if (!online::enabled() && req.id() != 0x0001) {
            req.reply(1, 0, ERR_UNAVAILABLE);
            return;
        }
        switch (req.id()) {
        case 0x0001: // InitializeSockets(shared memory size, process, shared memory)
            net::sockets_start();
            req.reply(1, 0);
            break;

        case 0x0002: { // Socket(domain, type, protocol, process) -> fd
            int domain = int(req.arg(0)), type = int(req.arg(1)), proto = int(req.arg(2));
            if (domain != G_AF_INET) return reply_ret(req, -G_EAFNOSUPPORT);
            if (type != G_SOCK_STREAM && type != G_SOCK_DGRAM) return reply_ret(req, -G_EPROTOTYPE);
            net::socket_t h = socket(AF_INET, type == G_SOCK_STREAM ? SOCK_STREAM : SOCK_DGRAM, proto);
            if (h == net::NO_SOCKET) return reply_ret(req, -guest_errno(last_error()));
            set_nonblocking(h);
            int32_t fd = next_fd++;
            sockets[fd] = Socket{h, type, false};
            reply_ret(req, fd);
            break;
        }

        case 0x0003: { // Listen(fd, backlog, process)
            Socket *s = find(int32_t(req.arg(0)));
            if (!s) return reply_ret(req, -G_EBADF);
            reply_ret(req, listen(s->host, int(req.arg(1))) == 0 ? 0 : -guest_errno(last_error()));
            break;
        }

        case 0x0004: { // Accept(fd, max address length, process) -> fd, static buffer 0: address
            int32_t fd = int32_t(req.arg(0));
            uint32_t addr_len = req.arg(1);
            sockaddr_in from{};
            int32_t ret = blocking(req, fd, false, false, [&](Socket &s) {
                socklen_t len = sizeof from;
                net::socket_t h = accept(s.host, reinterpret_cast<sockaddr *>(&from), &len);
                if (h == net::NO_SOCKET) return -1;
                set_nonblocking(h);
                int32_t nfd = next_fd++;
                sockets[nfd] = Socket{h, G_SOCK_STREAM, false};
                return int(nfd);
            });
            auto addr = ret >= 0 ? to_guest(from, addr_len) : std::vector<uint8_t>();
            auto r = req.reply(2, 2);
            r.push(uint32_t(ret));
            req.push_static_buffer_clamped(r, 0, addr.data(), uint32_t(addr.size()));
            break;
        }

        case 0x0005:   // Bind(fd, address length, process, static buffer: address)
        case 0x0006: { // Connect(same)
            int32_t fd = int32_t(req.arg(0));
            uint32_t len = req.arg(1);
            sockaddr_in to{};
            if (!find(fd)) return reply_ret(req, -G_EBADF);
            if (!to_host(mem::ptr(tr(req, 3)), len, to)) return reply_ret(req, -G_EINVAL);
            if (req.id() == 0x0005) {
                Socket *s = find(fd);
                reply_ret(req, bind(s->host, reinterpret_cast<sockaddr *>(&to), sizeof to) == 0 ? 0 : -guest_errno(last_error()));
                break;
            }
            LOG("soc: connect %d to %s", fd, net::addr_text(to).c_str());
            Socket *s = find(fd);
            int32_t ret = 0;
            if (connect(s->host, reinterpret_cast<sockaddr *>(&to), sizeof to) != 0) {
                int e = last_error();
#if defined(_WIN32)
                bool pending = e == WSAEWOULDBLOCK;
#else
                bool pending = e == EINPROGRESS;
#endif
                if (!pending) ret = -guest_errno(e);
                else if (s->nonblocking) ret = -G_EINPROGRESS;
                else {
                    // a blocking connect: wait until it's done, then report how it went
                    net::socket_t h = s->host;
                    for (;;) {
                        if (wait_socket(h, true, 0)) break;
                        wait(req, h, true, 20);
                        if (!find(fd)) return reply_ret(req, -G_EBADF);
                    }
                    int err = 0;
                    socklen_t el = sizeof err;
                    getsockopt(h, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&err), &el);
                    ret = err ? -guest_errno(err) : 0;
                }
            }
            reply_ret(req, ret);
            break;
        }

        case 0x0007:   // RecvFromOther(fd, length, flags, address length, process, mapped buffer)
        case 0x0008: { // RecvFrom(fd, length, flags, address length, process) -> static buffers 0 data, 1 address
            int32_t fd = int32_t(req.arg(0));
            uint32_t len = req.arg(1), flags = req.arg(2), addr_len = req.arg(3);
            // never more than the game's buffer holds: its static buffer, or the mapped one's size
            uint32_t room = req.id() == 0x0008 ? req.static_buffer_size(0) : tr(req, 2) >> 4;
            len = std::min({len, room, 0x10000u});
            std::vector<uint8_t> buf(len);
            sockaddr_in from{};
            int host_flags = (flags & G_MSG_PEEK ? MSG_PEEK : 0) | (flags & G_MSG_OOB ? MSG_OOB : 0);
            int32_t ret = blocking(req, fd, false, flags & G_MSG_DONTWAIT, [&](Socket &s) {
                socklen_t fl = sizeof from;
                return int(recvfrom(s.host, reinterpret_cast<char *>(buf.data()), int(len), host_flags,
                                    reinterpret_cast<sockaddr *>(&from), &fl));
            });
            auto addr = ret >= 0 && addr_len ? to_guest(from, addr_len) : std::vector<uint8_t>();
            if (req.id() == 0x0007) {
                uint32_t desc = tr(req, 2), dest = tr(req, 3);
                if (ret > 0) std::memcpy(mem::ptr(dest), buf.data(), size_t(ret));
                auto r = req.reply(2, 4);
                r.push(uint32_t(ret));
                req.push_static_buffer_clamped(r, 0, addr.data(), uint32_t(addr.size()));
                r.push(desc);
                r.push(dest);
            } else {
                auto r = req.reply(3, 4);
                r.push(uint32_t(ret));
                r.push(uint32_t(std::max(ret, 0)));
                req.push_static_buffer_clamped(r, 0, buf.data(), uint32_t(std::max(ret, 0)));
                req.push_static_buffer_clamped(r, 1, addr.data(), uint32_t(addr.size()));
            }
            break;
        }

        case 0x0009:   // SendToOther(fd, length, flags, address length, process, static buffer 1: address, mapped buffer: data)
        case 0x000A: { // SendTo(fd, length, flags, address length, process, static buffer 2: data, static buffer 1: address)
            int32_t fd = int32_t(req.arg(0));
            uint32_t len = req.arg(1), flags = req.arg(2), addr_len = req.arg(3);
            const uint8_t *data, *gaddr;
            if (req.id() == 0x0009) gaddr = mem::ptr(tr(req, 3)), data = mem::ptr(tr(req, 5));
            else data = mem::ptr(tr(req, 3)), gaddr = mem::ptr(tr(req, 5));
            sockaddr_in to{};
            bool has_to = addr_len && to_host(gaddr, addr_len, to);
            if (addr_len && !has_to) return reply_ret(req, -G_EINVAL);
            int host_flags = flags & G_MSG_OOB ? MSG_OOB : 0;
            int32_t ret = blocking(req, fd, true, flags & G_MSG_DONTWAIT, [&](Socket &s) {
                const char *p = reinterpret_cast<const char *>(data);
                return has_to ? int(sendto(s.host, p, int(len), host_flags, reinterpret_cast<sockaddr *>(&to), sizeof to))
                              : int(send(s.host, p, int(len), host_flags));
            });
            reply_ret(req, ret);
            break;
        }

        case 0x000B: { // Close(fd, process)
            int32_t fd = int32_t(req.arg(0));
            Socket *s = find(fd);
            if (!s) return reply_ret(req, -G_EBADF);
            net::close_socket(s->host);
            sockets.erase(fd);
            reply_ret(req, 0);
            break;
        }

        case 0x000C: { // Shutdown(fd, how, process)
            Socket *s = find(int32_t(req.arg(0)));
            if (!s) return reply_ret(req, -G_EBADF);
            reply_ret(req, shutdown(s->host, int(req.arg(1))) == 0 ? 0 : -guest_errno(last_error()));
            break;
        }

        case 0x000D: { // GetHostByName(name length, output size, static buffer 0: name) -> static buffer 0: hostent
            std::string name(reinterpret_cast<const char *>(mem::ptr(tr(req, 1))), req.arg(0));
            name = name.c_str();
            std::string host = rewrite_host(name);
            // the 3DS's: type, length, address count, alias count, name[256], aliases[24][256], addresses[24][16]
            std::vector<uint8_t> out(0x1A88, 0);
            addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            int32_t ret = 0;
            if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
                ret = -1; // HOST_NOT_FOUND-style failure
                LOG("soc: %s didn't resolve", host.c_str());
            } else {
                uint16_t count = 0;
                for (addrinfo *a = res; a && count < 24; a = a->ai_next, count++) {
                    auto *in = reinterpret_cast<sockaddr_in *>(a->ai_addr);
                    std::memcpy(&out[0x1888 + count * 16], &in->sin_addr.s_addr, 4);
                }
                uint16_t head[4] = {uint16_t(G_AF_INET), 4, count, 0};
                std::memcpy(out.data(), head, sizeof head);
                std::strncpy(reinterpret_cast<char *>(&out[8]), name.c_str(), 255);
                freeaddrinfo(res);
                LOG("soc: %s -> %u address(es)%s", name.c_str(), count, host != name ? (" via " + host).c_str() : "");
            }
            auto r = req.reply(2, 2);
            r.push(uint32_t(ret));
            req.push_static_buffer_clamped(r, 0, out.data(), std::min<uint32_t>(uint32_t(out.size()), req.arg(1)));
            break;
        }

        case 0x000F: { // GetAddrInfo(node length, service length, hints length, output size; static buffers: node, service, hints)
            uint32_t node_len = req.arg(0), svc_len = req.arg(1), hints_len = req.arg(2), out_size = req.arg(3);
            std::string node = node_len ? reinterpret_cast<const char *>(mem::ptr(tr(req, 1))) : "";
            std::string svc = svc_len ? reinterpret_cast<const char *>(mem::ptr(tr(req, 3))) : "";
            addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            if (hints_len >= 16) {
                const int32_t *h = reinterpret_cast<const int32_t *>(mem::ptr(tr(req, 5)));
                hints.ai_socktype = h[2] == G_SOCK_STREAM ? SOCK_STREAM : h[2] == G_SOCK_DGRAM ? SOCK_DGRAM : 0;
                hints.ai_protocol = h[3];
            }
            std::string host = rewrite_host(node);
            int32_t ret = getaddrinfo(host.empty() ? nullptr : host.c_str(), svc.empty() ? nullptr : svc.c_str(), &hints, &res);
            // each entry: flags, family, socktype, protocol, address length, canonical name[256], address[0x1C]
            constexpr uint32_t ENTRY = 0x130;
            std::vector<uint8_t> out;
            uint32_t count = 0;
            if (ret == 0) {
                for (addrinfo *a = res; a && (count + 1) * ENTRY <= out_size; a = a->ai_next, count++) {
                    std::vector<uint8_t> e(ENTRY, 0);
                    int32_t head[5] = {0, G_AF_INET, a->ai_socktype == SOCK_STREAM ? G_SOCK_STREAM : G_SOCK_DGRAM,
                                       a->ai_protocol, 8};
                    std::memcpy(e.data(), head, sizeof head);
                    if (a->ai_canonname) std::strncpy(reinterpret_cast<char *>(&e[0x14]), a->ai_canonname, 255);
                    auto addr = to_guest(*reinterpret_cast<sockaddr_in *>(a->ai_addr), 0x1C);
                    std::memcpy(&e[0x114], addr.data(), addr.size());
                    out.insert(out.end(), e.begin(), e.end());
                }
                freeaddrinfo(res);
            } else {
                ret = -1;
            }
            LOG("soc: getaddrinfo %s%s -> %u", node.c_str(), host != node ? (" via " + host).c_str() : "", count);
            auto r = req.reply(3, 2);
            r.push(uint32_t(ret));
            r.push(count);
            req.push_static_buffer_clamped(r, 0, out.data(), uint32_t(out.size()));
            break;
        }

        case 0x0011: { // GetSockOpt(fd, level, option, length, process) -> length, static buffer 0
            Socket *s = find(int32_t(req.arg(0)));
            int level = int(req.arg(1)), opt = int(req.arg(2));
            uint32_t len = req.arg(3);
            int32_t value = 0, ret = 0;
            if (!s) ret = -G_EBADF;
            else if (level == G_SOL_SOCKET && opt == 0x1008) value = s->type; // SO_TYPE
            else if (level == G_SOL_SOCKET && (opt == 0x1009 || opt == 0x1001 || opt == 0x1002)) {
                int host_opt = opt == 0x1009 ? SO_ERROR : opt == 0x1001 ? SO_SNDBUF : SO_RCVBUF;
                socklen_t l = sizeof value;
                if (getsockopt(s->host, SOL_SOCKET, host_opt, reinterpret_cast<char *>(&value), &l) != 0)
                    ret = -guest_errno(last_error());
                else if (opt == 0x1009 && value) value = guest_errno(value);
            } else {
                LOG("soc: getsockopt level %#x option %#x", level, opt);
            }
            auto r = req.reply(3, 2);
            r.push(uint32_t(ret));
            r.push(std::min<uint32_t>(len, 4));
            req.push_static_buffer_clamped(r, 0, &value, std::min<uint32_t>(len, 4));
            break;
        }

        case 0x0012: { // SetSockOpt(fd, level, option, length, process, static buffer 0: value)
            Socket *s = find(int32_t(req.arg(0)));
            int level = int(req.arg(1)), opt = int(req.arg(2));
            uint32_t len = req.arg(3);
            if (!s) return reply_ret(req, -G_EBADF);
            int32_t value = 0;
            std::memcpy(&value, mem::ptr(tr(req, 3)), std::min<uint32_t>(len, 4));
            int host_level = -1, host_opt = -1;
            if (level == G_SOL_SOCKET) {
                host_level = SOL_SOCKET;
                switch (opt) {
                case 0x0004: host_opt = SO_REUSEADDR; break;
                case 0x0008: host_opt = SO_KEEPALIVE; break;
                case 0x0020: host_opt = SO_BROADCAST; break;
                case 0x1001: host_opt = SO_SNDBUF; break;
                case 0x1002: host_opt = SO_RCVBUF; break;
                }
            } else if (level == 6 && opt == 0x2001) { // IPPROTO_TCP, TCP_NODELAY
                host_level = IPPROTO_TCP, host_opt = TCP_NODELAY;
            } else if (level == 0 && (opt == 7 || opt == 8)) { // IPPROTO_IP, IP_TOS / IP_TTL
                host_level = IPPROTO_IP, host_opt = opt == 7 ? IP_TOS : IP_TTL;
            }
            int32_t ret = 0;
            if (host_opt < 0) LOG("soc: setsockopt level %#x option %#x = %d (ignored)", level, opt, value);
            else if (setsockopt(s->host, host_level, host_opt, reinterpret_cast<const char *>(&value), sizeof value) != 0)
                ret = -guest_errno(last_error());
            reply_ret(req, ret);
            break;
        }

        case 0x0013: { // Fcntl(fd, command, argument, process)
            Socket *s = find(int32_t(req.arg(0)));
            int cmd = int(req.arg(1)), arg = int(req.arg(2));
            if (!s) return reply_ret(req, -G_EBADF);
            if (cmd == G_F_GETFL) reply_ret(req, s->nonblocking ? G_O_NONBLOCK : 0);
            else if (cmd == G_F_SETFL) s->nonblocking = arg & G_O_NONBLOCK, reply_ret(req, 0);
            else reply_ret(req, -G_EINVAL);
            break;
        }

        case 0x0014: { // Poll(count, timeout ms, process, static buffer 0: fds) -> ready count, static buffer 0
            uint32_t n = std::min<uint32_t>(req.arg(0), 64);
            int32_t timeout = int32_t(req.arg(1));
            struct GPoll {
                int32_t fd;
                int16_t events, revents;
            };
            std::vector<GPoll> fds(n);
            std::memcpy(fds.data(), mem::ptr(tr(req, 3)), n * sizeof(GPoll));
            auto start = Clock::now();
            int32_t ready = 0;
            for (;;) {
                ready = 0;
                for (auto &p : fds) {
                    p.revents = 0;
                    Socket *s = find(p.fd);
                    if (!s) {
                        p.revents = G_POLLNVAL;
                        ready++;
                        continue;
                    }
#if defined(_WIN32)
                    WSAPOLLFD h{s->host, 0, 0};
                    if (p.events & (G_POLLIN | G_POLLPRI)) h.events |= POLLRDNORM;
                    if (p.events & G_POLLOUT) h.events |= POLLWRNORM;
                    WSAPoll(&h, 1, 0);
                    short re = h.revents;
                    if (re & (POLLRDNORM | POLLRDBAND)) p.revents |= G_POLLIN;
                    if (re & POLLWRNORM) p.revents |= G_POLLOUT;
#else
                    pollfd h{s->host, 0, 0};
                    if (p.events & G_POLLIN) h.events |= POLLIN;
                    if (p.events & G_POLLPRI) h.events |= POLLPRI;
                    if (p.events & G_POLLOUT) h.events |= POLLOUT;
                    ::poll(&h, 1, 0);
                    short re = h.revents;
                    if (re & POLLIN) p.revents |= G_POLLIN;
                    if (re & POLLPRI) p.revents |= G_POLLPRI;
                    if (re & POLLOUT) p.revents |= G_POLLOUT;
#endif
                    if (re & POLLERR) p.revents |= G_POLLERR;
                    if (re & POLLHUP) p.revents |= G_POLLHUP;
                    if (p.revents) ready++;
                }
                int waited = int(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count());
                if (ready || timeout == 0 || (timeout > 0 && waited >= timeout)) break;
                kernel::Thread *self = kernel::current_thread();
                kernel::release_cpu();
                req.lock->unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(timeout > 0 ? std::min(5, timeout - waited) : 5));
                req.lock->lock();
                kernel::reacquire_cpu(*req.lock, self);
            }
            auto r = req.reply(2, 2);
            r.push(uint32_t(ready));
            req.push_static_buffer_clamped(r, 0, fds.data(), uint32_t(n * sizeof(GPoll)));
            break;
        }

        case 0x0016: { // GetHostId -> this console's IP address
            auto r = req.reply(2, 0);
            r.push(local_address());
            break;
        }

        case 0x0017:   // GetSockName(fd, max address length, process) -> static buffer 0
        case 0x0018: { // GetPeerName(same)
            Socket *s = find(int32_t(req.arg(0)));
            sockaddr_in a{};
            int32_t ret = -G_EBADF;
            if (s) {
                socklen_t len = sizeof a;
                int ok = req.id() == 0x0017 ? getsockname(s->host, reinterpret_cast<sockaddr *>(&a), &len)
                                            : getpeername(s->host, reinterpret_cast<sockaddr *>(&a), &len);
                ret = ok == 0 ? 0 : -guest_errno(last_error());
                // a socket bound to every interface reports this PC's address, as the 3DS would its own
                if (ok == 0 && req.id() == 0x0017 && a.sin_addr.s_addr == 0) a.sin_addr.s_addr = local_address();
            }
            auto addr = ret == 0 ? to_guest(a, req.arg(1)) : std::vector<uint8_t>();
            auto r = req.reply(2, 2);
            r.push(uint32_t(ret));
            req.push_static_buffer_clamped(r, 0, addr.data(), uint32_t(addr.size()));
            break;
        }

        case 0x0019: // ShutdownSockets
            for (auto &[fd, s] : sockets) net::close_socket(s.host);
            sockets.clear();
            req.reply(1, 0);
            break;

        case 0x001A: { // GetNetworkOpt(level, option, length) -> length, static buffer 0
            uint32_t opt = req.arg(1), len = req.arg(2);
            std::vector<uint8_t> out;
            if (opt == 0x1004) { // MAC address: a Nintendo one, from this console's id
                uint64_t id = platform::console_id();
                out = {0x40, 0xF4, 0x07, uint8_t(id >> 16), uint8_t(id >> 8), uint8_t(id)};
            } else if (opt == 0x4003) { // IP address, netmask, broadcast
                uint32_t ip = local_address(), mask = htonl(0xFFFFFF00), bc = ip | ~mask;
                out.resize(12);
                std::memcpy(&out[0], &ip, 4), std::memcpy(&out[4], &mask, 4), std::memcpy(&out[8], &bc, 4);
            } else if (opt == 0x4004) { // MTU
                uint32_t mtu = 1400;
                out.resize(4), std::memcpy(out.data(), &mtu, 4);
            } else {
                LOG("soc: GetNetworkOpt level %#x option %#x", req.arg(0), opt);
            }
            if (out.size() > len) out.resize(len);
            auto r = req.reply(3, 2);
            r.push(out.empty() ? uint32_t(-G_EINVAL) : 0);
            r.push(uint32_t(out.size()));
            req.push_static_buffer_clamped(r, 0, out.data(), uint32_t(out.size()));
            break;
        }

        case 0x0021: // CloseSockets(process)
        case 0x0023: // AddGlobalSocket
            req.reply(1, 0);
            break;

        default:
            LOG("soc: command %#06x (header %08x) not handled", req.id(), req.header());
            req.reply(1, 0, ERR_UNAVAILABLE);
        }
    }
};

} // namespace

void register_soc() { register_service({"soc:U", "soc:P"}, std::make_shared<Soc>()); }

} // namespace hle
