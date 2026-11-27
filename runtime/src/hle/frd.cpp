// frd:u: the friends service. Multiplayer menus ask it who you are before local play: a profile
// (the console's user name), no friends. While online play is on (net/online.h) it is also who the
// game is on the server: the account's principal id and NEX password, and the NASC login that
// gives the game its NEX server and token. Unknown commands are logged ("frd:") and succeed, so a
// menu carries on rather than the game stopping.
#include "service.h"

#include "dump.h"
#include "frontend/settings.h"
#include "log.h"
#include "memory.h"
#include "net/online.h"
#include "platform.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace hle {
namespace {

// the last translate word: the handle the game passed (an event)
uint32_t last_handle(const Request &req) {
    uint32_t translates = req.header() & 0x3F;
    return translates ? req.in[req.normal_count() + translates] : 0;
}

uint32_t my_pid() {
    if (online::enabled()) return online::account().pid;
    // a made-up principal id (there's no account), one per console: see platform::console_id
    return uint32_t(platform::console_id() * 0x9E3779B97F4A7C15ull >> 32) | 1;
}

struct Frd : Service {
    // the last RequestGameAuthentication's answer (GetGameAuthenticationData), kernel lock held
    online::GameAuth auth;
    bool auth_done = false;

    Frd() : Service("frd:u") {}

    void log_call(const Request &req, const char *what) {
        std::string args;
        for (uint32_t i = 0; i < std::min<uint32_t>(req.normal_count(), 6); i++) {
            char buf[12];
            std::snprintf(buf, sizeof buf, " %08x", req.arg(int(i)));
            args += buf;
        }
        LOG("frd: %s (%#06x)%s", what, req.id(), args.c_str());
    }

    void handle(Request &req) override {
        switch (req.id()) {
        case 0x0032: // SetClientSdkVersion(version, process)
            req.reply(1, 0);
            break;
        case 0x0001:   // HasLoggedIn
        case 0x0002: { // IsOnline
            auto r = req.reply(2, 0);
            r.push(online::enabled() ? 1 : 0);
            break;
        }
        case 0x0003: { // Login(event): logged in at once while online; the event says it's done
            log_call(req, "Login");
            if (auto e = kernel::get<kernel::Event>(last_handle(req))) e->signal();
            req.reply(1, 0, online::enabled() ? kernel::RESULT_OK : 0xC8A0C4A2);
            break;
        }
        case 0x0004: // Logout
            req.reply(1, 0);
            break;
        case 0x0005: { // GetMyFriendKey -> principal id, padding, friend code
            uint32_t pid = my_pid();
            auto r = req.reply(5, 0);
            r.push(pid);
            r.push(0);
            r.push64(online::enabled() ? online::friend_code_of(pid) : 0);
            break;
        }
        case 0x0010: { // GetMyPassword(size) -> static buffer 0: the NEX password
            std::string pw = online::enabled() ? online::account().password : "";
            std::vector<char> out(std::min({req.arg(0), req.static_buffer_size(0), 0x100u}), 0);
            if (!out.empty()) std::strncpy(out.data(), pw.c_str(), out.size() - 1);
            auto r = req.reply(1, 2);
            req.push_static_buffer(r, 0, out.data(), uint32_t(out.size()));
            break;
        }
        case 0x0023: // GetLastResponseResult
            req.reply(1, 0);
            break;
        case 0x0022: { // GetEventNotification(max count) -> count, static buffer 0: none (friends never change here)
            auto r = req.reply(3, 2);
            r.push(0);
            r.push(0);
            req.push_static_buffer(r, 0, nullptr, 0);
            break;
        }
        case 0x0027: { // ResultToErrorCode(result) -> the code a 3DS shows the player
            log_call(req, "ResultToErrorCode");
            auto r = req.reply(2, 0);
            r.push(0);
            break;
        }
        case 0x0030: { // GetServerTypes -> NASC environment (0: production), server types 1 and 2
            auto r = req.reply(4, 0);
            r.push(0);
            r.push(1);
            r.push(1);
            break;
        }
        case 0x0024: { // PrincipalIdToFriendCode(pid) -> friend code
            auto r = req.reply(3, 0);
            r.push64(online::friend_code_of(req.arg(0)));
            break;
        }
        case 0x0025: { // FriendCodeToPrincipalId(friend code) -> pid
            auto r = req.reply(2, 0);
            r.push(req.arg(0));
            break;
        }
        case 0x0026: { // IsValidFriendCode(friend code)
            uint64_t fc = uint64_t(req.arg(1)) << 32 | req.arg(0);
            auto r = req.reply(2, 0);
            r.push(fc && online::friend_code_of(uint32_t(fc)) == fc ? 1 : 0);
            break;
        }
        case 0x0028: { // RequestGameAuthentication(game server id, screen name[6], sdk major, sdk minor, process, event)
            uint32_t game = req.arg(0), sdk_major = req.arg(7), sdk_minor = req.arg(8);
            auto event = kernel::get<kernel::Event>(last_handle(req));
            LOG("frd: RequestGameAuthentication for game server %08x (sdk %u.%u)", game, sdk_major, sdk_minor);
            auth = {};
            auth_done = false;
            uint64_t title = dump().program_id();
            auto self = std::static_pointer_cast<Frd>(shared_from_this());
            // the login is an HTTPS request: done on its own thread, and the game's event signaled after
            std::thread([self, event, game, title, sdk_major, sdk_minor] {
                online::GameAuth a = online::login(game, title, sdk_major, sdk_minor);
                std::lock_guard<std::mutex> g(kernel::k().lock);
                self->auth = a;
                self->auth_done = true;
                if (event) event->signal();
            }).detach();
            req.reply(1, 0, online::enabled() ? kernel::RESULT_OK : 0xC8A0C4A2);
            break;
        }
        case 0x0029: { // GetGameAuthenticationData -> static buffer 0: the answer
            // result, HTTP status, server address[32], port, padding, unused, token[256], server time.
            // Only as much as the game's receive buffer holds is written (its size is logged once, to check)
            uint8_t out[0x138] = {};
            uint32_t room = mem::read32(req.ctx->tls + 0x180) >> 14;
            LOG("frd: GetGameAuthenticationData into a %#x-byte buffer: result %d, HTTP %d", room, auth.result,
                auth.http_status);
            int32_t head[2] = {auth.result, auth.http_status};
            std::memcpy(out, head, 8);
            std::strncpy(reinterpret_cast<char *>(out + 0x08), auth.host.c_str(), 0x1F);
            std::memcpy(out + 0x28, &auth.port, 2);
            std::strncpy(reinterpret_cast<char *>(out + 0x30), auth.token.c_str(), 0xFF);
            std::memcpy(out + 0x128, &auth.server_time, 8);
            auto r = req.reply(1, 2, auth_done ? kernel::RESULT_OK : 0xC8A0C4A2);
            req.push_static_buffer(r, 0, out, std::min<uint32_t>(room, sizeof out));
            break;
        }
        case 0x0006: { // GetMyProfile -> region, country, area, language, platform (8 bytes)
            auto r = req.reply(3, 0);
            const ConsoleIdentity &id = console_identity();
            r.push(uint32_t(id.region) | uint32_t(id.country) << 8 | uint32_t(id.language) << 24);
            r.push(0x00000001);
            break;
        }
        case 0x0009: { // GetMyScreenName -> 11 UTF-16 units
            auto r = req.reply(7, 0);
            const std::string &setting = frontend::settings().player_name;
            const char *name = setting.empty() ? "Player" : setting.c_str();
            uint16_t units[12] = {};
            for (size_t i = 0; name[i] && i < 10; i++) units[i] = uint16_t(name[i]);
            for (int i = 0; i < 6; i++) r.push(uint32_t(units[i * 2]) | uint32_t(units[i * 2 + 1]) << 16);
            break;
        }
        case 0x0011: { // GetFriendKeyList(offset, max) -> count, static buffer: none
            auto r = req.reply(2, 2);
            r.push(0);
            req.push_static_buffer(r, 0, nullptr, 0);
            break;
        }
        default:
            log_call(req, "command");
            req.reply(1, 0);
        }
    }
};

} // namespace

void register_frd() { register_service({"frd:u", "frd:a"}, std::make_shared<Frd>()); }

} // namespace hle
