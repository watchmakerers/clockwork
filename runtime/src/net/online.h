#pragma once
// Nintendo Network play through a Pretendo-style server (Youmakai Network): who this player is
// there, and the NASC login that hands a game its NEX server and token.
//
// The game's own NEX and PIA code does everything after the login, over real sockets (hle/soc.cpp),
// so a game here plays with the same game on a 3DS or an emulator connected to that server.
//
// A Clockwork player has no console certificate, so it uses a Clockwork account: registered once on
// the server with its register key (POST <server>/clockwork/register), and logging in with a secret
// instead of a console's uidhmac. Those accounts only reach the games the server hosts itself.
#include <cstdint>
#include <string>

namespace online {

// Youmakai Network, the official server: what a player gets without typing anything. Its register key
// is public on purpose: on the server it only makes new Clockwork accounts (CLOCKWORK_KEY, capped per
// IP and per day), apart from the private key that registers consoles.
inline constexpr const char *OFFICIAL_SERVER = "https://youmakai.duckdns.org:8443";
inline constexpr const char *OFFICIAL_SERVER_KEY = "sha256//zq3ZRGrDOIKNxt5kP24HeHPoXN2ke0ukT0kvKH7XEt8=";
inline constexpr const char *OFFICIAL_REGISTER_KEY = "92caa45b92231bb6cbeb9c1f0b9cb1c3";

// the settings name the official server (address and key)
bool is_official(const std::string &server, const std::string &server_key);

struct Account {
    std::string server;     // the server it belongs to, "https://host[:port]"
    std::string server_key; // that server's key when it was made ("sha256//..."; empty: CA-verified)
    uint32_t pid = 0;     // principal id
    std::string password; // NEX password (the game logs into its NEX server with it)
    std::string secret;   // proves to the server's NASC front that this is the account's owner
    std::string friend_code;
    bool valid() const { return pid && !password.empty() && !secret.empty(); }
};

// the saved account (online-account.ini in the data folder); empty if none
Account load_account();
void save_account(const Account &a);
void forget_account();

// online play is on (settings), the running game supports it (Yo-kai Watch 3 for now) and there's
// an account for the chosen server
bool enabled();
const Account &account(); // the one games use (loaded once per process)

// Registers a new account on `server` (verified by `server_key`, or by a trusted authority when it's
// empty) with its register key; saves it. Blocking (the launcher runs it on its own thread). On
// failure, `error` says why.
bool register_account(const std::string &server, const std::string &server_key, const std::string &key, Account &out,
                      std::string &error);

// What the 3DS friends service hands a game after RequestGameAuthentication (frd:u 0x29): the NEX
// server to connect to and a token for it, or the NASC return code that refused it.
struct GameAuth {
    int32_t result = 0;      // NASC returncd: 1 is success
    int32_t http_status = 0; // 200 when the server answered
    std::string host;        // NEX authentication server, "a.b.c.d"
    uint16_t port = 0;
    std::string token;
    uint64_t server_time = 0; // seconds since 2000-01-01
};

// The NASC LOGIN for `game_server_id` (the game's NEX id, like 0x00191000) from title
// `title_id`. Blocking.
GameAuth login(uint32_t game_server_id, uint64_t title_id, uint32_t sdk_major, uint32_t sdk_minor);

// the friend code of a principal id, as a 3DS shows it (the 64-bit "friend key" value too)
uint64_t friend_code_of(uint32_t pid);

} // namespace online
