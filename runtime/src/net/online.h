#pragma once
// Online play through Youmakai Network, the only online server Clockwork uses: who this player is
// there, and the NASC login that hands a game its NEX server and token.
//
// The game's own NEX and PIA code does everything after the login, over real sockets (hle/soc.cpp),
// so a game here plays with the same game on a 3DS connected to Youmakai Network.
//
// A Clockwork player has no console certificate, so it uses a Clockwork account: registered once on
// the server (POST <server>/clockwork/register), and logging in with a secret instead of a
// console's uidhmac. Those accounts only reach the games the server hosts itself.
#include <cstdint>
#include <string>

namespace online {

// The server, and the SHA-256 of its public key: nothing is sent to a server without that key. The
// register key is public on purpose: on the server it only makes new Clockwork accounts
// (CLOCKWORK_KEY, capped per IP and per day).
inline constexpr const char *SERVER_HOST = "youmakai.duckdns.org";
inline constexpr const char *SERVER = "https://youmakai.duckdns.org";
inline constexpr const char *SERVER_KEY = "sha256//BxKriwbv+tOG2EuAvdUjRfIqaDn6QJgNd5P8oRNQmTs=";
inline constexpr const char *REGISTER_KEY = "1cce58a6e1d3a70f8212b28b587a9f8d";

struct Account {
    std::string server;     // the server it belongs to, "https://host[:port]"
    std::string server_key; // that server's key when it was made ("sha256//...")
    uint32_t pid = 0;     // principal id
    std::string password; // NEX password (the game logs into its NEX server with it)
    std::string secret;   // proves to the server's NASC front that this is the account's owner
    std::string friend_code;
    bool valid() const { return pid && !password.empty() && !secret.empty(); }
    // made on the server as it is now, under its current key; any other account is not used
    bool usable() const { return valid() && server == SERVER && server_key == SERVER_KEY; }
};

// the saved account (online-account.ini in the data folder); empty if none
Account load_account();
void save_account(const Account &a);
void forget_account();

// online play is on (settings), the running game supports it (Yo-kai Watch 3, Busters 2) and there's
// a usable account
bool enabled();
const Account &account(); // the one games use (loaded once per process)

// Registers a new account and saves it. Blocking (the launcher runs it on its own thread). On
// failure, `error` says why.
bool register_account(Account &out, std::string &error);

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
