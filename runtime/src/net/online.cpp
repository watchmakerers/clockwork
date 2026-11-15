#include "online.h"

#include "frontend/json.h"
#include "frontend/settings.h"
#include "log.h"
#include "net/socket.h"
#include "platform.h"

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>

namespace online {
namespace {

std::filesystem::path account_file() { return platform::data_dir() / "online-account.ini"; }

// NASC's base64: '+' '/' '=' written as '.' '-' '*'
std::string nasc_b64(const std::string &in) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-";
    std::string out;
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        uint32_t v = uint8_t(in[i]) << 16 | uint8_t(in[i + 1]) << 8 | uint8_t(in[i + 2]);
        for (int s = 18; s >= 0; s -= 6) out += T[(v >> s) & 63];
    }
    if (size_t left = in.size() - i) {
        uint32_t v = uint8_t(in[i]) << 16 | (left > 1 ? uint8_t(in[i + 1]) << 8 : 0);
        out += T[(v >> 18) & 63], out += T[(v >> 12) & 63];
        out += left > 1 ? T[(v >> 6) & 63] : '*';
        out += '*';
    }
    return out;
}

std::string nasc_unb64(const std::string &in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '.' || c == '+') return 62;
        if (c == '-' || c == '/') return 63;
        return -1;
    };
    std::string out;
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        int v = val(c);
        if (v < 0) continue; // padding ('*' or '=') and anything else
        acc = acc << 6 | uint32_t(v), bits += 6;
        if (bits >= 8) bits -= 8, out += char((acc >> bits) & 0xFF);
    }
    return out;
}

std::string url_decode(const std::string &s) {
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size()) out += char(std::strtol(s.substr(i + 1, 2).c_str(), nullptr, 16)), i += 2;
        else out += s[i] == '+' ? ' ' : s[i];
    }
    return out;
}

// key=value&... -> the value for `key` (url-decoded), or ""
std::string form_field(const std::string &body, const std::string &key) {
    size_t at = 0;
    while (at <= body.size()) {
        size_t end = body.find('&', at);
        if (end == std::string::npos) end = body.size();
        std::string pair = body.substr(at, end - at);
        if (size_t eq = pair.find('='); eq != std::string::npos && pair.substr(0, eq) == key)
            return url_decode(pair.substr(eq + 1));
        at = end + 1;
    }
    return "";
}

std::string trim_slash(std::string s) {
    while (!s.empty() && s.back() == '/') s.pop_back();
    return s;
}

constexpr size_t MAX_REPLY = 64 * 1024; // more than any answer needs; a bigger one is refused

// a server key as the launcher shows it: "sha256//" and the base64 SHA-256 of the server's public key
bool valid_server_key(const std::string &key) {
    if (key.rfind("sha256//", 0) != 0 || key.size() != 8 + 44 || key.back() != '=') return false;
    for (size_t i = 8; i + 1 < key.size(); i++) {
        char c = key[i];
        if (!std::isalnum(uint8_t(c)) && c != '+' && c != '/') return false;
    }
    return true;
}

// A POST to the server, which is always verified, one of two ways:
// - with a server key (a self-hosted server's self-signed certificate): its public key must be that
//   one, whatever its certificate says
// - without: a certificate from a trusted authority, for that host name
// TLS 1.2 or newer, HTTPS only, no redirects, and answers over MAX_REPLY are cut off as failures.
bool post(const std::string &url, const std::string &server_key, const std::string &body, const char *content_type,
          long &status, std::string &out, std::string &error) {
    if (url.rfind("https://", 0) != 0) return error = "the server address must start with https://", false;
    if (!server_key.empty() && !valid_server_key(server_key))
        return error = "the server key isn't one (it looks like sha256//...=)", false;
    static std::once_flag once;
    std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
    CURL *c = curl_easy_init();
    if (!c) return error = "couldn't start a connection", false;
    curl_slist *headers = curl_slist_append(nullptr, (std::string("Content-Type: ") + content_type).c_str());
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(c, CURLOPT_SSLVERSION, long(CURL_SSLVERSION_TLSv1_2));
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, long(body.size()));
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "CTR FPD/000B"); // what the 3DS friends service sends
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L);
    if (!server_key.empty()) {
        // a self-signed certificate can't chain to an authority: the pinned key is what's trusted
        // (curl checks it on every connection, before anything is sent)
        curl_easy_setopt(c, CURLOPT_PINNEDPUBLICKEY, server_key.c_str());
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    }
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, +[](char *p, size_t s, size_t n, void *u) {
        auto *o = static_cast<std::string *>(u);
        if (o->size() + s * n > MAX_REPLY) return size_t(0); // stops the transfer
        o->append(p, s * n);
        return s * n;
    });
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &out);
    CURLcode r = curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(c);
    if (r == CURLE_SSL_PINNEDPUBKEYNOTMATCH)
        return error = "this isn't the server you set: its key doesn't match the server key", false;
    if (r == CURLE_PEER_FAILED_VERIFICATION || r == CURLE_SSL_CACERT_BADFILE)
        return error = "the server's certificate isn't trusted (a self-signed server needs its server key)", false;
    if (r != CURLE_OK) return error = std::string("the server didn't answer: ") + curl_easy_strerror(r), false;
    return true;
}

std::string escape(const std::string &s) {
    std::string out;
    for (unsigned char ch : s) {
        if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') out += char(ch);
        else {
            char buf[4];
            std::snprintf(buf, sizeof buf, "%%%02X", ch);
            out += buf;
        }
    }
    return out;
}

// SHA-1, for friend code checksums
void sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    std::string msg(reinterpret_cast<const char *>(data), len);
    msg += char(0x80);
    while (msg.size() % 64 != 56) msg += char(0);
    uint64_t bits = uint64_t(len) * 8;
    for (int i = 7; i >= 0; i--) msg += char(bits >> (i * 8));
    auto rol = [](uint32_t v, int n) { return v << n | v >> (32 - n); };
    for (size_t at = 0; at < msg.size(); at += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = uint32_t(uint8_t(msg[at + i * 4])) << 24 | uint32_t(uint8_t(msg[at + i * 4 + 1])) << 16 |
                   uint32_t(uint8_t(msg[at + i * 4 + 2])) << 8 | uint8_t(msg[at + i * 4 + 3]);
        for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) f = (b & c) | (~b & d), k = 0x5A827999;
            else if (i < 40) f = b ^ c ^ d, k = 0x6ED9EBA1;
            else if (i < 60) f = (b & c) | (b & d) | (c & d), k = 0x8F1BBCDC;
            else f = b ^ c ^ d, k = 0xCA62C1D6;
            uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d, d = c, c = rol(b, 30), b = a, a = t;
        }
        h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e;
    }
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 4; j++) out[i * 4 + j] = uint8_t(h[i] >> (24 - j * 8));
}

// "yyyymmddhhmmss" (UTC) -> seconds since 2000-01-01
uint64_t nasc_time(const std::string &s) {
    if (s.size() < 14) return 0;
    auto num = [&](size_t at, size_t n) { return std::atoi(s.substr(at, n).c_str()); };
    int y = num(0, 4), mo = num(4, 2), d = num(6, 2);
    // days from civil (Howard Hinnant)
    y -= mo <= 2;
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = unsigned(y - era * 400);
    unsigned doy = unsigned((153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1);
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = int64_t(era) * 146097 + int64_t(doe) - 719468; // since 1970-01-01
    int64_t unix_s = days * 86400 + num(8, 2) * 3600 + num(10, 2) * 60 + num(12, 2);
    return unix_s > 946684800 ? uint64_t(unix_s - 946684800) : 0;
}

} // namespace

uint64_t friend_code_of(uint32_t pid) {
    uint8_t le[4] = {uint8_t(pid), uint8_t(pid >> 8), uint8_t(pid >> 16), uint8_t(pid >> 24)}, h[20];
    sha1(le, 4, h);
    return uint64_t(h[0] >> 1) << 32 | pid;
}

Account load_account() {
    Account a;
    std::ifstream f(account_file());
    std::string line;
    while (std::getline(f, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        if (k == "server") a.server = v;
        else if (k == "pid") a.pid = uint32_t(std::strtoul(v.c_str(), nullptr, 10));
        else if (k == "password") a.password = v;
        else if (k == "secret") a.secret = v;
        else if (k == "friend_code") a.friend_code = v;
        else if (k == "server_key") a.server_key = v;
    }
    return a;
}

void save_account(const Account &a) {
    // it holds the account's password and secret: only this user may read it (made empty and
    // restricted before anything is written)
    std::filesystem::path path = account_file();
    { std::ofstream create(path, std::ios::trunc); }
    std::error_code ec;
    std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    std::ofstream f(path, std::ios::trunc);
    f << "server=" << a.server << "\nserver_key=" << a.server_key << "\npid=" << a.pid << "\npassword=" << a.password
      << "\nsecret=" << a.secret << "\nfriend_code=" << a.friend_code << "\n";
}

void forget_account() {
    std::error_code ec;
    std::filesystem::remove(account_file(), ec);
}

const Account &account() {
    static const Account a = load_account();
    return a;
}

bool enabled() {
    const auto &s = frontend::settings();
    const Account &a = account();
    // the account must be this server's, under the same key it was registered with
    return s.online && a.valid() && trim_slash(a.server) == trim_slash(s.online_server) &&
           a.server_key == s.online_server_key;
}

bool register_account(const std::string &server, const std::string &server_key, const std::string &key, Account &out,
                      std::string &error) {
    std::string base = trim_slash(server);
    long status = 0;
    std::string body;
    // the key goes in the body, never the address, so it stays out of server logs
    if (!post(base + "/clockwork/register", server_key, "key=" + escape(key), "application/x-www-form-urlencoded",
              status, body, error))
        return false;
    json::Value v = json::parse(body);
    if (status == 403) return error = "the server refused the register key", false;
    if (status == 429) return error = "too many tries; wait an hour and try again", false;
    if (status != 200) {
        std::string why = v["error"].string();
        return error = "the server answered " + std::to_string(status) + (why.empty() ? "" : ": " + why), false;
    }
    Account a;
    a.server = base;
    a.server_key = server_key;
    a.pid = uint32_t(v["pid"].integer());
    a.password = v["password"].string();
    a.secret = v["secret"].string();
    a.friend_code = v["friend_code"].string();
    if (!a.valid() || a.password.size() > 64 || a.secret.size() > 128 || a.friend_code.size() > 32)
        return error = "the server's answer isn't an account", false;
    save_account(a);
    out = a;
    LOG("online: registered pid %u on %s", a.pid, base.c_str());
    return true;
}

GameAuth login(uint32_t game_server_id, uint64_t title_id, uint32_t sdk_major, uint32_t sdk_minor) {
    GameAuth auth;
    const Account &a = account();
    if (!enabled()) return auth;

    char gameid[16], titleid[24], sdkver[16], devtime[16];
    std::snprintf(gameid, sizeof gameid, "%08X", game_server_id);
    std::snprintf(titleid, sizeof titleid, "%016llX", (unsigned long long)title_id);
    std::snprintf(sdkver, sizeof sdkver, "%03u%03u", sdk_major % 1000, sdk_minor % 1000);
    std::time_t now = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    std::strftime(devtime, sizeof devtime, "%y%m%d%H%M%S", &tm);

    // the fields a 3DS sends (those that make sense without a console), plus `clockwork`: the
    // account's secret, which the server's NASC front checks in place of a console certificate
    std::string body;
    auto field = [&](const char *k, const std::string &v) {
        if (!body.empty()) body += '&';
        body += k, body += '=', body += nasc_b64(v);
    };
    field("action", "LOGIN");
    field("gameid", gameid);
    field("sdkver", sdkver);
    field("titleid", titleid);
    field("unitcd", "2");
    field("servertype", "L1");
    field("fpdver", "000B");
    field("devtime", devtime);
    field("userid", std::to_string(a.pid));
    field("clockwork", a.secret);

    long status = 0;
    std::string reply, error;
    // sent only to the server key the account was made under (enabled() checked it's still the setting)
    if (!post(trim_slash(a.server) + "/ac", a.server_key, body, "application/x-www-form-urlencoded", status, reply,
              error)) {
        LOG("online: NASC login for %s failed: %s", gameid, error.c_str());
        return auth;
    }
    auth.http_status = int32_t(status);
    std::string returncd = nasc_unb64(form_field(reply, "returncd"));
    auth.result = std::atoi(returncd.c_str());
    std::string locator = nasc_unb64(form_field(reply, "locator"));
    if (size_t colon = locator.rfind(':'); colon != std::string::npos) {
        auth.host = locator.substr(0, colon);
        auth.port = uint16_t(std::atoi(locator.c_str() + colon + 1));
    }
    auth.token = form_field(reply, "token"); // passed on as the server sent it (still in NASC base64)
    auth.server_time = nasc_time(nasc_unb64(form_field(reply, "datetime")));
    // only a well-formed answer reaches the game: an IPv4 address, a port, a NASC base64 token
    in_addr ip{};
    bool token_ok = !auth.token.empty() && auth.token.size() <= 255 &&
                    std::all_of(auth.token.begin(), auth.token.end(), [](char ch) {
                        return std::isalnum(uint8_t(ch)) || ch == '.' || ch == '-' || ch == '*';
                    });
    if (auth.result == 1 && (inet_pton(AF_INET, auth.host.c_str(), &ip) != 1 || !auth.port || !token_ok)) {
        LOG("online: NASC answer for %s is malformed; refused", gameid);
        auth = {};
        auth.http_status = int32_t(status);
        return auth;
    }
    LOG("online: NASC login for %s (title %s): HTTP %ld, returncd %s, server %s:%u", gameid, titleid, status,
        returncd.empty() ? "none" : returncd.c_str(), auth.host.c_str(), auth.port);
    return auth;
}

} // namespace online
