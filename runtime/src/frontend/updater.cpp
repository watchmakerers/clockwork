#include "updater.h"

#include "gamebanana.h" // fetch_archive
#include "handoff.h"    // clockwork_binary
#include "json.h"
#include "log.h"

#include <SDL3/SDL.h>
#include <curl/curl.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#ifndef CLOCKWORK_BUILD
#define CLOCKWORK_BUILD ""
#endif

namespace fs = std::filesystem;

namespace updater {
namespace {

const char *const REPO = "watchmakerers/clockwork";
const char *const NIGHTLY_PREFIX = "nightly-";

// the package tools/package.sh makes for this OS (the release workflow's matrix)
const char *asset_name() {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    return "clockwork-windows-x86_64.zip";
#elif defined(__APPLE__) && defined(__aarch64__)
    return "clockwork-macos-arm64.tar.gz";
#elif defined(__linux__) && defined(__x86_64__)
    return "clockwork-linux-x86_64.tar.gz";
#else
    return nullptr;
#endif
}

std::mutex lock;
Status current;           // (lock)
std::string download_url; // the package check() found (lock)
std::atomic<float> progress{0};
std::atomic<bool> busy{false};

void set(State s, std::string latest = "", std::string error = "") {
    std::lock_guard lk(lock);
    current.install_failed = s == State::FAILED && current.state == State::DOWNLOADING;
    current.state = s;
    if (!latest.empty()) current.latest = std::move(latest);
    current.error = std::move(error);
}

// the folder this program is in
fs::path install_dir() {
    const char *base = SDL_GetBasePath();
    return fs::path(base ? base : "");
}

bool get_json(const std::string &url, json::Value &out, std::string &error) {
    static std::once_flag once;
    std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
    CURL *c = curl_easy_init();
    if (!c) return error = "Couldn't start the check.", false;
    std::string body;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(c, CURLOPT_USERAGENT, "Clockwork updater");
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, +[](char *p, size_t s, size_t n, void *u) {
        static_cast<std::string *>(u)->append(p, s * n);
        return s * n;
    });
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    struct curl_slist *headers = curl_slist_append(nullptr, "Accept: application/vnd.github+json");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    CURLcode r = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    curl_slist_free_all(headers);
    if (r != CURLE_OK) return error = std::string("GitHub didn't answer: ") + curl_easy_strerror(r), false;
    // the nightly is missing for a moment while it's replaced
    if (code == 404) return error = "No build to update to right now (one may be on its way): try again later.", false;
    if (code != 200) return error = "GitHub answered " + std::to_string(code) + ": try again later.", false;
    out = json::parse(body);
    if (out.kind != json::Value::OBJECT) return error = "GitHub's answer wasn't readable.", false;
    return true;
}

std::string label(const std::string &build) {
    if (build.empty()) return "built from source";
    if (build.rfind(NIGHTLY_PREFIX, 0) == 0) return "nightly " + build.substr(std::strlen(NIGHTLY_PREFIX), 7);
    return build;
}

// moves `from` over `to`, keeping what was there as <to>.old; false (and `error`) if it can't
bool replace(const fs::path &from, const fs::path &to, std::vector<fs::path> &moved, std::string &error) {
    std::error_code ec;
    fs::create_directories(to.parent_path(), ec);
    fs::path old = to;
    old += ".old";
    bool existed = fs::exists(to, ec);
#ifndef _WIN32
    fs::perms perms = existed ? fs::status(to, ec).permissions()
                              : to.has_extension() ? fs::perms(0644) : fs::perms(0755); // programs have none
#endif
    if (existed) {
        fs::remove(old, ec);
        fs::rename(to, old, ec);
        if (ec) return error = "Couldn't move " + to.string() + " aside: " + ec.message(), false;
    }
    fs::rename(from, to, ec);
    if (ec) {
        if (existed) fs::rename(old, to, ec);
        return error = "Couldn't put the new " + to.filename().string() + " in place: " + ec.message(), false;
    }
#ifndef _WIN32
    fs::permissions(to, perms, ec); // unpacked files come without their exec bits
#endif
    moved.push_back(to);
    return true;
}

// undoes the replacements made so far (the update failed partway)
void roll_back(const std::vector<fs::path> &moved) {
    std::error_code ec;
    for (auto it = moved.rbegin(); it != moved.rend(); ++it) {
        fs::path old = *it;
        old += ".old";
        fs::remove(*it, ec);
        if (fs::exists(old, ec)) fs::rename(old, *it, ec);
    }
}

void run_install(std::string url) {
    fs::path root = install_dir(), staging = root / ".update";
    std::string error;
    progress = 0;
    { // the files are swapped in this folder: it has to be writable (not, say, Program Files)
        fs::path probe = root / ".update-probe";
        bool writable = std::ofstream(probe).good();
        std::error_code ec;
        fs::remove(probe, ec);
        if (!writable)
            return set(State::FAILED, "", "Can't write to " + root.string() +
                                              ": move Clockwork to a folder of your own to update it.");
    }
    // unpacked next to the program, so the files move in by renaming (same drive)
    if (!gamebanana::fetch_archive(url, staging, progress, error)) {
        std::error_code ec;
        fs::remove_all(staging, ec);
        return set(State::FAILED, "", error);
    }
    // the package's files are in one folder (clockwork-<os>)
    fs::path from = staging;
    std::error_code ec;
    std::vector<fs::path> entries;
    for (auto &e : fs::directory_iterator(staging, ec)) entries.push_back(e.path());
    if (entries.size() == 1 && fs::is_directory(entries[0], ec)) from = entries[0];
    if (!fs::is_regular_file(from / fs::path(std::string(clockwork_binary) +
#ifdef _WIN32
                                             ".exe"
#else
                                             ""
#endif
                                             ),
                             ec)) {
        fs::remove_all(staging, ec);
        return set(State::FAILED, "", "The download doesn't have Clockwork in it.");
    }
    std::vector<fs::path> files, moved;
    for (auto it = fs::recursive_directory_iterator(from, ec); !ec && it != fs::recursive_directory_iterator();
         it.increment(ec))
        if (it->is_regular_file(ec)) files.push_back(it->path());
    for (const fs::path &f : files)
        if (!replace(f, root / fs::relative(f, from, ec), moved, error)) {
            roll_back(moved);
            fs::remove_all(staging, ec);
            return set(State::FAILED, "", error);
        }
    fs::remove_all(staging, ec);
    LOG("updater: updated %zu files in %s", moved.size(), root.string().c_str());
    progress = 1;
    set(State::READY);
}

} // namespace

const char *build() { return CLOCKWORK_BUILD; }

std::string build_label() { return label(build()); }

bool enabled() { return build()[0] != 0 && asset_name() != nullptr; }

bool built_nightly() { return std::string(build()).rfind(NIGHTLY_PREFIX, 0) == 0; }

Status status() {
    std::lock_guard lk(lock);
    Status s = current;
    s.progress = progress;
    return s;
}

void check(bool nightly) {
    if (!enabled() || busy.exchange(true)) return;
    set(State::CHECKING);
    std::thread([nightly] {
        std::string url = std::string("https://api.github.com/repos/") + REPO +
                          (nightly ? "/releases/tags/nightly" : "/releases/latest");
        json::Value r;
        std::string error;
        if (!get_json(url, r, error)) {
            busy = false;
            return set(State::FAILED, "", error);
        }
        // the nightly release points at the commit it was built from
        std::string latest = nightly ? NIGHTLY_PREFIX + r["target_commitish"].string() : r["tag_name"].string();
        std::string package;
        for (const json::Value &a : r["assets"].arr)
            if (a["name"].string() == asset_name()) package = a["browser_download_url"].string();
        if (latest == NIGHTLY_PREFIX || latest.empty() || package.empty()) {
            busy = false;
            return set(State::FAILED, "", "The newest build isn't ready for this computer yet: try again later.");
        }
        {
            std::lock_guard lk(lock);
            download_url = package;
        }
        LOG("updater: this is %s, the newest is %s", build(), latest.c_str());
        busy = false;
        set(latest == build() ? State::UP_TO_DATE : State::AVAILABLE, label(latest));
    }).detach();
}

void install() {
    std::string url;
    {
        std::lock_guard lk(lock);
        if (current.state != State::AVAILABLE) return;
        url = download_url;
    }
    if (busy.exchange(true)) return;
    set(State::DOWNLOADING);
    std::thread([url] {
        run_install(url);
        busy = false;
    }).detach();
}

void restart() {
    std::string exe = (install_dir() / clockwork_binary).string();
#ifdef _WIN32
    exe += ".exe";
    std::string q_exe = "\"" + exe + "\"";
    const char *argv[] = {q_exe.c_str(), "--launcher", nullptr};
    LOG("updater: starting %s", exe.c_str());
    std::fflush(nullptr);
    _execv(exe.c_str(), argv);
#else
    const char *argv[] = {exe.c_str(), "--launcher", nullptr};
    LOG("updater: starting %s", exe.c_str());
    std::fflush(nullptr);
    execv(exe.c_str(), const_cast<char *const *>(argv));
#endif
    LOG("updater: could not start %s", exe.c_str());
}

void cleanup() {
    if (!enabled()) return; // a build folder from source: never touched
    fs::path root = install_dir();
    std::error_code ec;
    fs::remove_all(root / ".update", ec);
    fs::remove_all(root / ".update.download", ec);
    std::vector<fs::path> old;
    for (auto it = fs::recursive_directory_iterator(root, ec); !ec && it != fs::recursive_directory_iterator();
         it.increment(ec))
        if (it->is_regular_file(ec) && it->path().extension() == ".old") old.push_back(it->path());
    for (const fs::path &p : old) fs::remove(p, ec); // a program still closing stays until next time
}

} // namespace updater
