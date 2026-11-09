#pragma once
// Keeps a packaged Clockwork up to date from its GitHub releases: the nightly pre-release (rebuilt
// after every change to master) or the latest version. It checks in the background, downloads the
// package for this OS next to the program, swaps the files in (the ones replaced are kept as
// <name>.old until the next start, as Windows can't delete a running program) and starts again.
// Builds from source have no build name (CLOCKWORK_BUILD) and never update.
#include <string>

namespace updater {

// "v0.6.0", "nightly-<commit>", or empty for a build from source
const char *build();
// a short form for the launcher: "v0.6.0", "nightly 1a2b3c4", "built from source"
std::string build_label();
// whether this build can update itself (a packaged build, for an OS with a package)
bool enabled();
// whether this build came from the nightly pre-release, so follows it unless told otherwise
bool built_nightly();

enum class State { IDLE, CHECKING, UP_TO_DATE, AVAILABLE, DOWNLOADING, READY, FAILED };
struct Status {
    State state = State::IDLE;
    std::string latest; // what's available ("v0.6.0", "nightly 1a2b3c4")
    std::string error;  // why the last check or update failed
    float progress = 0; // downloading: 0 to 1
    bool install_failed = false; // FAILED while updating (not while checking)
};
Status status();

// looks for a newer build in the background: the nightly pre-release, or the latest version
void check(bool nightly);
// downloads and swaps in what check() found, in the background; READY when it's done
void install();
// starts the updated launcher in place of this process (returns only if it couldn't)
void restart();
// removes what the last update left behind (the .old files, an unfinished download)
void cleanup();

} // namespace updater
