#pragma once

#include "core/secure_runtime.h"

#ifndef WINSECRUNTIME_HEADER_ONLY
#define WINSECRUNTIME_HEADER_ONLY 1
#endif

#if defined(_WIN32) && !WINSECRUNTIME_HEADER_ONLY
#  ifdef WINSECRUNTIME_BUILD_SHARED
#    ifdef WINSECRUNTIME_EXPORTS
#      define WINSECRUNTIME_API __declspec(dllexport)
#    else
#      define WINSECRUNTIME_API
#    endif
#  else
#    define WINSECRUNTIME_API
#  endif
#else
#  define WINSECRUNTIME_API
#endif

namespace WinSecRuntime {

enum class Mode : uint32_t {
    Minimal = 0,
    Moderate,
    Aggressive,
    Paranoid
};

struct Policy {
    Mode mode = Mode::Moderate;
    secure::runtime::Config cfg{};
};

#if WINSECRUNTIME_HEADER_ONLY
inline bool Initialize(Mode mode, const secure::runtime::Config& cfg = {}) {
    (void)mode;
    (void)cfg;
    return true;
}

inline void StartIntegrityEngine(const Policy& p = {}) {
#if SECURE_ENABLE_HEARTBEAT
    static secure::runtime::Heartbeat hb(5000, nullptr, p.cfg);
    (void)hb;
#endif
}

inline secure::Report RunAll(const Policy& p = {}) {
    return secure::runtime::run_all_checks(p.cfg);
}

inline void EnableAntiDebug(const Policy& p = {}) {
    (void)RunAll(p);
}

inline void EnableHookGuard(const Policy& p = {}) {
    (void)RunAll(p);
}
#else
WINSECRUNTIME_API bool Initialize(Mode mode, const secure::runtime::Config& cfg = {});
WINSECRUNTIME_API void StartIntegrityEngine(const Policy& p = {});
WINSECRUNTIME_API secure::Report RunAll(const Policy& p = {});
WINSECRUNTIME_API void EnableAntiDebug(const Policy& p = {});
WINSECRUNTIME_API void EnableHookGuard(const Policy& p = {});
#endif

} // namespace WinSecRuntime
