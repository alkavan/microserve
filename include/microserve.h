// SPDX-FileCopyrightText: 2025-2026 Igal Alkon
// SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef MICROSERVE_H
#define MICROSERVE_H

// Keep in sync with project(VERSION ...) in CMakeLists.txt
#define MICROSERVE_VERSION_MAJOR 0
#define MICROSERVE_VERSION_MINOR 5
#define MICROSERVE_VERSION_PATCH 0

#define MICROSERVE_STR_HELPER(x) #x
#define MICROSERVE_STR(x) MICROSERVE_STR_HELPER(x)
#define MICROSERVE_VERSION MICROSERVE_STR(MICROSERVE_VERSION_MAJOR) "." \
    MICROSERVE_STR(MICROSERVE_VERSION_MINOR) "." MICROSERVE_STR(MICROSERVE_VERSION_PATCH)

// Shared-library export. The public target is static today, so this stays empty
// unless MICROSERVE_BUILD_SHARED is set when building a DLL.
#ifdef _WIN32
    #ifdef MICROSERVE_BUILD_SHARED
        #define MICROSERVE_API __declspec(dllexport)
    #elif defined(MICROSERVE_SHARED)
        #define MICROSERVE_API __declspec(dllimport)
    #else
        #define MICROSERVE_API
    #endif
#else
    #if defined(MICROSERVE_BUILD_SHARED) && defined(__GNUC__) && __GNUC__ >= 4
        #define MICROSERVE_API __attribute__((visibility("default")))
    #else
        #define MICROSERVE_API
    #endif
#endif

#endif // MICROSERVE_H
