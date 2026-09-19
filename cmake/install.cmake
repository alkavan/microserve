# SPDX-FileCopyrightText: 2025-2026 Igal Alkon
# SPDX-FileCopyrightText: 2026 ALKONTEK <git@alkontek.com>
# SPDX-License-Identifier: BSD-3-Clause

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS microserver
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/certs")
    install(DIRECTORY certs/
            DESTINATION ${CMAKE_INSTALL_DATADIR}/microserve/certs
    )
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/public")
    install(DIRECTORY public/
            DESTINATION ${CMAKE_INSTALL_DATADIR}/microserve/public
    )
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/private")
    install(DIRECTORY private/
            DESTINATION ${CMAKE_INSTALL_DATADIR}/microserve/private
    )
endif()

# Runs at install time, so cmake --install --prefix is visible.
install(CODE "
    set(MICROSERVE_DIST_DIR \"${CMAKE_CURRENT_SOURCE_DIR}/dist\")
    set(MICROSERVE_SYSCONFDIR \"${CMAKE_INSTALL_SYSCONFDIR}\")
    set(MICROSERVE_STAGE_DIR \"${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/microserve-dist-install\")
    include(\"${CMAKE_CURRENT_SOURCE_DIR}/cmake/install_dist_configs.cmake\")
")

set(INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_INCLUDEDIR}")
set(MICROSERVE_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/microserve")

configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/microserveConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/microserveConfig.cmake"
        INSTALL_DESTINATION "${MICROSERVE_INSTALL_CMAKEDIR}"
        PATH_VARS INCLUDE_INSTALL_DIR
)

write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/microserveConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMinorVersion
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/microserve.h"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/microserveConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/microserveConfigVersion.cmake"
        DESTINATION "${MICROSERVE_INSTALL_CMAKEDIR}"
)