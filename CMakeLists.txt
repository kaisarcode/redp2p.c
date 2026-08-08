# redp2p - REDP2P
# KaisarCode - CMake build configuration
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.14)
project(redp2p LANGUAGES C)
set(CMAKE_C_STANDARD 11)

if(NOT DEFINED REDP2P_BUILD_VERSION)
    set(REDP2P_BUILD_VERSION 0)
endif()

option(REDP2P_BUILD_TESTS "Build redp2p tests" OFF)

set(REDP2P_TEST_EXTERNAL_ARTIFACTS OFF)
if(REDP2P_BUILD_TESTS AND REDP2P_TEST_SHARED_LIBRARY)
    set(REDP2P_TEST_EXTERNAL_ARTIFACTS ON)
endif()

if(NOT MSVC)
    add_compile_options(-O3 -Wall -Wextra -Werror)
    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        add_compile_options(-Wno-unused-command-line-argument)
    endif()
    add_definitions(-D_GNU_SOURCE)
else()
    add_compile_options(/O2 /W3 /WX)
endif()

# Shared library
set(REDP2P_SOURCES
    src/libredp2p.c
    lib/monocypher/monocypher.c
    lib/kcp/ikcp.c
    lib/parson/parson.c
)

set_source_files_properties(src/libredp2p.c PROPERTIES
    COMPILE_DEFINITIONS REDP2P_BUILD_VERSION=${REDP2P_BUILD_VERSION}
)

if(NOT REDP2P_TEST_EXTERNAL_ARTIFACTS)
    add_library(redp2p_shared SHARED ${REDP2P_SOURCES})
    set_target_properties(redp2p_shared PROPERTIES OUTPUT_NAME "redp2p")
    target_include_directories(redp2p_shared PRIVATE src lib/monocypher lib/kcp lib/parson)

    # Static library
    add_library(redp2p_static STATIC ${REDP2P_SOURCES})
    set_target_properties(redp2p_static PROPERTIES OUTPUT_NAME "redp2p")
    target_include_directories(redp2p_static PRIVATE src lib/monocypher lib/kcp lib/parson)

    # Binary: redp2p
    if(APPLE)
        add_executable(redp2p src/redp2p.c ${REDP2P_SOURCES})
    else()
        add_executable(redp2p src/redp2p.c)
        target_link_libraries(redp2p PRIVATE redp2p_static)
    endif()
    target_include_directories(redp2p PRIVATE src lib/monocypher lib/kcp lib/parson)

    if(UNIX AND NOT ANDROID AND NOT APPLE)
        target_link_libraries(redp2p_shared pthread m)
        target_link_libraries(redp2p_static pthread m)
        target_link_libraries(redp2p PRIVATE pthread m)
    elseif(MINGW)
        target_link_libraries(redp2p_shared ws2_32 bcrypt)
        target_link_libraries(redp2p_static ws2_32 bcrypt)
        target_link_libraries(redp2p PRIVATE ws2_32 bcrypt)
    elseif(MSVC)
        target_link_libraries(redp2p_shared ws2_32 bcrypt)
        target_link_libraries(redp2p_static ws2_32 bcrypt)
        target_link_libraries(redp2p PRIVATE ws2_32 bcrypt)
    endif()
endif()

if(REDP2P_BUILD_TESTS)
    enable_testing()

    if(REDP2P_TEST_SHARED_LIBRARY)
        add_library(redp2p_test_shared SHARED IMPORTED)
        set_target_properties(redp2p_test_shared PROPERTIES
            IMPORTED_LOCATION "${REDP2P_TEST_SHARED_LIBRARY}"
        )
        if(REDP2P_TEST_IMPORT_LIBRARY)
            set_target_properties(redp2p_test_shared PROPERTIES
                IMPORTED_IMPLIB "${REDP2P_TEST_IMPORT_LIBRARY}"
            )
        endif()
    else()
        set(REDP2P_TEST_SHARED_TARGET redp2p_shared)
    endif()

    if(TARGET redp2p_test_shared)
        set(REDP2P_TEST_SHARED_TARGET redp2p_test_shared)
    endif()

    add_executable(redp2p_contract_test src/test.c)
    target_include_directories(redp2p_contract_test PRIVATE src)
    target_link_libraries(redp2p_contract_test PRIVATE ${REDP2P_TEST_SHARED_TARGET})
    if(REDP2P_TEST_CLI)
        set(REDP2P_TEST_CLI_TARGET_PATH "${REDP2P_TEST_CLI}")
    elseif(TARGET redp2p)
        set(REDP2P_TEST_CLI_TARGET_PATH "$<TARGET_FILE:redp2p>")
    else()
        set(REDP2P_TEST_CLI_TARGET_PATH "")
    endif()
    target_compile_definitions(redp2p_contract_test PRIVATE
        REDP2P_TEST_CLI="${REDP2P_TEST_CLI_TARGET_PATH}"
    )

    if(UNIX AND NOT ANDROID AND NOT APPLE)
        target_link_libraries(redp2p_contract_test PRIVATE pthread m)
    elseif(MINGW)
        target_link_libraries(redp2p_contract_test PRIVATE ws2_32 bcrypt)
    elseif(MSVC)
        target_link_libraries(redp2p_contract_test PRIVATE ws2_32 bcrypt)
    endif()

    add_custom_command(TARGET redp2p_contract_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:${REDP2P_TEST_SHARED_TARGET}>
            $<TARGET_FILE_DIR:redp2p_contract_test>
    )

    if(REDP2P_TEST_CLI)
        if(CMAKE_CROSSCOMPILING_EMULATOR)
            set(REDP2P_TEST_CLI_COMMAND
                ${CMAKE_CROSSCOMPILING_EMULATOR}
                "${REDP2P_TEST_CLI}"
            )
        else()
            set(REDP2P_TEST_CLI_COMMAND "${REDP2P_TEST_CLI}")
        endif()
    elseif(TARGET redp2p)
        set(REDP2P_TEST_CLI_COMMAND "$<TARGET_FILE:redp2p>")
    endif()

    if(REDP2P_TEST_CLI_COMMAND)
        add_test(NAME cli-redp2p-help COMMAND ${REDP2P_TEST_CLI_COMMAND} --help)
        add_test(NAME cli-redp2p-version COMMAND ${REDP2P_TEST_CLI_COMMAND} --version)
        set_tests_properties(cli-redp2p-help PROPERTIES
            PASS_REGULAR_EXPRESSION "REDP2P_PASS"
        )
        set_tests_properties(cli-redp2p-version PROPERTIES
            PASS_REGULAR_EXPRESSION "redp2p build [0-9]+"
        )
    endif()

    add_test(NAME library-redp2p_options_default COMMAND redp2p_contract_test redp2p_options_default)
    add_test(NAME library-redp2p_options_load_env COMMAND redp2p_contract_test redp2p_options_load_env)
    add_test(NAME library-redp2p_options_load_env_invalid COMMAND redp2p_contract_test redp2p_options_load_env_invalid)
    add_test(NAME library-redp2p_options_free COMMAND redp2p_contract_test redp2p_options_free)
    add_test(NAME library-redp2p_open COMMAND redp2p_contract_test redp2p_open)
    add_test(NAME library-redp2p_close COMMAND redp2p_contract_test redp2p_close)
    add_test(NAME library-redp2p_stop COMMAND redp2p_contract_test redp2p_stop)
    add_test(NAME library-redp2p_version COMMAND redp2p_contract_test redp2p_version)
    add_test(NAME library-redp2p_strerror COMMAND redp2p_contract_test redp2p_strerror)
    add_test(NAME library-redp2p_is_valid_id COMMAND redp2p_contract_test redp2p_is_valid_id)
    add_test(NAME library-redp2p_is_valid_pass_token COMMAND redp2p_contract_test redp2p_is_valid_pass_token)
    add_test(NAME library-redp2p_serve_index COMMAND redp2p_contract_test redp2p_serve_index)
    add_test(NAME library-redp2p_wait COMMAND redp2p_contract_test redp2p_wait)
    add_test(NAME library-redp2p_connect COMMAND redp2p_contract_test redp2p_connect)
    add_test(NAME library-redp2p_udp_tunnel COMMAND redp2p_contract_test redp2p_udp_tunnel)
    add_test(NAME library-redp2p_tcp_stream COMMAND redp2p_contract_test redp2p_tcp_stream)
    add_test(NAME library-redp2p_deregister COMMAND redp2p_contract_test redp2p_deregister)
    add_test(NAME library-redp2p_list_publishers COMMAND redp2p_contract_test redp2p_list_publishers)
    add_test(NAME library-redp2p_get_error COMMAND redp2p_contract_test redp2p_get_error)
    add_test(NAME library-redp2p_set_seats COMMAND redp2p_contract_test redp2p_set_seats)
    add_test(NAME library-redp2p_set_pow COMMAND redp2p_contract_test redp2p_set_pow)
    add_test(NAME library-redp2p_set_port COMMAND redp2p_contract_test redp2p_set_port)
    add_test(NAME library-redp2p_set_protocol COMMAND redp2p_contract_test redp2p_set_protocol)
    add_test(NAME library-redp2p_set_pass COMMAND redp2p_contract_test redp2p_set_pass)
    add_test(NAME library-redp2p_set_vip COMMAND redp2p_contract_test redp2p_set_vip)
    add_test(NAME library-redp2p_set_sweep COMMAND redp2p_contract_test redp2p_set_sweep)
    add_test(NAME library-redp2p_set_stun_url COMMAND redp2p_contract_test redp2p_set_stun_url)
    set_tests_properties(library-redp2p_serve_index PROPERTIES TIMEOUT 30)
    set_tests_properties(library-redp2p_wait PROPERTIES TIMEOUT 30)
    set_tests_properties(library-redp2p_connect PROPERTIES TIMEOUT 30)
    set_tests_properties(
        library-redp2p_udp_tunnel
        library-redp2p_tcp_stream
        PROPERTIES TIMEOUT 45
    )
    set_tests_properties(library-redp2p_deregister PROPERTIES TIMEOUT 30)
    set_tests_properties(library-redp2p_list_publishers PROPERTIES TIMEOUT 30)
endif()
