cmake_minimum_required(VERSION 3.13)

project(QUICTun)

include(GNUInstallDirs)

set(PICOQUIC_FETCH_PTLS
    ON
    CACHE BOOL "" FORCE)
set(FETCHCONTENT_SOURCE_DIR_PICOTLS
    "${CMAKE_CURRENT_SOURCE_DIR}/picotls"
    CACHE PATH "" FORCE)

# Instrument dependencies as well as QUICTun in sanitizer profiles. Options set
# *after* add_subdirectory() do not reach PicoQUIC/Picotls targets.
if(CMAKE_BUILD_TYPE STREQUAL "Debug_ASan")
    add_compile_options(-Og -g -fsanitize=address,undefined
                        -fno-omit-frame-pointer)
    add_link_options(-g -fsanitize=address,undefined)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug_MSan")
    add_compile_options(-Og -g -fsanitize=memory -fno-omit-frame-pointer)
    add_link_options(-g -fsanitize=memory)
endif()

# We need the picoquic libraries to build QUICTun, but must not install picoquic
# demo programs, headers, archives or picotls artifacts with it.
add_subdirectory(picoquic EXCLUDE_FROM_ALL)

file(GLOB SRC "src/*.c")
add_executable(${PROJECT_NAME} ${SRC})
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Werror -Wpedantic
                                               -std=gnu11)
target_include_directories(${PROJECT_NAME} PRIVATE include picoquic/picoquic
                                                   picotls/include)
target_link_libraries(${PROJECT_NAME} PRIVATE picoquic-core)

# Regression tests compile production helpers into a separate test process. This
# target is opt-in and never part of the install set.
option(QUICTUN_BUILD_TESTS "Build QUICTun internal C unit tests" OFF)
if(QUICTUN_BUILD_TESTS)
    add_executable(quictun-unit tests/unit/test_core.c src/errno_names.c)
    target_compile_options(quictun-unit PRIVATE -Wall -Wextra -Werror
                                                -Wpedantic -std=gnu11)
    target_include_directories(quictun-unit PRIVATE include picoquic/picoquic
                                                    picotls/include)
    target_link_libraries(quictun-unit PRIVATE picoquic-core)
endif()

# Install QUICTun in /usr/bin, independent of CMAKE_INSTALL_PREFIX.
install(TARGETS ${PROJECT_NAME} DESTINATION /usr/bin)

find_program(CLANGFORMAT clang-format)
if(CLANGFORMAT)
    add_custom_target(
        quictun-format
        COMMAND "${CLANGFORMAT}" -i ${SRC}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Format QUICTun sources (explicitly requested)"
        VERBATIM)
endif()

find_package(Git QUIET)
execute_process(
    COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
    RESULT_VARIABLE GIT_RC)
target_compile_definitions(${PROJECT_NAME}
                           PRIVATE GIT_COMMIT_STR="${GIT_COMMIT}")

if(QUICTUN_BUILD_TESTS)
    target_compile_definitions(quictun-unit
                               PRIVATE GIT_COMMIT_STR="${GIT_COMMIT}")
endif()
