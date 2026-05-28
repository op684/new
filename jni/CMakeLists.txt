cmake_minimum_required(VERSION 3.22)
project(mcpe_modmenu LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT ANDROID)
    message(FATAL_ERROR "This module only builds for Android via the NDK toolchain.")
endif()

if(NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "Only arm64-v8a is supported. Got: ${ANDROID_ABI}")
endif()

add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -ffunction-sections -fdata-sections
    -fvisibility=hidden -fvisibility-inlines-hidden
)
add_link_options(-Wl,--gc-sections -Wl,--exclude-libs,ALL)

include(FetchContent)

# ---- Dobby (inline hooking) ----------------------------------------------
FetchContent_Declare(
    dobby
    GIT_REPOSITORY https://github.com/jmpews/Dobby.git
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
set(DOBBY_GENERATE_SHARED OFF CACHE BOOL "" FORCE)
set(DOBBY_BUILD_EXAMPLE   OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(dobby)

# ---- Dear ImGui -----------------------------------------------------------
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.90.4
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(imgui)

add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(imgui PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)
target_compile_definitions(imgui PUBLIC
    IMGUI_IMPL_OPENGL_ES3
    IMGUI_DISABLE_FILE_FUNCTIONS
)

# ---- The Zygisk module ----------------------------------------------------
add_library(zygisk_module SHARED
    main.cpp
    hooks/egl.cpp
    hooks/input.cpp
    hooks/mcpe.cpp
    menu/menu.cpp
    mods/manager.cpp
    mods/xray.cpp
    mods/chest_finder.cpp
    mods/nuker.cpp
    util/memory.cpp
)

target_include_directories(zygisk_module PRIVATE .)

target_link_libraries(zygisk_module PRIVATE
    imgui
    dobby
    log
    android
    EGL
    GLESv3
)

# Magisk loads the module by exact filename: zygisk/<abi>.so
set_target_properties(zygisk_module PROPERTIES
    OUTPUT_NAME "${ANDROID_ABI}"
    PREFIX ""
)
