project(CanaryMonitor LANGUAGES CXX VERSION 0.1.0)

message(STATUS "Configuring '${PROJECT_NAME}'")

include(FetchContent)
set(FAST_BUILD OFF)
set(WIL_BUILD_PACKAGING OFF)
set(WIL_BUILD_TESTS OFF)

FetchContent_Declare(
    WIL
    URL https://github.com/microsoft/wil/archive/refs/tags/v1.0.231028.1.zip
    URL_HASH MD5=48f04bde1b5d745ee2f6dedc9040fba7
)
FetchContent_MakeAvailable(WIL)

set(MONITOR_VERSION_MAJOR ${PROJECT_VERSION_MAJOR} CACHE INTERNAL "MONITOR_VERSION_MAJOR")
set(MONITOR_VERSION_MINOR ${PROJECT_VERSION_MINOR} CACHE INTERNAL "MONITOR_VERSION_MINOR")
set(MONITOR_VERSION_PATCH ${PROJECT_VERSION_PATCH} CACHE INTERNAL "MONITOR_VERSION_PATCH")

set(MONITOR_RC_FILE ${CMAKE_BINARY_DIR}/CanaryMonitor.rc)
set(MONITOR_RES_FILE ${CMAKE_BINARY_DIR}/CanaryMonitor.res)

cmake_path(SET MONITOR_DRIVER_PATH "$ENV{TEMP}/MinifilterDriver.sys")
cmake_path(SET MONITOR_DRIVER_INF_PATH "$ENV{TEMP}/MinifilterDriver.inf")
configure_file(${PROJECT_NAME}.rc.in ${MONITOR_RC_FILE} NEWLINE_STYLE WIN32 ESCAPE_QUOTES)

add_executable(${PROJECT_NAME} WIN32 CanaryMonitor.cpp)
add_dependencies(${PROJECT_NAME} MinifilterDriver)

target_include_directories(${PROJECT_NAME} PUBLIC ./Include $<TARGET_PROPERTY:WIL,INTERFACE_INCLUDE_DIRECTORIES>)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

target_compile_options(
    ${PROJECT_NAME}
    PUBLIC
    $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>

    PRIVATE
    $<IF:$<CONFIG:Debug>,/WX /Gm- /permissive-,/WX /permissive>
    $<$<NOT:$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},arm64>>:$<$<CONFIG:Debug>:/fsanitize=address>>
)

target_link_options(${PROJECT_NAME} PUBLIC /SUBSYSTEM:Console)

target_link_libraries(${PROJECT_NAME}
    ${MONITOR_RES_FILE}
    ntdll.lib
    kernel32.lib
    Advapi32.lib
    Dbghelp.lib
    Shell32.lib
    user32.lib
    FltLib.lib
)

set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS " /level='requireAdministrator' /uiAccess='false' ")

install(TARGETS ${PROJECT_NAME} DESTINATION Tools)
install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION Tools OPTIONAL)

add_custom_command(
    TARGET ${PROJECT_NAME} PRE_BUILD
    COMMAND
    rc /nologo /I $<TARGET_PROPERTY:${PROJECT_NAME},INCLUDE_DIRECTORIES> /fo ${MONITOR_RES_FILE} /r ${MONITOR_RC_FILE}
    COMMENT
    "Compiling '${MONITOR_RES_FILE}' resource file"
)
