project(ProcessDumper LANGUAGES CXX VERSION 0.1.0)

message(STATUS "Configuring '${PROJECT_NAME}'")

set(DUMPER_VERSION_MAJOR ${PROJECT_VERSION_MAJOR} CACHE INTERNAL "DUMPER_VERSION_MAJOR")
set(DUMPER_VERSION_MINOR ${PROJECT_VERSION_MINOR} CACHE INTERNAL "DUMPER_VERSION_MINOR")
set(DUMPER_VERSION_PATCH ${PROJECT_VERSION_PATCH} CACHE INTERNAL "DUMPER_VERSION_PATCH")

set(DUMPER_RC_FILE ${CMAKE_BINARY_DIR}/ProcessDumper.rc)
set(DUMPER_RES_FILE ${CMAKE_BINARY_DIR}/ProcessDumper.res)

cmake_path(SET DUMPER_DRIVER_PATH "$ENV{TEMP}/MinifilterDriver.sys")
configure_file(${PROJECT_NAME}.rc.in ${DUMPER_RC_FILE} NEWLINE_STYLE WIN32 ESCAPE_QUOTES)

add_executable(${PROJECT_NAME} WIN32 ProcessDumper.cpp)
add_dependencies(${PROJECT_NAME} MinifilterDriver)

target_include_directories(${PROJECT_NAME} PRIVATE ./Include)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)

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
    ${DUMPER_RES_FILE}
    kernel32.lib
    ntdll.lib
    Advapi32.lib
    Dbghelp.lib
)

set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS " /level='requireAdministrator' /uiAccess='false' ")

install(TARGETS ${PROJECT_NAME} DESTINATION Tools)
install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION Tools OPTIONAL)

add_custom_command(
    TARGET ${PROJECT_NAME} PRE_BUILD
    COMMAND
    rc /nologo /I $<TARGET_PROPERTY:${PROJECT_NAME},INCLUDE_DIRECTORIES> /fo ${DUMPER_RES_FILE} /r ${DUMPER_RC_FILE}
    COMMENT
    "Compiling '${DUMPER_RES_FILE}' resource file"
)
