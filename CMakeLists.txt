cmake_minimum_required(VERSION 3.26)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

project(
    canary-driver
    LANGUAGES CXX
    VERSION 0.1.0
    DESCRIPTION "canary-driver"
    HOMEPAGE_URL https://github.com/calladoum-elastic/canary-driver
)

set(PROJECT_AUTHOR "Christophe Alladoum")
set(PROJECT_LICENSE MIT)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

set(CXX_STANDARD 20)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(DEBUG "Enable Debug" ON)

message(STATUS "Locating Windows Driver Kit")
find_package(WDK REQUIRED)

add_subdirectory(Common)
add_subdirectory(MiniFilter)
add_subdirectory(ProcessDumper)

# list(APPEND VCPKG_MANIFEST_FEATURES "ProcessDumper")
