project(CommonLib LANGUAGES CXX VERSION 0.1.0)

message(STATUS "Configuring '${PROJECT_NAME}'")

wdk_add_library(${PROJECT_NAME}
    STATIC
    KMDF
    1.15

    ../Common/Log.cpp
    ../Common/Log.hpp
    ../Common/Utils.cpp
    ../Common/Utils.hpp
)

target_include_directories(${PROJECT_NAME} INTERFACE ../Common)
