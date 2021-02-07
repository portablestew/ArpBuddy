cmake_minimum_required(VERSION 3.0.0)
project(arpbuddy VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(arpbuddy
    ArpBuddy.cpp
    ArpSocket.cpp
    Util.cpp
    main.cpp
)
target_include_directories(arpbuddy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
