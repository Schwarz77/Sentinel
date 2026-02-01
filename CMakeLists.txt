cmake_minimum_required(VERSION 3.15)
project(Sentinel CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include deps)


if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600)
    link_directories(${CMAKE_SOURCE_DIR}/deps)
    set(NET_LIBS WinDivert.lib)
#else()
#    set(NET_LIBS pcap)
endif()

add_executable(Sentinel 
    src/main.cpp 
    src/WinDivertSource.cpp
)

target_link_libraries(Sentinel PRIVATE ${NET_LIBS})




