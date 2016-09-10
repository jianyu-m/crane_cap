cmake_minimum_required(VERSION 2.8)
project(crane_cap)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_BUILD_TYPE Debug)
set(SOURCE_FILES main.c)
add_executable(crane_cap ${SOURCE_FILES})
add_executable(get_time "get_time.c")
add_executable(paxos_cap libpaxos_cap.c paxos_types_pack.c)
target_link_libraries(crane_cap pcap)
target_link_libraries(paxos_cap pcap msgpack)

