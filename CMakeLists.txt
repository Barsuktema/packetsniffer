cmake_minimum_required(VERSION 3.12)

project(packet_sniffer)

add_executable(packet_sniffer 
    src/main.cpp
    src/sniffer.cpp
    src/loader.cpp
    src/reswrite.cpp
)
find_package(spdlog REQUIRED)
add_library( pcap SHARED IMPORTED )
set_target_properties( pcap PROPERTIES IMPORTED_LOCATION /usr/lib/x86_64-linux-gnu/libpcap.so )

set_target_properties(packet_sniffer PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
target_link_libraries(packet_sniffer pcap spdlog::spdlog)
