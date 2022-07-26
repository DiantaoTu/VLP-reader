
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(VLP_reader)

find_package(PCL REQUIRED)

include_directories(${PCL_INCLUDE_DIRS})
link_directories(${PCL_LIBRARY_DIRS})
add_definitions(${PCL_DEFINITIONS})

find_package(Boost REQUIRED COMPONENTS system thread)
include_directories(${Boost_INCLUDE_DIRS})

# find_package(PCAP REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} 
                    ${PCL_LIBRARIES}
                    ${Boost_LIBRARIES}
                    /usr/lib/x86_64-linux-gnu/libpcap.so)
