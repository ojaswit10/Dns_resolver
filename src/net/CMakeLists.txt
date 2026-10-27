add_library(dns_net
    socket_compat.cpp
    transport.cpp
)
target_include_directories(dns_net PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(dns_net PUBLIC dns_codec)

if(WIN32)
    target_link_libraries(dns_net PUBLIC ws2_32)
    target_compile_definitions(dns_net PUBLIC _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

# The tests run fake nameservers on background threads.
find_package(Threads REQUIRED)

add_executable(transport_test transport_test.cpp)
target_link_libraries(transport_test PRIVATE dns_net Threads::Threads)
add_test(NAME transport_test COMMAND transport_test)
