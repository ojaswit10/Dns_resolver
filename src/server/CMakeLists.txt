find_package(Threads REQUIRED)

add_library(dns_server
    server.cpp
)
target_include_directories(dns_server PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(dns_server PUBLIC dns_resolver Threads::Threads)

add_executable(serve serve_main.cpp)
target_link_libraries(serve PRIVATE dns_server)

add_executable(server_test server_test.cpp)
target_link_libraries(server_test PRIVATE dns_server)
add_test(NAME server_test COMMAND server_test)
