add_executable(dns_query dns_query.cpp)
target_link_libraries(dns_query PRIVATE dns_codec dns_net)
