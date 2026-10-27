add_library(dns_resolver
    resolver.cpp
)
target_include_directories(dns_resolver PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(dns_resolver PUBLIC dns_codec dns_net dns_cache)

add_executable(resolve resolve_main.cpp)
target_link_libraries(resolve PRIVATE dns_resolver)

add_executable(resolver_test resolver_test.cpp)
target_link_libraries(resolver_test PRIVATE dns_resolver)
add_test(NAME resolver_test COMMAND resolver_test)
