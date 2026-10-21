add_library(dns_cache
    cache.cpp
)

target_include_directories(dns_cache PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(dns_cache PUBLIC dns_codec)

add_executable(cache_test cache_test.cpp)
target_link_libraries(cache_test PRIVATE dns_cache)
add_test(NAME cache_test COMMAND cache_test)
