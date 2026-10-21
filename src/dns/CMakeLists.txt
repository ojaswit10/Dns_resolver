add_library(dns_codec
    message.cpp
    codec.cpp
)
target_include_directories(dns_codec PUBLIC ${PROJECT_SOURCE_DIR}/src)

add_executable(codec_test codec_test.cpp)
target_link_libraries(codec_test PRIVATE dns_codec)
add_test(NAME codec_test COMMAND codec_test)
