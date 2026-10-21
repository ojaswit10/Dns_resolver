cmake_minimum_required(VERSION 3.16)
project(dns_resolver LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Link the MinGW runtime statically so the .exe files run outside the toolchain shell.
if(MINGW)
    add_link_options(-static)
endif()

enable_testing()

# Each module folder owns its own CMakeLists.txt. Folders that do not exist yet
# on your branch are skipped, so adding a module never requires editing this file.
foreach(module IN ITEMS src/dns src/net src/cache src/resolver src/server tools)
    if(EXISTS ${PROJECT_SOURCE_DIR}/${module}/CMakeLists.txt)
        add_subdirectory(${module})
    endif()
endforeach()
