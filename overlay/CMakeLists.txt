cmake_minimum_required(VERSION 3.22)
project(skroot_overlay CXX C)
set(CMAKE_CXX_STANDARD 20)

add_executable(skroot_overlay
    src/overlay_main.cpp
)

target_include_directories(skroot_overlay PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/native_surface
)

target_compile_options(skroot_overlay PRIVATE -fno-stack-protector)

find_library(LOG_LIB log)
find_library(ANDROID_LIB android)

target_link_libraries(skroot_overlay ${LOG_LIB} ${ANDROID_LIB} dl m)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET skroot_overlay POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-debug $<TARGET_FILE:skroot_overlay>)
endif()
