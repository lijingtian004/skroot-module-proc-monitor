cmake_minimum_required(VERSION 3.22)
project(skroot_overlay CXX C)
set(CMAKE_CXX_STANDARD 20)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/include/ImGui)

add_executable(skroot_overlay
    src/overlay_main.cpp
    src/VulkanGraphics.cpp
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_impl_vulkan.cpp
    ${IMGUI_DIR}/imgui_impl_android.cpp
)

target_include_directories(skroot_overlay PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/ImGui
    ${CMAKE_SOURCE_DIR}/include/native_surface
)

# 关掉栈保护，bizinb的头文件有大栈对象
target_compile_options(skroot_overlay PRIVATE -fno-stack-protector)

find_library(LOG_LIB log)
find_library(ANDROID_LIB android)
find_library(VULKAN_LIB vulkan)

target_link_libraries(skroot_overlay ${LOG_LIB} ${ANDROID_LIB} ${VULKAN_LIB} dl)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET skroot_overlay POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-debug $<TARGET_FILE:skroot_overlay>)
endif()
