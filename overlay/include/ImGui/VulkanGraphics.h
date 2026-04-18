#ifndef VULKAN_GRAPHICS_H
#define VULKAN_GRAPHICS_H

#include "imgui.h"
#include "imgui_impl_vulkan.h"
#include <vulkan/vulkan.h>
#include <vulkan/vulkan_android.h>
#include <android/native_window.h>
#include <memory>

class VulkanGraphics {
public:
    bool Init(ANativeWindow* window, int width, int height);
    void Shutdown();
    void NewFrame();
    void Render(ImDrawData* drawData);

    VkInstance       GetInstance()       { return m_Instance; }
    VkPhysicalDevice GetPhysicalDevice() { return m_PhysicalDevice; }
    VkDevice         GetDevice()         { return m_Device; }
    VkQueue          GetQueue()          { return m_Queue; }
    uint32_t         GetQueueFamily()    { return m_QueueFamily; }
    VkDescriptorPool GetDescriptorPool() { return m_DescriptorPool; }

private:
    VkInstance       m_Instance = VK_NULL_HANDLE;
    VkPhysicalDevice m_PhysicalDevice = VK_NULL_HANDLE;
    VkDevice         m_Device = VK_NULL_HANDLE;
    VkQueue          m_Queue = VK_NULL_HANDLE;
    uint32_t         m_QueueFamily = (uint32_t)-1;
    VkDescriptorPool m_DescriptorPool = VK_NULL_HANDLE;
    VkPipelineCache  m_PipelineCache = VK_NULL_HANDLE;
    VkAllocationCallbacks* m_Allocator = nullptr;

    std::unique_ptr<ImGui_ImplVulkanH_Window> wd;
    ANativeWindow* m_Window = nullptr;
    int m_Width, m_Height;
    uint32_t m_MinImageCount = 2;
    bool m_SwapChainRebuild = false;
    int m_LastWidth = 0, m_LastHeight = 0;
};

#endif
