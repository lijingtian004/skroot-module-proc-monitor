#include "VulkanGraphics.h"
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <unistd.h>

static void check_vk_result(VkResult err) {
    if (err == 0) return;
    fprintf(stderr, "[vulkan] VkResult = %d\n", err);
    if (err < 0) abort();
}

static VkPhysicalDevice SelectPhysicalDevice(VkInstance instance) {
    uint32_t gpu_count = 0;
    vkEnumeratePhysicalDevices(instance, &gpu_count, nullptr);
    if (gpu_count == 0) return VK_NULL_HANDLE;

    ImVector<VkPhysicalDevice> gpus;
    gpus.resize(gpu_count);
    vkEnumeratePhysicalDevices(instance, &gpu_count, gpus.Data);

    for (auto& device : gpus) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(device, &props);
        if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU)
            return device;
    }
    return gpus[0];
}

bool VulkanGraphics::Init(ANativeWindow* window, int width, int height) {
    m_Window = window;
    m_Width = width;
    m_Height = height;

    // Load Vulkan functions via dlopen
    void* libvulkan = dlopen("libvulkan.so", RTLD_NOW);
    if (!libvulkan) { fprintf(stderr, "Failed to load libvulkan.so\n"); return false; }

    ImGui_ImplVulkan_LoadFunctions([](const char* name, void* handle) -> PFN_vkVoidFunction {
        return (PFN_vkVoidFunction)dlsym(handle, name);
    }, libvulkan);

    // Create Instance
    const char* extensions[] = { "VK_KHR_surface", "VK_KHR_android_surface" };
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "SKRootOverlay";
    appInfo.apiVersion = VK_MAKE_VERSION(1, 1, 0);

    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &appInfo;
    ci.enabledExtensionCount = 2;
    ci.ppEnabledExtensionNames = extensions;

    VkResult err = vkCreateInstance(&ci, m_Allocator, &m_Instance);
    check_vk_result(err);

    // Select GPU
    m_PhysicalDevice = SelectPhysicalDevice(m_Instance);
    if (m_PhysicalDevice == VK_NULL_HANDLE) { fprintf(stderr, "No GPU found\n"); return false; }

    // Find queue family
    uint32_t qcount = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(m_PhysicalDevice, &qcount, nullptr);
    ImVector<VkQueueFamilyProperties> queues;
    queues.resize(qcount);
    vkGetPhysicalDeviceQueueFamilyProperties(m_PhysicalDevice, &qcount, queues.Data);
    for (uint32_t i = 0; i < qcount; i++) {
        if (queues[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) { m_QueueFamily = i; break; }
    }

    // Create logical device
    const char* dev_exts[] = { "VK_KHR_swapchain" };
    float priority[] = { 1.0f };
    VkDeviceQueueCreateInfo qci{};
    qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = m_QueueFamily;
    qci.queueCount = 1;
    qci.pQueuePriorities = priority;

    VkDeviceCreateInfo dci{};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    dci.enabledExtensionCount = 1;
    dci.ppEnabledExtensionNames = dev_exts;

    err = vkCreateDevice(m_PhysicalDevice, &dci, m_Allocator, &m_Device);
    check_vk_result(err);
    vkGetDeviceQueue(m_Device, m_QueueFamily, 0, &m_Queue);

    // Create descriptor pool
    VkDescriptorPoolSize pool_sizes[] = {
        { VK_DESCRIPTOR_TYPE_SAMPLER, 1000 }, { VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 1000 },
        { VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 1000 }, { VK_DESCRIPTOR_TYPE_STORAGE_IMAGE, 1000 },
        { VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER, 1000 }, { VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 1000 }, { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC, 1000 }, { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC, 1000 },
        { VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT, 1000 }
    };
    VkDescriptorPoolCreateInfo pi{};
    pi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pi.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    pi.maxSets = 1000 * 11;
    pi.poolSizeCount = 11;
    pi.pPoolSizes = pool_sizes;
    err = vkCreateDescriptorPool(m_Device, &pi, m_Allocator, &m_DescriptorPool);
    check_vk_result(err);

    // Create surface
    wd = std::make_unique<ImGui_ImplVulkanH_Window>();
    VkAndroidSurfaceCreateInfoKHR sci{};
    sci.sType = VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR;
    sci.window = m_Window;
    err = vkCreateAndroidSurfaceKHR(m_Instance, &sci, m_Allocator, &wd->Surface);
    check_vk_result(err);

    // Check WSI support
    VkBool32 wsi = VK_FALSE;
    vkGetPhysicalDeviceSurfaceSupportKHR(m_PhysicalDevice, m_QueueFamily, wd->Surface, &wsi);
    if (!wsi) { fprintf(stderr, "No WSI support\n"); return false; }

    // Select format
    VkFormat fmts[] = { VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM };
    wd->SurfaceFormat = ImGui_ImplVulkanH_SelectSurfaceFormat(m_PhysicalDevice, wd->Surface, fmts, 2, VK_COLORSPACE_SRGB_NONLINEAR_KHR);

    VkPresentModeKHR pmodes[] = { VK_PRESENT_MODE_FIFO_KHR };
    wd->PresentMode = ImGui_ImplVulkanH_SelectPresentMode(m_PhysicalDevice, wd->Surface, pmodes, 1);

    // Create swapchain
    ImGui_ImplVulkanH_CreateOrResizeWindow(m_Instance, m_PhysicalDevice, m_Device, wd.get(), m_QueueFamily, m_Allocator, m_Width, m_Height, m_MinImageCount);

    // Init ImGui Vulkan backend
    ImGui_ImplVulkan_InitInfo init_info{};
    init_info.Instance = m_Instance;
    init_info.PhysicalDevice = m_PhysicalDevice;
    init_info.Device = m_Device;
    init_info.QueueFamily = m_QueueFamily;
    init_info.Queue = m_Queue;
    init_info.DescriptorPool = m_DescriptorPool;
    init_info.RenderPass = wd->RenderPass;
    init_info.MinImageCount = m_MinImageCount;
    init_info.ImageCount = wd->ImageCount;
    init_info.MSAASamples = VK_SAMPLE_COUNT_1_BIT;
    init_info.CheckVkResultFn = check_vk_result;
    ImGui_ImplVulkan_Init(&init_info);

    return true;
}

void VulkanGraphics::NewFrame() {
    // Handle resize
    if (m_SwapChainRebuild) {
        int w = ANativeWindow_getWidth(m_Window);
        int h = ANativeWindow_getHeight(m_Window);
        if (w > 0 && h > 0 && (w != m_LastWidth || h != m_LastHeight)) {
            usleep(500000);
            m_LastWidth = w; m_LastHeight = h;
            ImGui_ImplVulkan_SetMinImageCount(m_MinImageCount);
            ImGui_ImplVulkanH_CreateOrResizeWindow(m_Instance, m_PhysicalDevice, m_Device, wd.get(), m_QueueFamily, m_Allocator, w, h, m_MinImageCount);
            wd->FrameIndex = 0;
            m_SwapChainRebuild = false;
        }
    }
    ImGui_ImplVulkan_NewFrame();
}

void VulkanGraphics::Render(ImDrawData* drawData) {
    VkSemaphore image_acquired = wd->FrameSemaphores[wd->SemaphoreIndex].ImageAcquiredSemaphore;
    VkSemaphore render_complete = wd->FrameSemaphores[wd->SemaphoreIndex].RenderCompleteSemaphore;

    VkResult err = vkAcquireNextImageKHR(m_Device, wd->Swapchain, UINT64_MAX, image_acquired, VK_NULL_HANDLE, &wd->FrameIndex);
    if (err == VK_ERROR_OUT_OF_DATE_KHR) { m_SwapChainRebuild = true; return; }

    auto* fd = &wd->Frames[wd->FrameIndex];
    vkWaitForFences(m_Device, 1, &fd->Fence, VK_TRUE, UINT64_MAX);
    vkResetFences(m_Device, 1, &fd->Fence);

    vkResetCommandPool(m_Device, fd->CommandPool, 0);
    VkCommandBufferBeginInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(fd->CommandBuffer, &bi);

    VkRenderPassBeginInfo rpi{};
    rpi.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    rpi.renderPass = wd->RenderPass;
    rpi.framebuffer = fd->Framebuffer;
    rpi.renderArea.extent = { (uint32_t)wd->Width, (uint32_t)wd->Height };
    rpi.clearValueCount = 1;
    rpi.pClearValues = &wd->ClearValue;
    vkCmdBeginRenderPass(fd->CommandBuffer, &rpi, VK_SUBPASS_CONTENTS_INLINE);

    ImGui_ImplVulkan_RenderDrawData(drawData, fd->CommandBuffer);

    vkCmdEndRenderPass(fd->CommandBuffer);
    vkEndCommandBuffer(fd->CommandBuffer);

    VkPipelineStageFlags waitStage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.waitSemaphoreCount = 1;
    si.pWaitSemaphores = &image_acquired;
    si.pWaitDstStageMask = &waitStage;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &fd->CommandBuffer;
    si.signalSemaphoreCount = 1;
    si.pSignalSemaphores = &render_complete;
    vkQueueSubmit(m_Queue, 1, &si, fd->Fence);

    if (m_SwapChainRebuild) return;

    VkPresentInfoKHR pi{};
    pi.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    pi.waitSemaphoreCount = 1;
    pi.pWaitSemaphores = &render_complete;
    pi.swapchainCount = 1;
    pi.pSwapchains = &wd->Swapchain;
    pi.pImageIndices = &wd->FrameIndex;
    err = vkQueuePresentKHR(m_Queue, &pi);
    if (err == VK_ERROR_OUT_OF_DATE_KHR) { m_SwapChainRebuild = true; return; }

    wd->SemaphoreIndex = (wd->SemaphoreIndex + 1) % wd->SemaphoreCount;
}

void VulkanGraphics::Shutdown() {
    vkDeviceWaitIdle(m_Device);
    ImGui_ImplVulkan_Shutdown();
    ImGui_ImplVulkanH_DestroyWindow(m_Instance, m_Device, wd.get(), m_Allocator);
    vkDestroyDescriptorPool(m_Device, m_DescriptorPool, m_Allocator);
    vkDestroyDevice(m_Device, m_Allocator);
    vkDestroyInstance(m_Instance, m_Allocator);
}
