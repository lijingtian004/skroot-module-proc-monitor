/*
 * SKRoot proc_monitor ImGui Overlay
 * Vulkan 渲染 + 独立悬浮窗
 */

#include "imgui.h"
#include "imgui_impl_android.h"
#include "imgui_impl_vulkan.h"
#include "VulkanGraphics.h"
#include "ANativeWindowCreator.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>

#define LOG_TAG "SKRootOverlay"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Signal handler for segfault debugging
static void sig_handler(int sig, siginfo_t* info, void* ctx) {
    LOGE("CRASH: signal %d at address %p", sig, info->si_addr);
    _exit(1);
}
static void install_signal_handlers() {
    struct sigaction sa{};
    sa.sa_sigaction = sig_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
}

static int g_port = 10273;
static int g_fps = 60;
static bool g_running = true;

struct OverlayData {
    double cpu_total = 0; double cpu_cores[16] = {}; int cpu_core_count = 0;
    double gpu_pct = -1; char gpu_name[32] = {}; double power_mw = 0;
    int bat_level = -1; int bat_temp = 0; char bat_status[32] = {};
    char fg_app[128] = {}; double fg_cpu = 0; int fg_mem = 0;
};
static OverlayData g_data;
static pthread_mutex_t g_data_mtx = PTHREAD_MUTEX_INITIALIZER;

// 简易 JSON
static double jnum(const char* j, const char* k) {
    char n[64]; snprintf(n, sizeof(n), "\"%s\"", k);
    const char* p = strstr(j, n); if (!p) return 0;
    p = strchr(p + strlen(n), ':'); if (!p) return 0;
    return atof(p + 1);
}
static void jstr(const char* j, const char* k, char* o, int sz) {
    o[0] = 0; char n[64]; snprintf(n, sizeof(n), "\"%s\"", k);
    const char* p = strstr(j, n); if (!p) return;
    p = strchr(p + strlen(n), '"'); if (!p) return; p++;
    const char* e = strchr(p, '"'); if (!e) return;
    int l = (int)(e - p); if (l >= sz) l = sz - 1;
    memcpy(o, p, l); o[l] = 0;
}

// 纯 socket HTTP 请求
static std::string http_post(const char* host, int port, const char* path) {
    std::string result;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return result;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    struct timeval tv{.tv_sec = 1, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return result; }

    char req[256];
    int len = snprintf(req, sizeof(req), "POST %s HTTP/1.0\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", path, host);
    send(fd, req, len, 0);

    char buf[4096]; int n;
    while ((n = recv(fd, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = 0;
        result += buf;
    }
    close(fd);

    // 去掉 HTTP 头
    auto pos = result.find("\r\n\r\n");
    if (pos != std::string::npos) result = result.substr(pos + 4);
    return result;
}

static void fetch_data() {
    static int pc = 0;
    if (pc++ % 30 == 0) {
        FILE* f = fopen("/data/local/tmp/skroot_webui_port", "r");
        if (f) { int p = 0; if (fscanf(f, "%d", &p) == 1 && p > 0) g_port = p; fclose(f); }
    }

    std::string resp = http_post("127.0.0.1", g_port, "/api/overlay");
    if (resp.empty()) return;

    const char* c = resp.c_str();
    pthread_mutex_lock(&g_data_mtx);
    g_data.cpu_total = jnum(c, "cpu_total");
    g_data.gpu_pct = jnum(c, "gpu_pct");
    g_data.power_mw = jnum(c, "power_mw");
    g_data.bat_level = (int)jnum(c, "bat_level");
    g_data.bat_temp = (int)jnum(c, "bat_temp");
    g_data.fg_cpu = jnum(c, "fg_cpu");
    g_data.fg_mem = (int)jnum(c, "fg_mem");
    jstr(c, "gpu_name", g_data.gpu_name, 32);
    jstr(c, "bat_status", g_data.bat_status, 32);
    jstr(c, "fg_app", g_data.fg_app, 128);
    // CPU cores array
    const char* ap = strstr(c, "\"cpu_cores\"");
    if (ap) {
        ap = strchr(ap, '['); if (ap) {
            ap++; g_data.cpu_core_count = 0;
            while (*ap && *ap != ']' && g_data.cpu_core_count < 16) {
                while (*ap == ' ' || *ap == ',') ap++;
                if (*ap == ']') break;
                g_data.cpu_cores[g_data.cpu_core_count++] = atof(ap);
                while (*ap && *ap != ',' && *ap != ']') ap++;
            }
        }
    }
    pthread_mutex_unlock(&g_data_mtx);
}

static void* data_thread(void*) {
    while (g_running) { fetch_data(); usleep(2000000); }
    return nullptr;
}

static const char* status_cn(const char* s) {
    if (!s||!s[0]) return "--";
    if (!strcmp(s,"Charging")) return "充电中";
    if (!strcmp(s,"Discharging")) return "放电中";
    if (!strcmp(s,"Full")) return "已充满";
    return s;
}

static void DrawUI() {
    pthread_mutex_lock(&g_data_mtx);
    OverlayData d = g_data;
    pthread_mutex_unlock(&g_data_mtx);

    ImGui::SetNextWindowPos(ImVec2(20, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(300, 0), ImGuiCond_FirstUseEver);
    ImGui::Begin("SKRoot 功耗监控", &g_running, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize);

    // 功率
    ImVec4 pc = d.power_mw > 5000 ? ImVec4(1,.3f,.3f,1) : d.power_mw > 2000 ? ImVec4(1,.83f,.3f,1) : ImVec4(.3f,.9f,.3f,1);
    ImGui::TextColored(pc, "⚡");
    ImGui::SameLine();
    ImGui::Text(d.power_mw >= 1000 ? "%.2f W" : "%.0f mW", d.power_mw >= 1000 ? d.power_mw/1000 : d.power_mw);
    ImGui::SameLine(0,16); ImGui::Text("🔋 %d%%", d.bat_level);
    if (d.bat_temp > 0) { ImGui::SameLine(0,16); ImGui::Text("🌡%.1f°C", d.bat_temp/10.0); }
    ImGui::TextColored(ImVec4(.6f,.6f,.6f,1), "%s", status_cn(d.bat_status));
    ImGui::Separator();

    // CPU
    ImGui::TextColored(ImVec4(.5f,.8f,.75f,1), "CPU %.1f%%", d.cpu_total);
    if (d.cpu_core_count > 0) {
        ImGui::SameLine(); ImGui::Text("[");
        for (int i = 0; i < d.cpu_core_count; i++) {
            ImGui::SameLine(0, 2); ImGui::Text("%.0f", d.cpu_cores[i]);
        }
        ImGui::SameLine(); ImGui::Text("]");
    }
    if (d.gpu_pct >= 0) { ImGui::SameLine(0,16); ImGui::TextColored(ImVec4(.8f,.6f,.85f,1), "GPU %.1f%%", d.gpu_pct); }
    ImGui::Separator();

    // 前台
    const char* app = d.fg_app[0] ? (strrchr(d.fg_app,'.') ? strrchr(d.fg_app,'.')+1 : d.fg_app) : "--";
    ImGui::Text("📱 %s", app);
    if (d.fg_cpu > 0 || d.fg_mem > 0) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(.5f,.5f,.5f,1), "CPU %.1f%% %dM", d.fg_cpu, d.fg_mem);
    }
    ImGui::End();
}

int main() {
    install_signal_handlers();
    LOGI("overlay starting, pid=%d", getpid());
    LOGI("checking dlopen libgui.so...");
    auto test_libgui = dlopen("/system/lib64/libgui.so", RTLD_LAZY);
    LOGI("dlopen libgui.so: %p", (void*)test_libgui);
    if (test_libgui) dlclose(test_libgui);
    auto test_libutils = dlopen("/system/lib64/libutils.so", RTLD_LAZY);
    LOGI("dlopen libutils.so: %p", (void*)test_libutils);
    if (test_libutils) dlclose(test_libutils);

    auto di = android::ANativeWindowCreator::GetDisplayInfo();
    int sw = di.width > 0 ? di.width : 1080;
    int sh = di.height > 0 ? di.height : 2400;
    LOGI("display: %dx%d (raw: %dx%d, orient=%d)", sw, sh, di.width, di.height, di.orientation);

    auto* win = android::ANativeWindowCreator::Create("SKRootOverlay", sw, sh);
    if (!win) { LOGE("ANativeWindow failed"); return 1; }
    LOGI("ANativeWindow created: %p", win);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui::GetStyle().ScaleAllSizes(sw / 540.0f);
    ImGui::GetIO().DisplaySize = ImVec2((float)sw, (float)sh);

    VulkanGraphics vk;
    if (!vk.Init(win, sw, sh)) { LOGE("Vulkan init failed"); return 1; }
    LOGI("Vulkan initialized");

    ImGui_ImplAndroid_Init(win);

    pthread_t tid;
    pthread_create(&tid, nullptr, data_thread, nullptr);

    LOGI("entering render loop at %d FPS", g_fps);

    while (g_running) {
        usleep(1000000 / g_fps);
        vk.NewFrame();
        ImGui_ImplAndroid_NewFrame();
        ImGui::NewFrame();
        DrawUI();
        ImGui::Render();
        vk.Render(ImGui::GetDrawData());
    }

    LOGI("overlay shutting down");

    g_running = false;
    pthread_join(tid, nullptr);
    vk.Shutdown();
    ImGui_ImplAndroid_Shutdown();
    ImGui::DestroyContext();
    android::ANativeWindowCreator::Destroy(win);
    return 0;
}
