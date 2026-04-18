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
#include <linux/input.h>
#include <fcntl.h>

#define LOG_TAG "SKRootOverlay"
static FILE* g_logfp = nullptr;
#define LOGI(...) do { __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); if(g_logfp) { fprintf(g_logfp, "[I] " __VA_ARGS__); fprintf(g_logfp, "\n"); fflush(g_logfp); } } while(0)
#define LOGE(...) do { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); if(g_logfp) { fprintf(g_logfp, "[E] " __VA_ARGS__); fprintf(g_logfp, "\n"); fflush(g_logfp); } } while(0)

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

static double jnum(const char* j, const char* k) {
    char n[64]; snprintf(n, sizeof(n), "\"%s\"", k);
    const char* p = strstr(j, n); if (!p) return 0;
    p = strchr(p + strlen(n), ':'); if (!p) return 0;
    return atof(p + 1);
}
static void jstr(const char* j, const char* k, char* o, int sz) {
    o[0] = 0; char n[64]; snprintf(n, sizeof(n), "\"%s\"", k);
    const char* p = strstr(j, n); if (!p) return;
    p = strchr(p + strlen(n), '\"'); if (!p) return; p++;
    const char* e = strchr(p, '\"'); if (!e) return;
    int l = (int)(e - p); if (l >= sz) l = sz - 1;
    memcpy(o, p, l); o[l] = 0;
}

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
    while ((n = recv(fd, buf, sizeof(buf) - 1, 0)) > 0) { buf[n] = 0; result += buf; }
    close(fd);
    auto pos = result.find("\r\n\r\n");
    if (pos != std::string::npos) result = result.substr(pos + 4);
    return result;
}

static void fetch_data() {
    static int pc = 0;
    if (pc++ % 30 == 0) {
        FILE* f = fopen("/data/adb/modules/skroot_module_proc_monitor/webui_port", "r");
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

// ====== 触摸输入 ======
static int g_touch_fd = -1;
static int g_screen_w = 1080, g_screen_h = 2400;
static float g_scale_x = 1.0f, g_scale_y = 1.0f;

static bool checkDeviceIsTouch(int fd) {
    uint8_t* bits = nullptr;
    ssize_t bits_size = 0;
    bool has_slot = false, has_x = false, has_y = false;
    struct input_absinfo abs_i{};
    while (true) {
        int res = ioctl(fd, EVIOCGBIT(EV_ABS, bits_size), bits);
        if (res < bits_size) break;
        bits_size = res + 16;
        bits = (uint8_t*)realloc(bits, bits_size * 2);
    }
    if (!bits) return false;
    for (int j = 0; j < bits_size; j++) {
        for (int k = 0; k < 8; k++) {
            if (bits[j] & (1 << k)) {
                int code = j * 8 + k;
                if (ioctl(fd, EVIOCGABS(code), &abs_i) == 0) {
                    if (code == ABS_MT_SLOT) has_slot = true;
                    if (code == ABS_MT_POSITION_X) has_x = true;
                    if (code == ABS_MT_POSITION_Y) has_y = true;
                }
            }
        }
    }
    free(bits);
    return has_slot && has_x && has_y;
}

static int find_touch_device() {
    char path[64];
    for (int i = 0; i <= 15; i++) {
        snprintf(path, sizeof(path), "/dev/input/event%d", i);
        int fd = open(path, O_RDWR);
        if (fd < 0) continue;
        if (!checkDeviceIsTouch(fd)) { close(fd); continue; }
        struct input_absinfo xi{}, yi{};
        ioctl(fd, EVIOCGABS(ABS_MT_POSITION_X), &xi);
        ioctl(fd, EVIOCGABS(ABS_MT_POSITION_Y), &yi);
        if (xi.maximum <= 0 || yi.maximum <= 0) { close(fd); continue; }
        g_scale_x = (float)g_screen_w / (float)xi.maximum;
        g_scale_y = (float)g_screen_h / (float)yi.maximum;
        LOGI("touch: %s x[0-%d] y[0-%d] scale=%.3f,%.3f", path, xi.maximum, yi.maximum, g_scale_x, g_scale_y);
        return fd;
    }
    return -1;
}

static void* touch_thread(void*) {
    sleep(2);
    g_touch_fd = find_touch_device();
    if (g_touch_fd < 0) { LOGE("no touch device found"); return nullptr; }
    LOGI("touch thread started fd=%d", g_touch_fd);

    struct input_event events[64];
    int cur_x = 0, cur_y = 0, tracking_id = -1;
    bool touching = false;
    ImGuiIO& io = ImGui::GetIO();

    while (g_running) {
        ssize_t n = read(g_touch_fd, events, sizeof(events));
        if (n <= 0) { usleep(8000); continue; }
        size_t count = n / sizeof(struct input_event);
        for (size_t i = 0; i < count; i++) {
            auto& ev = events[i];
            if (ev.type == EV_ABS) {
                if (ev.code == ABS_MT_POSITION_X) cur_x = ev.value;
                else if (ev.code == ABS_MT_POSITION_Y) cur_y = ev.value;
                else if (ev.code == ABS_MT_TRACKING_ID) {
                    if (ev.value >= 0 && tracking_id < 0) {
                        touching = true;
                        io.AddMouseButtonEvent(0, true);
                    } else if (ev.value < 0 && tracking_id >= 0) {
                        touching = false;
                        io.AddMouseButtonEvent(0, false);
                    }
                    tracking_id = ev.value;
                }
            }
            if (ev.type == EV_SYN && ev.code == SYN_REPORT && touching) {
                io.AddMousePosEvent(cur_x * g_scale_x, cur_y * g_scale_y);
            }
        }
    }
    close(g_touch_fd);
    return nullptr;
}

// ====== UI ======
static void DrawUI() {
    pthread_mutex_lock(&g_data_mtx);
    OverlayData d = g_data;
    pthread_mutex_unlock(&g_data_mtx);

    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.02f, io.DisplaySize.y * 0.02f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x * 0.7f, 0), ImGuiCond_FirstUseEver);
    ImGui::Begin("SKRoot 功耗监控", &g_running, ImGuiWindowFlags_NoCollapse);

    ImVec4 pc = d.power_mw > 5000 ? ImVec4(1,.3f,.3f,1) : d.power_mw > 2000 ? ImVec4(1,.83f,.3f,1) : ImVec4(.3f,.9f,.3f,1);
    ImGui::TextColored(pc, "⚡");
    ImGui::SameLine();
    ImGui::Text(d.power_mw >= 1000 ? "%.2f W" : "%.0f mW", d.power_mw >= 1000 ? d.power_mw/1000 : d.power_mw);
    ImGui::SameLine(0,16); ImGui::Text("🔋 %d%%", d.bat_level);
    if (d.bat_temp > 0) { ImGui::SameLine(0,16); ImGui::Text("🌡%.1f°C", d.bat_temp/10.0); }
    ImGui::TextColored(ImVec4(.6f,.6f,.6f,1), "%s", status_cn(d.bat_status));
    ImGui::Separator();
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
    const char* app = d.fg_app[0] ? (strrchr(d.fg_app,'.') ? strrchr(d.fg_app,'.')+1 : d.fg_app) : "--";
    ImGui::Text("📱 %s", app);
    if (d.fg_cpu > 0 || d.fg_mem > 0) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(.5f,.5f,.5f,1), "CPU %.1f%% %dM", d.fg_cpu, d.fg_mem);
    }
    ImGui::End();
}

// ====== MAIN ======
int main() {
    g_logfp = fopen("/data/adb/modules/skroot_module_proc_monitor/overlay.log", "w");
    if (g_logfp) { dup2(fileno(g_logfp), STDERR_FILENO); }
    install_signal_handlers();
    LOGI("=== overlay starting, pid=%d, uid=%d ===", getpid(), getuid());

    auto di = android::ANativeWindowCreator::GetDisplayInfo();
    int sw = di.width > 0 ? di.width : 1080;
    int sh = di.height > 0 ? di.height : 2400;
    g_screen_w = sw; g_screen_h = sh;
    LOGI("display: %dx%d orient=%d", sw, sh, di.orientation);

    auto* win = android::ANativeWindowCreator::Create("SKRootOverlay", sw, sh);
    if (!win) { LOGE("ANativeWindow failed"); return 1; }
    int actual_w = ANativeWindow_getWidth(win);
    int actual_h = ANativeWindow_getHeight(win);
    LOGI("ANativeWindow created: %p actual=%dx%d requested=%dx%d", win, actual_w, actual_h, sw, sh);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    float scale = sw / 540.0f;
    ImGui::GetStyle().ScaleAllSizes(scale);
    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2((float)sw, (float)sh);
    io.FontGlobalScale = scale;

    VulkanGraphics vk;
    if (!vk.Init(win, sw, sh)) { LOGE("Vulkan init failed"); return 1; }
    LOGI("Vulkan initialized");
    ImGui_ImplAndroid_Init(win);

    pthread_t tid, touch_tid;
    pthread_create(&tid, nullptr, data_thread, nullptr);
    pthread_create(&touch_tid, nullptr, touch_thread, nullptr);
    LOGI("render loop %d FPS", g_fps);

    while (g_running) {
        usleep(1000000 / g_fps);
        vk.NewFrame();
        ImGui_ImplAndroid_NewFrame();
        ImGui::NewFrame();
        DrawUI();
        ImGui::Render();
        vk.Render(ImGui::GetDrawData());
    }
    g_running = false;
    pthread_join(tid, nullptr);
    vk.Shutdown();
    ImGui_ImplAndroid_Shutdown();
    ImGui::DestroyContext();
    android::ANativeWindowCreator::Destroy(win);
    if (g_logfp) fclose(g_logfp);
    return 0;
}
