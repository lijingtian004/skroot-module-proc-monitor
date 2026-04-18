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
    LOGE("CRASH: signal %d addr %p", sig, info->si_addr);
    _exit(1);
}

static int g_port = 10273;
static int g_fps = 60;
static bool g_running = true;
static int g_screen_w = 1080, g_screen_h = 2400;
static int g_orientation = 0;
static float g_scale_x = 1.0f, g_scale_y = 1.0f;
static int g_touch_fd = -1;
// 窗口 bounds（由 UI 更新，触摸线程读取）
static float g_win_x = 0, g_win_y = 0, g_win_w = 0, g_win_h = 0;
static bool g_was_inside = false; // 上次触摸是否在窗口内

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
    std::string result; int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return result;
    struct sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    struct timeval tv{.tv_sec=1,.tv_usec=0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return result; }
    char req[256]; int len = snprintf(req, sizeof(req), "POST %s HTTP/1.0\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", path, host);
    send(fd, req, len, 0); char buf[4096]; int n;
    while ((n = recv(fd, buf, sizeof(buf)-1, 0)) > 0) { buf[n]=0; result+=buf; }
    close(fd); auto pos = result.find("\r\n\r\n");
    if (pos != std::string::npos) result = result.substr(pos+4);
    return result;
}
static void fetch_data() {
    static int pc = 0;
    if (pc++ % 30 == 0) {
        FILE* f = fopen("/data/adb/skroot_webui_port", "r");
        if (!f) f = fopen("/data/local/tmp/skroot_webui_port", "r");
        if (f) { int p=0; if(fscanf(f,"%d",&p)==1&&p>0) g_port=p; fclose(f); }
    }
    std::string resp = http_post("127.0.0.1", g_port, "/api/overlay");
    if (resp.empty()) return; const char* c = resp.c_str();
    pthread_mutex_lock(&g_data_mtx);
    g_data.cpu_total=jnum(c,"cpu_total"); g_data.gpu_pct=jnum(c,"gpu_pct");
    g_data.power_mw=jnum(c,"power_mw"); g_data.bat_level=(int)jnum(c,"bat_level");
    g_data.bat_temp=(int)jnum(c,"bat_temp"); g_data.fg_cpu=jnum(c,"fg_cpu");
    g_data.fg_mem=(int)jnum(c,"fg_mem");
    jstr(c,"gpu_name",g_data.gpu_name,32); jstr(c,"bat_status",g_data.bat_status,32);
    jstr(c,"fg_app",g_data.fg_app,128);
    const char* ap=strstr(c,"\"cpu_cores\"");
    if(ap){ap=strchr(ap,'[');if(ap){ap++;g_data.cpu_core_count=0;
    while(*ap&&*ap!=']'&&g_data.cpu_core_count<16){while(*ap==' '||*ap==',')ap++;
    if(*ap==']')break;g_data.cpu_cores[g_data.cpu_core_count++]=atof(ap);
    while(*ap&&*ap!=','&&*ap!=']')ap++;}}}
    pthread_mutex_unlock(&g_data_mtx);
}
static void* data_thread(void*) { while(g_running){fetch_data();usleep(2000000);} return nullptr; }

// ====== 触摸 ======
static bool checkDeviceIsTouch(int fd) {
    uint8_t* bits = nullptr; ssize_t bits_size = 0;
    bool has_slot=false, has_x=false, has_y=false; struct input_absinfo ai{};
    while(true){int res=ioctl(fd,EVIOCGBIT(EV_ABS,bits_size),bits);if(res<bits_size)break;bits_size=res+16;bits=(uint8_t*)realloc(bits,bits_size*2);}
    if(!bits) return false;
    for(int j=0;j<bits_size;j++) for(int k=0;k<8;k++) if(bits[j]&(1<<k)){
        int code=j*8+k; if(ioctl(fd,EVIOCGABS(code),&ai)==0){
            if(code==ABS_MT_SLOT) has_slot=true; if(code==ABS_MT_POSITION_X) has_x=true; if(code==ABS_MT_POSITION_Y) has_y=true;}}
    free(bits); return has_slot&&has_x&&has_y;
}
static int find_touch_device() {
    char path[64];
    for(int i=0;i<=15;i++){snprintf(path,sizeof(path),"/dev/input/event%d",i);
    int fd=open(path,O_RDWR);if(fd<0)continue;if(!checkDeviceIsTouch(fd)){close(fd);continue;}
    struct input_absinfo xi{},yi{};ioctl(fd,EVIOCGABS(ABS_MT_POSITION_X),&xi);ioctl(fd,EVIOCGABS(ABS_MT_POSITION_Y),&yi);
    if(xi.maximum<=0||yi.maximum<=0){close(fd);continue;}
    g_scale_x=(float)g_screen_w/(float)xi.maximum; g_scale_y=(float)g_screen_h/(float)yi.maximum;
    LOGI("touch: %s x[0-%d] y[0-%d] scale=%.3f,%.3f",path,xi.maximum,yi.maximum,g_scale_x,g_scale_y);
    return fd;} return -1;
}
static void* touch_thread(void*) {
    sleep(2); g_touch_fd = find_touch_device();
    if(g_touch_fd<0){LOGE("no touch device");return nullptr;}
    LOGI("touch started fd=%d", g_touch_fd);
    struct input_event events[64]; int cur_x=0, cur_y=0, tracking_id=-1;
    bool touching=false, down_sent=false; ImGuiIO& io=ImGui::GetIO();
    while(g_running){
        ssize_t n=read(g_touch_fd,events,sizeof(events));
        if(n<=0){usleep(8000);continue;} size_t count=n/sizeof(struct input_event);
        for(size_t i=0;i<count;i++){auto& ev=events[i];
            if(ev.type==EV_ABS){
                if(ev.code==ABS_MT_POSITION_X) cur_x=ev.value;
                else if(ev.code==ABS_MT_POSITION_Y) cur_y=ev.value;
                else if(ev.code==ABS_MT_TRACKING_ID){
                    if(ev.value>=0&&tracking_id<0) touching=true;
                    else if(ev.value<0&&tracking_id>=0){
                        touching=false;
                        if(down_sent){io.AddMouseButtonEvent(0,false);down_sent=false;g_was_inside=false;}
                    } tracking_id=ev.value;
                }
            }
            if(ev.type==EV_SYN&&ev.code==SYN_REPORT&&touching){
                float sx=cur_x*g_scale_x, sy=cur_y*g_scale_y;
                // 只在窗口区域内生效
                bool inside = (sx>=g_win_x && sx<=g_win_x+g_win_w && sy>=g_win_y && sy<=g_win_y+g_win_h);
                if(inside){
                    if(!down_sent){io.AddMouseButtonEvent(0,true);down_sent=true;}
                    io.AddMousePosEvent(sx, sy);
                    g_was_inside = true;
                } else if(g_was_inside && down_sent){
                    // 从窗口内拖到窗口外 → 抬起，停止拖动
                    io.AddMouseButtonEvent(0, false);
                    down_sent = false;
                    g_was_inside = false;
                }
                // 窗口外的触摸完全忽略
            }
        }
    } close(g_touch_fd); return nullptr;
}

// ====== UI 配色 - 深色终端风 ======
namespace C {
    ImU32 bg          = IM_COL32(18, 18, 24, 220);
    ImU32 bg_header   = IM_COL32(30, 30, 42, 255);
    ImU32 border      = IM_COL32(50, 50, 70, 180);
    ImU32 text        = IM_COL32(220, 220, 230, 255);
    ImU32 text_dim    = IM_COL32(140, 140, 160, 255);
    ImU32 accent      = IM_COL32(100, 180, 255, 255);  // 电量蓝
    ImU32 power_low   = IM_COL32(80,  220, 120, 255);  // 绿
    ImU32 power_mid   = IM_COL32(255, 200, 60,  255);  // 黄
    ImU32 power_high  = IM_COL32(255, 80,  80,  255);  // 红
    ImU32 cpu_color   = IM_COL32(80,  200, 180, 255);  // 青
    ImU32 gpu_color   = IM_COL32(180, 140, 255, 255);  // 紫
    ImU32 bar_bg      = IM_COL32(40, 40, 55, 255);
}

static void DrawBar(ImDrawList* dl, ImVec2 pos, float w, float h, float pct, ImU32 color, float max_pct=100.0f) {
    dl->AddRectFilled(pos, ImVec2(pos.x+w, pos.y+h), C::bar_bg, h*0.4f);
    float fill = (pct / max_pct) * w;
    if (fill > 2.0f) dl->AddRectFilled(pos, ImVec2(pos.x+fill, pos.y+h), color, h*0.4f);
}

static void DrawUI() {
    pthread_mutex_lock(&g_data_mtx); OverlayData d = g_data; pthread_mutex_unlock(&g_data_mtx);
    ImGuiIO& io = ImGui::GetIO();
    float sw = io.DisplaySize.x, sh = io.DisplaySize.y;
    float pad = sw * 0.015f;
    float win_w = sw * 0.52f;
    float win_h = 0; // auto

    ImGui::SetNextWindowPos(ImVec2(pad, pad), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(win_w, 0), ImGuiCond_FirstUseEver);
    
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(18/255.f, 18/255.f, 24/255.f, 220/255.f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(50/255.f, 50/255.f, 70/255.f, 180/255.f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, sw * 0.015f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(sw*0.018f, sw*0.014f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(sw*0.008f, sw*0.006f));

    ImGui::Begin("##SKRoot", &g_running, ImGuiWindowFlags_NoCollapse);

    // 记录窗口 bounds 给触摸线程
    ImVec2 wp = ImGui::GetWindowPos();
    ImVec2 ws = ImGui::GetWindowSize();
    g_win_x = wp.x; g_win_y = wp.y; g_win_w = ws.x; g_win_h = ws.y;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    float line_h = ImGui::GetTextLineHeight();
    float bar_h = line_h * 0.6f;
    float content_w = ws.x - sw*0.036f;

    // ---- 标题 ----
    ImGui::TextColored(ImColor(C::accent), "⚡");
    ImGui::SameLine(0, sw*0.006f);
    ImGui::TextColored(ImColor(C::text), "SKRoot Monitor");
    ImGui::SameLine(sw*0.32f);
    ImGui::TextColored(ImColor(C::text_dim), "v2.9");
    ImGui::Spacing();

    // ---- 功率 + 电池 ----
    ImU32 pc = d.power_mw > 5000 ? C::power_high : d.power_mw > 2000 ? C::power_mid : C::power_low;
    ImGui::TextColored(ImColor(pc), "%s", d.power_mw >= 1000 ? "W" : "mW");
    ImGui::SameLine(0, sw*0.003f);
    ImGui::TextColored(ImColor(C::text), "%s%.1f",
        d.power_mw >= 1000 ? "" : "", d.power_mw >= 1000 ? d.power_mw/1000 : d.power_mw);
    ImGui::SameLine(0, sw*0.02f);
    ImGui::TextColored(ImColor(C::accent), "BAT");
    ImGui::SameLine(0, sw*0.003f);
    ImGui::TextColored(ImColor(C::text), "%d%%", d.bat_level);
    if(d.bat_temp > 0){
        ImGui::SameLine(0, sw*0.015f);
        ImGui::TextColored(ImColor(C::text_dim), "%.1f°C", d.bat_temp/10.0);
    }
    ImGui::Spacing();

    // ---- CPU ----
    float cpu_pct = (float)d.cpu_total;
    ImGui::TextColored(ImColor(C::cpu_color), "CPU");
    ImGui::SameLine(0, sw*0.012f);
    ImGui::TextColored(ImColor(C::text), "%.1f%%", cpu_pct);
    ImGui::SameLine(0, sw*0.01f);
    // 进度条
    ImVec2 bar_pos = ImGui::GetCursorScreenPos();
    DrawBar(dl, bar_pos, content_w * 0.5f, bar_h, cpu_pct, C::cpu_color);
    ImGui::Dummy(ImVec2(content_w * 0.5f, bar_h));
    
    // 核心数
    if(d.cpu_core_count > 0){
        ImGui::Indent(sw*0.025f);
        ImGui::TextColored(ImColor(C::text_dim), "cores");
        ImGui::SameLine(0, sw*0.005f);
        char cores_buf[128] = "";
        for(int i=0;i<d.cpu_core_count;i++){
            char tmp[16]; snprintf(tmp,sizeof(tmp),"%s%.0f", i?" | ":"", d.cpu_cores[i]);
            strcat(cores_buf, tmp);
        }
        ImGui::TextColored(ImColor(C::text_dim), "%s", cores_buf);
        ImGui::Unindent(sw*0.025f);
    }
    ImGui::Spacing();

    // ---- GPU ----
    if(d.gpu_pct >= 0){
        float gpu_pct = (float)d.gpu_pct;
        ImGui::TextColored(ImColor(C::gpu_color), "GPU");
        ImGui::SameLine(0, sw*0.012f);
        ImGui::TextColored(ImColor(C::text), "%.1f%%", gpu_pct);
        ImGui::SameLine(0, sw*0.01f);
        ImVec2 gp = ImGui::GetCursorScreenPos();
        DrawBar(dl, gp, content_w * 0.5f, bar_h, gpu_pct, C::gpu_color);
        ImGui::Dummy(ImVec2(content_w * 0.5f, bar_h));
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // ---- 前台 App ----
    const char* app = d.fg_app[0] ? (strrchr(d.fg_app,'.') ? strrchr(d.fg_app,'.')+1 : d.fg_app) : "--";
    ImGui::TextColored(ImColor(C::accent), "APP");
    ImGui::SameLine(0, sw*0.01f);
    ImGui::TextColored(ImColor(C::text), "%s", app);
    if(d.fg_cpu > 0 || d.fg_mem > 0){
        ImGui::SameLine(0, sw*0.015f);
        ImGui::TextColored(ImColor(C::text_dim), "%.0f%%  %dM", d.fg_cpu, d.fg_mem);
    }

    ImGui::End();
    ImGui::PopStyleVar(4);
    ImGui::PopStyleColor(2);
}

// ====== MAIN ======
int main() {
    g_logfp = fopen("/data/adb/overlay.log", "w");
    if(g_logfp) dup2(fileno(g_logfp), STDERR_FILENO);
    struct sigaction sa{}; sa.sa_sigaction=sig_handler; sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,nullptr); sigaction(SIGABRT,&sa,nullptr); sigaction(SIGBUS,&sa,nullptr);
    LOGI("=== overlay pid=%d ===", getpid());

    auto di = android::ANativeWindowCreator::GetDisplayInfo();
    g_screen_w = di.width>0?di.width:1080; g_screen_h = di.height>0?di.height:2400;
    g_orientation = di.orientation;
    LOGI("display: %dx%d orient=%d", g_screen_w, g_screen_h, g_orientation);

    auto* win = android::ANativeWindowCreator::Create("SKRootOverlay", g_screen_w, g_screen_h);
    if(!win){LOGE("ANativeWindow failed");return 1;}
    LOGI("window=%p", win);

    IMGUI_CHECKVERSION(); ImGui::CreateContext();
    ImGui::StyleColorsDark();
    float scale = g_screen_w / 540.0f;
    ImGui::GetStyle().ScaleAllSizes(scale);
    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2((float)g_screen_w, (float)g_screen_h);
    io.FontGlobalScale = scale;
    io.MouseDrawCursor = false;

    VulkanGraphics vk;
    if(!vk.Init(win, g_screen_w, g_screen_h)){LOGE("Vulkan failed");return 1;}
    LOGI("Vulkan OK %dFPS", g_fps);
    ImGui_ImplAndroid_Init(win);

    pthread_t dtid, ttid;
    pthread_create(&dtid, nullptr, data_thread, nullptr);
    pthread_create(&ttid, nullptr, touch_thread, nullptr);

    while(g_running){
        usleep(1000000/g_fps);
        vk.NewFrame(); ImGui_ImplAndroid_NewFrame(); ImGui::NewFrame();
        DrawUI(); ImGui::Render(); vk.Render(ImGui::GetDrawData());
    }
    g_running=false; pthread_join(dtid,nullptr);
    vk.Shutdown(); ImGui_ImplAndroid_Shutdown(); ImGui::DestroyContext();
    android::ANativeWindowCreator::Destroy(win);
    if(g_logfp) fclose(g_logfp); return 0;
}
