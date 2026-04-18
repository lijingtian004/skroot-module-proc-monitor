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
    LOGE("CRASH: signal %d at %p", sig, info->si_addr);
    _exit(1);
}

static int g_port = 10273;
static int g_fps = 60;
static bool g_running = true;
static int g_screen_w = 1080, g_screen_h = 2400;
static float g_scale_x = 1.0f, g_scale_y = 1.0f;
static int g_touch_fd = -1;

// ImGui 窗口边界（用于触摸过滤）
static float g_win_x = 0, g_win_y = 0, g_win_w = 0, g_win_h = 0;
static bool g_was_touching_window = false;

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
    o[0]=0; char n[64]; snprintf(n,sizeof(n),"\"%s\"",k);
    const char* p=strstr(j,n); if(!p) return;
    p=strchr(p+strlen(n),'\"'); if(!p) return; p++;
    const char* e=strchr(p,'\"'); if(!e) return;
    int l=(int)(e-p); if(l>=sz) l=sz-1;
    memcpy(o,p,l); o[l]=0;
}
static std::string http_post(const char* host, int port, const char* path) {
    std::string r; int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0) return r;
    struct sockaddr_in a{}; a.sin_family=AF_INET; a.sin_port=htons(port);
    inet_pton(AF_INET,host,&a.sin_addr);
    struct timeval tv{.tv_sec=1,.tv_usec=0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    if(connect(fd,(sockaddr*)&a,sizeof(a))<0){close(fd);return r;}
    char req[256]; int len=snprintf(req,sizeof(req),"POST %s HTTP/1.0\r\nHost: %s\r\nContent-Length: 0\r\n\r\n",path,host);
    send(fd,req,len,0); char buf[4096]; int n;
    while((n=recv(fd,buf,sizeof(buf)-1,0))>0){buf[n]=0;r+=buf;}
    close(fd); auto pos=r.find("\r\n\r\n"); if(pos!=std::string::npos) r=r.substr(pos+4);
    return r;
}
static void fetch_data() {
    static int pc=0;
    if(pc++%30==0){FILE* f=fopen("/data/adb/skroot_webui_port","r");
    if(!f) f=fopen("/data/local/tmp/skroot_webui_port","r");
    if(f){int p=0;if(fscanf(f,"%d",&p)==1&&p>0)g_port=p;fclose(f);}}
    std::string resp=http_post("127.0.0.1",g_port,"/api/overlay");
    if(resp.empty()) return;
    const char* c=resp.c_str();
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
static void* data_thread(void*){while(g_running){fetch_data();usleep(2000000);}return nullptr;}

// ====== 触摸 ======
static bool checkTouch(int fd) {
    uint8_t* bits=nullptr; ssize_t bs=0;
    bool s=false,x=false,y=false; struct input_absinfo ai{};
    while(true){int r=ioctl(fd,EVIOCGBIT(EV_ABS,bs),bits);if(r<bs)break;bs=r+16;bits=(uint8_t*)realloc(bits,bs*2);}
    if(!bits) return false;
    for(int j=0;j<bs;j++) for(int k=0;k<8;k++) if(bits[j]&(1<<k)){
        int code=j*8+k; if(ioctl(fd,EVIOCGABS(code),&ai)==0){
            if(code==ABS_MT_SLOT) s=true; if(code==ABS_MT_POSITION_X) x=true; if(code==ABS_MT_POSITION_Y) y=true;}}
    free(bits); return s&&x&&y;
}
static int findTouch() {
    char p[64]; for(int i=0;i<=15;i++){
        snprintf(p,sizeof(p),"/dev/input/event%d",i); int fd=open(p,O_RDWR); if(fd<0) continue;
        if(!checkTouch(fd)){close(fd);continue;}
        struct input_absinfo xi{},yi{}; ioctl(fd,EVIOCGABS(ABS_MT_POSITION_X),&xi); ioctl(fd,EVIOCGABS(ABS_MT_POSITION_Y),&yi);
        if(xi.maximum<=0||yi.maximum<=0){close(fd);continue;}
        g_scale_x=(float)g_screen_w/(float)xi.maximum; g_scale_y=(float)g_screen_h/(float)yi.maximum;
        LOGI("touch: %s x[0-%d] y[0-%d]",p,xi.maximum,yi.maximum); return fd;}
    return -1;
}
static void* touch_thread(void*) {
    sleep(2); g_touch_fd=findTouch();
    if(g_touch_fd<0){LOGE("no touch");return nullptr;}
    LOGI("touch fd=%d",g_touch_fd);
    struct input_event evs[64]; int cx=0,cy=0,tid=-1; bool touching=false;
    ImGuiIO& io=ImGui::GetIO();
    while(g_running) {
        ssize_t n=read(g_touch_fd,evs,sizeof(evs)); if(n<=0){usleep(8000);continue;}
        size_t cnt=n/sizeof(struct input_event);
        for(size_t i=0;i<cnt;i++){
            auto& e=evs[i];
            if(e.type==EV_ABS){
                if(e.code==ABS_MT_POSITION_X) cx=e.value;
                else if(e.code==ABS_MT_POSITION_Y) cy=e.value;
                else if(e.code==ABS_MT_TRACKING_ID){
                    if(e.value>=0&&tid<0){touching=true;}
                    else if(e.value<0&&tid>=0){touching=false;io.AddMouseButtonEvent(0,false);}
                    tid=e.value;}
            }
            if(e.type==EV_SYN&&e.code==SYN_REPORT){
                float fx=cx*g_scale_x, fy=cy*g_scale_y;
                // 关键：只有触摸在窗口区域内 或 正在拖拽窗口时，才喂给 ImGui
                bool in_window = (fx>=g_win_x && fx<=g_win_x+g_win_w && fy>=g_win_y && fy<=g_win_y+g_win_h);
                if(touching && (in_window || g_was_touching_window)) {
                    if(!g_was_touching_window && in_window) {
                        io.AddMouseButtonEvent(0, true);
                        g_was_touching_window = true;
                    }
                    io.AddMousePosEvent(fx, fy);
                } else if(!touching && g_was_touching_window) {
                    io.AddMouseButtonEvent(0, false);
                    g_was_touching_window = false;
                }
            }
        }
    }
    close(g_touch_fd); return nullptr;
}

// ====== UI ======
static void DrawUI() {
    pthread_mutex_lock(&g_data_mtx);
    OverlayData d = g_data;
    pthread_mutex_unlock(&g_data_mtx);

    ImGuiIO& io = ImGui::GetIO();
    float sw = io.DisplaySize.x, sh = io.DisplaySize.y;
    float margin = sw * 0.02f;
    ImGui::SetNextWindowPos(ImVec2(margin, margin), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(sw * 0.5f, 0), ImGuiCond_FirstUseEver);

    // 圆角半透明风格
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 16.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 12));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.08f, 0.08f, 0.12f, 0.85f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.3f, 0.3f, 0.4f, 0.5f));
    ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.25f, 0.55f, 0.95f, 0.6f));

    ImGui::Begin("##SKRootMonitor", &g_running,
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar);

    // 记录窗口位置给触摸线程
    g_win_x = ImGui::GetWindowPos().x;
    g_win_y = ImGui::GetWindowPos().y;
    g_win_w = ImGui::GetWindowSize().x;
    g_win_h = ImGui::GetWindowSize().y;

    // 标题
    ImGui::TextColored(ImVec4(0.3f, 0.7f, 1.0f, 1.0f), "⚡ SKRoot 功耗监控");
    ImGui::Spacing();

    // 功率卡片
    ImVec4 pc = d.power_mw>5000 ? ImVec4(1,.4f,.4f,1) : d.power_mw>2000 ? ImVec4(1,.85f,.4f,1) : ImVec4(.4f,.95f,.4f,1);
    ImGui::TextColored(pc, "%.0f mW", d.power_mw);
    ImGui::SameLine(0, 20);
    ImGui::TextColored(ImVec4(.8f,.8f,.8f,1), "🔋 %d%%", d.bat_level);
    if(d.bat_temp>0) {
        ImGui::SameLine(0, 16);
        ImGui::TextColored(ImVec4(.9f,.7f,.5f,1), "🌡%.1f°", d.bat_temp/10.0);
    }

    // 状态行
    ImGui::TextColored(ImVec4(.5f,.5f,.55f,1), "%s", d.bat_status[0] ? d.bat_status : "--");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // CPU/GPU 行
    ImGui::TextColored(ImVec4(.5f,.85f,.75f,1), "CPU");
    ImGui::SameLine(60);
    ImGui::Text("%.1f%%", d.cpu_total);
    if(d.gpu_pct>=0) {
        ImGui::SameLine(0, 20);
        ImGui::TextColored(ImVec4(.8f,.6f,.9f,1), "GPU");
        ImGui::SameLine(ImGui::GetCursorPosX()+20);
        ImGui::Text("%.1f%%", d.gpu_pct);
    }

    // 核心详情（紧凑一行）
    if(d.cpu_core_count>0) {
        ImGui::TextColored(ImVec4(.4f,.4f,.45f,1), "核");
        ImGui::SameLine(30);
        for(int i=0;i<d.cpu_core_count;i++){
            if(i>0) { ImGui::SameLine(0, 4); ImGui::TextColored(ImVec4(.3f,.3f,.35f,1), "|"); ImGui::SameLine(0, 4); }
            ImGui::Text("%.0f", d.cpu_cores[i]);
        }
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // 前台应用
    const char* app = d.fg_app[0]?(strrchr(d.fg_app,'.')?strrchr(d.fg_app,'.')+1:d.fg_app):"--";
    ImGui::TextColored(ImVec4(.9f,.9f,.9f,1), "📱 %s", app);
    if(d.fg_cpu>0||d.fg_mem>0) {
        ImGui::SameLine(0, 16);
        ImGui::TextColored(ImVec4(.5f,.5f,.55f,1), "%.1f%% %dM", d.fg_cpu, d.fg_mem);
    }

    ImGui::PopStyleColor(3);
    ImGui::PopStyleVar(2);
    ImGui::End();
}

// ====== MAIN ======
int main() {
    g_logfp = fopen("/data/adb/overlay.log", "w");
    if(g_logfp) dup2(fileno(g_logfp), STDERR_FILENO);
    struct sigaction sa{}; sa.sa_sigaction=sig_handler; sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,nullptr); sigaction(SIGABRT,&sa,nullptr); sigaction(SIGBUS,&sa,nullptr);
    LOGI("=== pid=%d ===", getpid());

    auto di = android::ANativeWindowCreator::GetDisplayInfo();
    g_screen_w = di.width>0?di.width:1080;
    g_screen_h = di.height>0?di.height:2400;
    LOGI("display: %dx%d orient=%d", g_screen_w, g_screen_h, di.orientation);

    auto* win = android::ANativeWindowCreator::Create("SKRootOverlay", g_screen_w, g_screen_h);
    if(!win){LOGE("window failed");return 1;}
    LOGI("window=%p", win);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    // 自定义深色主题
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.ScaleAllSizes(g_screen_w / 540.0f);
    style.Colors[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.08f, 0.12f, 1.0f);
    style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.12f, 0.3f, 0.6f, 1.0f);
    style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.08f, 0.08f, 0.12f, 0.6f);

    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2((float)g_screen_w, (float)g_screen_h);
    io.FontGlobalScale = g_screen_w / 540.0f;

    VulkanGraphics vk;
    if(!vk.Init(win, g_screen_w, g_screen_h)){LOGE("Vulkan failed");return 1;}
    LOGI("Vulkan OK %d FPS", g_fps);
    ImGui_ImplAndroid_Init(win);

    pthread_t dt, tt;
    pthread_create(&dt, nullptr, data_thread, nullptr);
    pthread_create(&tt, nullptr, touch_thread, nullptr);

    while(g_running) {
        usleep(1000000/g_fps);
        vk.NewFrame();
        ImGui_ImplAndroid_NewFrame();
        ImGui::NewFrame();
        DrawUI();
        ImGui::Render();
        vk.Render(ImGui::GetDrawData());
    }
    g_running = false;
    pthread_join(dt, nullptr);
    vk.Shutdown();
    ImGui_ImplAndroid_Shutdown();
    ImGui::DestroyContext();
    android::ANativeWindowCreator::Destroy(win);
    if(g_logfp) fclose(g_logfp);
    return 0;
}
