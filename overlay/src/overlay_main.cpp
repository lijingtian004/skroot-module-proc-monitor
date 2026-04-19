#include <android/native_window.h>
#include <android/native_window_jni.h>
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
#include <algorithm>
#include <sys/stat.h>

#define LOG_TAG "SKRootUI"
static FILE* g_logfp = nullptr;
#define LOGI(...) do { __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); if(g_logfp) { fprintf(g_logfp, "[I] " __VA_ARGS__); fprintf(g_logfp, "\n"); fflush(g_logfp); } } while(0)
#define LOGE(...) do { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); if(g_logfp) { fprintf(g_logfp, "[E] " __VA_ARGS__); fprintf(g_logfp, "\n"); fflush(g_logfp); } } while(0)

static bool g_running = true;
static int g_port = 10273;
static int g_screen_w = 1080, g_screen_h = 2400;
static ANativeWindow* g_win = nullptr;

// ====== 配置 ======
static int g_fetch_interval_us = 5000000;  // 默认5秒
static bool g_fast_mode = false;  // 快速刷新模式
static int g_overlay_style = 0;  // 0=当前样式(黑色半透明), 1=透明样式

// ====== 数据 ======
struct OverlayData {
    double cpu_total = 0;
    double cpu_cores[8] = {};  // 8核心
    int cpu_core_count = 0;
    double gpu_pct = -1;
    double power_mw = 0;
    int bat_level = -1;
    int bat_temp = 0;
    char fg_app[128] = {};
    double fg_cpu = 0;
    int fg_mem = 0;
    int fps = 0;  // 本地计算
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
static int jarr(const char* j, const char* key, double* out, int max) {
    char n[64]; snprintf(n,sizeof(n),"\"%s\"",key);
    const char* p=strstr(j,n); if(!p) return 0;
    p=strchr(p,'['); if(!p) return 0; p++;
    int cnt=0;
    while(cnt<max&&*p&&*p!=']'){while(*p==' '||*p==',')p++;out[cnt++]=atof(p);while(*p&&*p!=','&&*p!=']')p++;}
    return cnt;
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
    close(fd); auto pos=r.find("\r\n\r\n");
    if(pos!=std::string::npos) r=r.substr(pos+4); return r;
}
// ====== FPS 获取 ======
static double getSysFSFPS() {
    const char* paths[] = {
        "/sys/class/drm/sde-crtc-0/measured_fps",
        "/sys/class/drm/card0-DSI-1/measured_fps",
        "/sys/class/graphics/fb0/measured_fps",
        "/sys/class/drm/card0/device/graphics/fb0/measured_fps",
        "/d/dri/0/clk_dump_fps",
        nullptr
    };
    
    for (int i = 0; paths[i] != nullptr; i++) {
        FILE* f = fopen(paths[i], "r");
        if (f) {
            char buf[256];
            if (fgets(buf, sizeof(buf), f)) {
                // 格式1: "fps: 58.1 duration:500000 frame_count:30"
                char* p = strstr(buf, "fps:");
                if (p) {
                    p += 4;
                    while (*p == ' ' || *p == '\t') p++;
                    double fps = atof(p);
                    fclose(f);
                    if (fps > 0 && fps <= 200) return fps;
                }
                // 格式2: 直接是数字
                double fps = atof(buf);
                fclose(f);
                if (fps > 0 && fps <= 200) return fps;
            } else {
                fclose(f);
            }
        }
    }
    return 0;
}

// 从dumpsys获取FPS
static double getDumpsysFPS() {
    FILE* pipe = popen("dumpsys SurfaceFlinger --latency 2>/dev/null | head -20", "r");
    if (!pipe) return 0;
    
    char buf[1024];
    std::string output;
    while (fgets(buf, sizeof(buf), pipe)) {
        output += buf;
    }
    pclose(pipe);
    
    // 解析刷新率（第一行通常是刷新周期，如16666666表示60Hz）
    if (!output.empty()) {
        long long refresh_ns = atoll(output.c_str());
        if (refresh_ns > 0) {
            return 1000000000.0 / refresh_ns;
        }
    }
    return 0;
}

static void fetch_data() {
    // 读取配置 - 每次都读取
    {
        FILE* cfg = fopen("/data/adb/overlay_config", "r");
        if (cfg) {
            char line[256];
            while (fgets(line, sizeof(line), cfg)) {
                if (strncmp(line, "fast_mode=", 10) == 0) {
                    int val = atoi(line + 10);
                    bool new_mode = (val != 0);
                    if (new_mode != g_fast_mode) {
                        g_fast_mode = new_mode;
                        g_fetch_interval_us = g_fast_mode ? 2000000 : 5000000;
                        LOGI("config: fast_mode=%d", g_fast_mode);
                    }
                } else if (strncmp(line, "overlay_style=", 14) == 0) {
                    int new_style = atoi(line + 14);
                    if (new_style != g_overlay_style) {
                        g_overlay_style = new_style;
                        LOGI("config: overlay_style=%d", g_overlay_style);
                    }
                }
            }
            fclose(cfg);
        }
    }
    
    static int pc=0;
    if(pc++%30==0){FILE* f=fopen("/data/adb/skroot_webui_port","r");
    if(!f)f=fopen("/data/local/tmp/skroot_webui_port","r");
    if(f){int p=0;if(fscanf(f,"%d",&p)==1&&p>0)g_port=p;fclose(f);}}
    std::string resp=http_post("127.0.0.1",g_port,"/api/overlay");
    if(resp.empty()) return; const char* c=resp.c_str();
    pthread_mutex_lock(&g_data_mtx);
    g_data.cpu_total=jnum(c,"cpu_total"); g_data.gpu_pct=jnum(c,"gpu_pct");
    g_data.power_mw=jnum(c,"power_mw"); g_data.bat_level=(int)jnum(c,"bat_level");
    g_data.bat_temp=(int)jnum(c,"bat_temp"); g_data.fg_cpu=jnum(c,"fg_cpu");
    g_data.fg_mem=(int)jnum(c,"fg_mem");
    jstr(c,"fg_app",g_data.fg_app,128);
    g_data.cpu_core_count=jarr(c,"cpu_cores",g_data.cpu_cores,8);
    // FPS从系统获取
    double sys_fps = getSysFSFPS();
    if (sys_fps > 0) {
        g_data.fps = (int)sys_fps;
    } else {
        double dumpsys_fps = getDumpsysFPS();
        if (dumpsys_fps > 0) {
            g_data.fps = (int)dumpsys_fps;
        }
    }
    pthread_mutex_unlock(&g_data_mtx);
}
static void* data_thread(void*){
    while(g_running){
        fetch_data();
        // 短循环sleep，使配置变化更快生效
        for(int i = 0; i < g_fetch_interval_us / 500000 && g_running; i++) {
            usleep(500000);  // 500ms
        }
    }
    return nullptr;
}

// ====== 7x10 bitmap font (更清晰的字体) ======
static const uint8_t FONT_7x10[][10] = {
    {0x1C,0x22,0x22,0x3E,0x22,0x22,0x22,0x22,0x00,0x00}, // A
    {0x3C,0x22,0x22,0x3C,0x22,0x22,0x22,0x3C,0x00,0x00}, // B
    {0x1C,0x22,0x20,0x20,0x20,0x20,0x22,0x1C,0x00,0x00}, // C
    {0x3C,0x22,0x22,0x22,0x22,0x22,0x22,0x3C,0x00,0x00}, // D
    {0x3E,0x20,0x20,0x3C,0x20,0x20,0x20,0x3E,0x00,0x00}, // E
    {0x3E,0x20,0x20,0x3C,0x20,0x20,0x20,0x20,0x00,0x00}, // F
    {0x1C,0x22,0x20,0x2E,0x22,0x22,0x22,0x1E,0x00,0x00}, // G
    {0x22,0x22,0x22,0x3E,0x22,0x22,0x22,0x22,0x00,0x00}, // H
    {0x1C,0x08,0x08,0x08,0x08,0x08,0x08,0x1C,0x00,0x00}, // I
    {0x0E,0x04,0x04,0x04,0x04,0x04,0x24,0x18,0x00,0x00}, // J
    {0x22,0x24,0x28,0x30,0x28,0x24,0x22,0x22,0x00,0x00}, // K
    {0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x3E,0x00,0x00}, // L
    {0x22,0x36,0x2A,0x2A,0x22,0x22,0x22,0x22,0x00,0x00}, // M
    {0x22,0x32,0x2A,0x26,0x22,0x22,0x22,0x22,0x00,0x00}, // N
    {0x1C,0x22,0x22,0x22,0x22,0x22,0x22,0x1C,0x00,0x00}, // O
    {0x3C,0x22,0x22,0x3C,0x20,0x20,0x20,0x20,0x00,0x00}, // P
    {0x1C,0x22,0x22,0x22,0x2A,0x24,0x22,0x1D,0x00,0x00}, // Q
    {0x3C,0x22,0x22,0x3C,0x28,0x24,0x22,0x22,0x00,0x00}, // R
    {0x1C,0x22,0x20,0x1C,0x02,0x02,0x22,0x1C,0x00,0x00}, // S
    {0x3E,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x00,0x00}, // T
    {0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x1C,0x00,0x00}, // U
    {0x22,0x22,0x22,0x22,0x14,0x14,0x08,0x08,0x00,0x00}, // V
    {0x22,0x22,0x22,0x2A,0x2A,0x36,0x22,0x22,0x00,0x00}, // W
    {0x22,0x22,0x14,0x08,0x08,0x14,0x22,0x22,0x00,0x00}, // X
    {0x22,0x22,0x14,0x08,0x08,0x08,0x08,0x08,0x00,0x00}, // Y
    {0x3E,0x02,0x04,0x08,0x10,0x20,0x20,0x3E,0x00,0x00}, // Z
    {0x1C,0x22,0x26,0x2A,0x32,0x22,0x22,0x1C,0x00,0x00}, // 0
    {0x08,0x18,0x08,0x08,0x08,0x08,0x08,0x1C,0x00,0x00}, // 1
    {0x1C,0x22,0x02,0x0C,0x10,0x20,0x20,0x3E,0x00,0x00}, // 2
    {0x1C,0x22,0x02,0x0C,0x02,0x02,0x22,0x1C,0x00,0x00}, // 3
    {0x04,0x0C,0x14,0x24,0x3E,0x04,0x04,0x04,0x00,0x00}, // 4
    {0x3E,0x20,0x3C,0x02,0x02,0x02,0x22,0x1C,0x00,0x00}, // 5
    {0x0C,0x10,0x20,0x3C,0x22,0x22,0x22,0x1C,0x00,0x00}, // 6
    {0x3E,0x02,0x04,0x08,0x10,0x10,0x10,0x10,0x00,0x00}, // 7
    {0x1C,0x22,0x22,0x1C,0x22,0x22,0x22,0x1C,0x00,0x00}, // 8
    {0x1C,0x22,0x22,0x1E,0x02,0x04,0x08,0x10,0x00,0x00}, // 9
    {0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x08,0x00,0x00}, // .
    {0x00,0x00,0x00,0x3E,0x00,0x00,0x00,0x00,0x00,0x00}, // -
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, // space
    {0x08,0x08,0x08,0x08,0x08,0x00,0x08,0x08,0x00,0x00}, // !
    {0x04,0x08,0x10,0x20,0x10,0x08,0x04,0x00,0x00,0x00}, // <
    {0x10,0x08,0x04,0x02,0x04,0x08,0x10,0x00,0x00,0x00}, // >
    {0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,0x08,0x10,0x00}, // ,
    {0x22,0x22,0x04,0x08,0x10,0x22,0x22,0x00,0x00,0x00}, // %
    {0x08,0x14,0x14,0x08,0x00,0x00,0x00,0x00,0x00,0x00}, // degree symbol
};

static int char_to_idx(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a'; // reuse uppercase
    if (c >= '0' && c <= '9') return 26 + c - '0';
    if (c == '.') return 36;
    if (c == '-') return 37;
    if (c == ' ') return 38;
    if (c == '!') return 39;
    if (c == '<') return 40;
    if (c == '>') return 41;
    if (c == ',') return 42;
    if (c == '%') return 43;
    if (c == 0xC2) return 44; // ° from UTF-8 °C  (first byte)
    return 38; // space for unknown
}

// ====== 像素绘制 ======
static inline uint32_t make_rgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
    return (uint32_t)r | ((uint32_t)g << 8) | ((uint32_t)b << 16) | ((uint32_t)a << 24);
}

static inline void put_pixel(uint32_t* pixels, int stride, int x, int y, int w, int h, uint32_t color) {
    if (x >= 0 && x < w && y >= 0 && y < h) {
        uint8_t a = (color >> 24) & 0xFF;
        if (a == 255) {
            pixels[y * stride + x] = color;
        } else if (a > 0) {
            uint32_t dst = pixels[y * stride + x];
            uint8_t da = (dst >> 24) & 0xFF;
            uint8_t dr = dst & 0xFF, dg = (dst>>8)&0xFF, db = (dst>>16)&0xFF;
            float fa = a / 255.0f;
            float fd = da / 255.0f;
            // Premultiplied alpha blending
            uint8_t nr = (uint8_t)((color&0xFF) * fa + dr * (1.0f - fa));
            uint8_t ng = (uint8_t)(((color>>8)&0xFF) * fa + dg * (1.0f - fa));
            uint8_t nb = (uint8_t)(((color>>16)&0xFF) * fa + db * (1.0f - fa));
            uint8_t na = (uint8_t)((a + da * (1.0f - fa)) * 255);
            pixels[y * stride + x] = (uint32_t)nr | ((uint32_t)ng << 8) | ((uint32_t)nb << 16) | ((uint32_t)na << 24);
        }
    }
}

static void fill_rect(uint32_t* pixels, int stride, int w, int h, int rx, int ry, int rw, int rh, uint32_t color) {
    for (int y = ry; y < ry + rh && y < h; y++)
        for (int x = rx; x < rx + rw && x < w; x++)
            put_pixel(pixels, stride, x, y, w, h, color);
}

static void fill_rounded_rect(uint32_t* pixels, int stride, int w, int h, int rx, int ry, int rw, int rh, int radius, uint32_t color) {
    // Fill center + edges
    fill_rect(pixels, stride, w, h, rx + radius, ry, rw - 2*radius, rh, color); // center horizontal
    fill_rect(pixels, stride, w, h, rx, ry + radius, radius, rh - 2*radius, color); // left
    fill_rect(pixels, stride, w, h, rx + rw - radius, ry + radius, radius, rh - 2*radius, color); // right
    // Corners
    for (int dy = 0; dy < radius; dy++) {
        for (int dx = 0; dx < radius; dx++) {
            float dist = sqrtf((float)(dx*dx + dy*dy));
            if (dist <= radius) {
                put_pixel(pixels, stride, rx + radius - 1 - dx, ry + radius - 1 - dy, w, h, color);
                put_pixel(pixels, stride, rx + rw - radius + dx, ry + radius - 1 - dy, w, h, color);
                put_pixel(pixels, stride, rx + radius - 1 - dx, ry + rh - radius + dy, w, h, color);
                put_pixel(pixels, stride, rx + rw - radius + dx, ry + rh - radius + dy, w, h, color);
            }
        }
    }
}

static void draw_char(uint32_t* pixels, int stride, int w, int h, int x, int y, char c, uint32_t color, int scale) {
    int idx = char_to_idx(c);
    if (idx < 0 || idx >= 45) return;
    // 7x10字体：每行7位（使用高7位），共10行
    for (int row = 0; row < 10; row++) {
        uint8_t bits = FONT_7x10[idx][row];
        for (int col = 0; col < 7; col++) {
            if (bits & (0x40 >> col)) {  // 使用高7位
                for (int sy = 0; sy < scale; sy++)
                    for (int sx = 0; sx < scale; sx++)
                        put_pixel(pixels, stride, x + col*scale + sx, y + row*scale + sy, w, h, color);
            }
        }
    }
}

static void draw_text(uint32_t* pixels, int stride, int w, int h, int x, int y, const char* text, uint32_t color, int scale) {
    int cx = x;
    while (*text) {
        if (*text == 0xC2 && *(text+1) == (char)0xB0) {
            // °C degree symbol
            draw_char(pixels, stride, w, h, cx, y, 0xC2, color, scale);
            cx += 8 * scale;  // 7x10字体宽度为8*scale
            text += 2;
            // Draw 'C'
            draw_char(pixels, stride, w, h, cx, y, 'C', color, scale);
            cx += 8 * scale;
            text++; // already at 'C', skip
            continue;
        }
        draw_char(pixels, stride, w, h, cx, y, *text, color, scale);
        cx += 8 * scale;  // 7x10字体宽度为8*scale
        text++;
    }
}

static int text_width(const char* text, int scale) {
    int w = 0;
    while (*text) { w += 8 * scale; text++; }  // 7x10字体宽度为8*scale
    return w;
}

// ====== 窗口拖动 ======
static float g_win_x = 50, g_win_y = 100;
static int g_touch_fd = -1;
static float g_scale_x = 1.0f, g_scale_y = 1.0f;
static bool g_dragging = false;
static float g_last_sx = 0, g_last_sy = 0; // 增量拖动：上一次触摸位置
static bool g_skip_first_syn = false; // 跳过DOWN后的第一个SYN

static bool checkTouch(int fd) {
    uint8_t bits[64] = {0};  // 固定大小缓冲区
    bool s=false,x=false,y=false; struct input_absinfo ai{};
    int r=ioctl(fd,EVIOCGBIT(EV_ABS,sizeof(bits)),bits);
    if(r<=0)return false;
    for(int j=0;j<r;j++)for(int k=0;k<8;k++)if(bits[j]&(1<<k)){
        int c=j*8+k;if(ioctl(fd,EVIOCGABS(c),&ai)==0){
            if(c==ABS_MT_SLOT)s=true;if(c==ABS_MT_POSITION_X)x=true;if(c==ABS_MT_POSITION_Y)y=true;}}
    return s&&x&&y;
}
static int findTouch() {
    char p[64];for(int i=0;i<=15;i++){snprintf(p,sizeof(p),"/dev/input/event%d",i);
    int fd=open(p,O_RDWR);if(fd<0)continue;if(!checkTouch(fd)){close(fd);continue;}
    struct input_absinfo xi{},yi{};ioctl(fd,EVIOCGABS(ABS_MT_POSITION_X),&xi);ioctl(fd,EVIOCGABS(ABS_MT_POSITION_Y),&yi);
    if(xi.maximum<=0||yi.maximum<=0){close(fd);continue;}
    g_scale_x=(float)g_screen_w/(float)xi.maximum;g_scale_y=(float)g_screen_h/(float)yi.maximum;
    LOGI("touch: %s x[0-%d] y[0-%d]",p,xi.maximum,yi.maximum);return fd;}return -1;
}
static void* touch_thread(void*) {
    sleep(2); g_touch_fd=findTouch();
    if(g_touch_fd<0){LOGE("no touch");return nullptr;}
    LOGI("touch fd=%d",g_touch_fd);
    struct input_event evs[64];int cx=0,cy=0,tid=-1;
    bool touching=false,dragging=false;
    int touch_start_ms=0;
    while(g_running){ssize_t n=read(g_touch_fd,evs,sizeof(evs));
    if(n<=0){usleep(8000);continue;}
    // 超时保护：3秒无UP事件则强制重置
    if(touching){
        struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
        int now_ms=ts.tv_sec*1000+ts.tv_nsec/1000000;
        if(now_ms-touch_start_ms>3000){LOGI("TOUCH TIMEOUT force reset");touching=false;dragging=false;tid=-1;}
    }
    size_t cnt=n/sizeof(struct input_event);
    for(size_t i=0;i<cnt;i++){auto& e=evs[i];
        if(e.type==EV_ABS){
            if(e.code==ABS_MT_POSITION_X)cx=e.value;
            else if(e.code==ABS_MT_POSITION_Y)cy=e.value;
            else if(e.code==ABS_MT_TRACKING_ID){
                if(e.value>=0){
                    // DOWN: 处理新触摸（包括UP丢失的恢复）
                    if(tid>=0){LOGI("MISSED UP! old_tid=%d force reset",tid);touching=false;dragging=false;}
                    float sx=cx*g_scale_x, sy=cy*g_scale_y;
                    int ww=g_screen_w*0.35f;
                    int padding=ww*0.025f;
                    int font_scale=ww/140;
                    if(font_scale<2)font_scale=2;
                    int big_fs=font_scale*2;
                    if(big_fs<4)big_fs=4;
                    // 窗口高度计算（与render_frame一致）
                    int big_lh=11*big_fs;
                    int top_h=big_lh;  // 大字高度
                    int bot_h=11*font_scale+font_scale;  // 小字
                    int content_h=top_h+bot_h+padding;
                    int wh=content_h+2*padding;
                    int hit_pad=20;
                    bool inside=(sx>=g_win_x-hit_pad && sx<=g_win_x+ww+hit_pad && sy>=g_win_y-hit_pad && sy<=g_win_y+wh+hit_pad);
                    LOGI("TOUCH DOWN raw(%d,%d) screen(%.0f,%.0f) win(%.0f,%.0f %dx%d) inside=%d",
                         cx,cy,sx,sy,g_win_x,g_win_y,ww,wh,inside?1:0);
                    if(inside){
                        dragging=true;
                        g_last_sx=sx; g_last_sy=sy; // 记录初始位置，窗口不跳
                        g_skip_first_syn=true; // 跳过第一个SYN，防止驱动发来的坐标偏移
                    } else {
                    dragging=false;
                    g_skip_first_syn=false; // 窗口外DOWN，不跳过任何SYN
                }
                touching=true;
                    {struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);touch_start_ms=ts.tv_sec*1000+ts.tv_nsec/1000000;}
                }
                else if(tid>=0){
                    // UP: 抬起
                    LOGI("TOUCH UP touching=%d dragging=%d",touching?1:0,dragging?1:0);
                    touching=false;dragging=false;g_skip_first_syn=false;
                }
                tid=e.value;
            }
        } // end EV_ABS
        if(e.type==EV_SYN&&e.code==SYN_REPORT&&touching&&dragging){
            float sx=cx*g_scale_x, sy=cy*g_scale_y;
            if(g_skip_first_syn){g_skip_first_syn=false;g_last_sx=sx;g_last_sy=sy;LOGI("SKIP first SYN");continue;}
            // 检查手指是否还在窗口区域内（含外扩padding）
            int ww=g_screen_w*0.35f;
            int padding=ww*0.025f;
            int font_scale=ww/140;if(font_scale<2)font_scale=2;
            int big_fs=font_scale*2;if(big_fs<4)big_fs=4;
            // 窗口高度计算（与render_frame一致）
            int big_lh=11*big_fs;
            int top_h=big_lh;  // 大字高度
            int bot_h=11*font_scale+font_scale;  // 小字
            int content_h=top_h+bot_h+padding;
            int wh=content_h+2*padding;
            int hit_pad=20;
            if(!(sx>=g_win_x-hit_pad && sx<=g_win_x+ww+hit_pad && sy>=g_win_y-hit_pad && sy<=g_win_y+wh+hit_pad)){
                LOGI("DRAG OUTSIDE -> stop dragging");
                dragging=false;continue;
            }
            float old_x=g_win_x, old_y=g_win_y;
            // 增量拖动：只移动差值，窗口不跳
            g_win_x += sx - g_last_sx;
            g_win_y += sy - g_last_sy;
            g_last_sx = sx; g_last_sy = sy;
            if(g_win_x<0)g_win_x=0; if(g_win_y<0)g_win_y=0;
            if(g_win_x>g_screen_w-200)g_win_x=g_screen_w-200;
            if(g_win_y>g_screen_h-100)g_win_y=g_screen_h-100;
            // 只在实际移动时打印
            if(g_win_x!=old_x||g_win_y!=old_y)
                LOGI("DRAG -> (%.0f,%.0f)",g_win_x,g_win_y);
        }}}close(g_touch_fd);return nullptr;
}

// ====== 渲染 ======
// 背景：alpha越高越透明；其他元素：标准RGBA（alpha=255不透明）
static void draw_vbar(uint32_t* px, int stride, int w, int h,
                      int bx, int by, int bw, int bh, float pct, uint32_t color) {
    // 竖向柱状图：从下往上填充
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    // 背景（alpha=255 完全不透明）
    fill_rounded_rect(px, stride, w, h, bx, by, bw, bh, 2, make_rgba(40,40,40,255));
    // 填充（从底部起）
    int fill_h = (int)(bh * pct / 100.0f);
    if (fill_h > 1) {
        int fy = by + bh - fill_h;
        // alpha=255 完全不透明
        uint32_t bar_color = pct > 80 ? make_rgba(255,100,80,255) :
                             pct > 50 ? make_rgba(255,215,75,255) : make_rgba(color & 0xFF, (color>>8)&0xFF, (color>>16)&0xFF, 255);
        fill_rounded_rect(px, stride, w, h, bx+1, fy, bw-2, fill_h, 2, bar_color);
    }
}

static void render_frame() {
    if (!g_win) return;
    ANativeWindow_Buffer buf;
    if (ANativeWindow_lock(g_win, &buf, nullptr) != 0) return;

    int w = buf.width, h = buf.height;
    static bool logged_buf=false; if(!logged_buf){LOGI("buf=%dx%d screen=%dx%d",w,h,g_screen_w,g_screen_h);logged_buf=true;}
    uint32_t* px = (uint32_t*)buf.bits;
    int stride = buf.stride;
    
    pthread_mutex_lock(&g_data_mtx);
    OverlayData d = g_data;
    pthread_mutex_unlock(&g_data_mtx);

    // 窗口参数
    int wx = (int)g_win_x, wy = (int)g_win_y;
    int ww = g_screen_w * 0.35f;  // 缩小到40%
    int pad = ww * 0.025f;
    int gap = pad / 2;
    int col_w = (ww - 2*pad - 2*gap) / 3;
    int fs = ww / 140;  // 7x10字体基础缩放
    if (fs < 2) fs = 2;
    int big_fs = fs * 2;  // 大字体
    if (big_fs < 4) big_fs = 4;
    int lh = 11 * fs;  // 7x10字体行高
    int big_lh = 11 * big_fs;

    int top_h = big_lh;
    int bot_h = lh + fs;
    int content_h = top_h + bot_h + pad;
    int wh = content_h + 2 * pad;
    
    // 清空整个buffer为透明黑色
    memset(px, 0, stride * h * 4);

    // 根据样式绘制背景
    // 注意：只有背景是 alpha越高越透明
    uint32_t bg_color;
    if (g_overlay_style == 1) {
        // 透明样式：alpha高=更透明
        bg_color = make_rgba(20, 20, 25, 200);  // alpha=200，高透明度
    } else {
        // 默认样式：alpha低=更不透明
        bg_color = make_rgba(0, 0, 0, 60);      // alpha=60，低透明度
    }
    fill_rounded_rect(px, stride, w, h, wx, wy, ww, wh, ww*0.02f, bg_color);

    uint32_t white = make_rgba(255,255,255,255);      // alpha=255 完全不透明
    uint32_t dim = make_rgba(180,180,180,200);        // 轻微透明
    uint32_t accent = make_rgba(100,200,255,255);     // alpha=255 完全不透明

    // === 左列：电量 + 电池温度 ===
    int col1x = wx + pad;
    // 上块 - 电量大字
    int ty = wy + pad;
    char bat_str[16];
    if (d.bat_level >= 0) snprintf(bat_str, sizeof(bat_str), "%d%%", d.bat_level);
    else snprintf(bat_str, sizeof(bat_str), "--%%");
    uint32_t bat_color = d.bat_level > 20 ? accent : make_rgba(255,100,80,255);
    int bw = text_width(bat_str, big_fs);
    draw_text(px, stride, w, h, col1x + (col_w - bw)/2, ty, bat_str, bat_color, big_fs);
    // 电量标签（移除BATT文字，只保留数值）

    // 下块 - 电池温度
    int by = wy + pad + top_h + pad;
    char bt_str[16]; snprintf(bt_str, sizeof(bt_str), "%.1fC", d.bat_temp/10.0f);
    uint32_t bt_color = d.bat_temp > 450 ? make_rgba(255,100,80,255) : d.bat_temp > 380 ? make_rgba(255,215,75,255) : white;
    bw = text_width(bt_str, fs);
    draw_text(px, stride, w, h, col1x + (col_w - bw)/2, by, bt_str, bt_color, fs);
    // 温度标签（移除TEMP文字）

    // === 中列：帧数 + 功率 ===
    int col2x = wx + pad + col_w + gap;
    // 上块 - FPS
    ty = wy + pad;
    char fps_str[16]; snprintf(fps_str, sizeof(fps_str), "%d", d.fps);
    uint32_t fps_color = d.fps >= 25 ? make_rgba(100,255,130,255) : d.fps >= 15 ? make_rgba(255,215,75,255) : make_rgba(255,100,80,255);
    bw = text_width(fps_str, big_fs);
    draw_text(px, stride, w, h, col2x + (col_w - bw)/2, ty, fps_str, fps_color, big_fs);
    // FPS标签（移除FPS文字）

    // 下块 - 功率（统一用W单位）
    by = wy + pad + top_h + pad;
    char pwr_str[16];
    snprintf(pwr_str, sizeof(pwr_str), "%.1fW", d.power_mw/1000.0);
    uint32_t pwr_color = d.power_mw > 5000 ? make_rgba(255,100,80,255) : d.power_mw > 2000 ? make_rgba(255,215,75,255) : white;
    draw_text(px, stride, w, h, col2x + (col_w - text_width(pwr_str,fs))/2, by, pwr_str, pwr_color, fs);
    // 功率标签（移除POWER文字）

    // === 右列：CPU 8核心柱状图 + CPU使用率 ===
    int col3x = wx + pad + (col_w + gap) * 2;
    // 上块 - 8个竖向柱状图（高度与其他列上块一致）
    ty = wy + pad;
    int bar_gap = 3;
    int bar_w = (col_w - bar_gap * 7) / 8;  // 8根柱子
    int bar_h = top_h;  // 柱状图高度等于上块高度
    for (int i = 0; i < 8 && i < d.cpu_core_count; i++) {
        int bx = col3x + i * (bar_w + bar_gap);
        draw_vbar(px, stride, w, h, bx, ty, bar_w, bar_h, d.cpu_cores[i], accent);
    }
    // CPU标签（移除CPU文字）

    // 下块 - CPU 使用率
    by = wy + pad + top_h + pad;
    char ct_str[16]; snprintf(ct_str, sizeof(ct_str), "%.0f%%", d.cpu_total);
    draw_text(px, stride, w, h, col3x + (col_w - text_width(ct_str,fs))/2, by, ct_str, white, fs);
    // USAGE标签（移除USAGE文字）

    ANativeWindow_unlockAndPost(g_win);
}

// ====== MAIN ======
int main() {
    g_logfp = fopen("/data/adb/overlay.log", "w");
    if(g_logfp) dup2(fileno(g_logfp), STDERR_FILENO);
    LOGI("=== custom UI pid=%d ===", getpid());

    auto di = android::ANativeWindowCreator::GetDisplayInfo();
    g_screen_w = di.width>0?di.width:1080;
    g_screen_h = di.height>0?di.height:2400;
    LOGI("display: %dx%d", g_screen_w, g_screen_h);

    g_win = android::ANativeWindowCreator::Create("SKRootOverlay", g_screen_w, g_screen_h);
    if (!g_win) { LOGE("window failed"); return 1; }
    LOGI("window=%p", g_win);

    ANativeWindow_setBuffersGeometry(g_win, g_screen_w, g_screen_h, WINDOW_FORMAT_RGBA_8888);

    pthread_t dt, tt;
    pthread_create(&dt, nullptr, data_thread, nullptr);
    pthread_create(&tt, nullptr, touch_thread, nullptr);

    LOGI("rendering at 30 FPS");
    
    while (g_running) {
        render_frame();
        usleep(33333); // ~30 FPS
    }

    g_running = false;
    pthread_join(dt, nullptr);
    android::ANativeWindowCreator::Destroy(g_win);
    if (g_logfp) fclose(g_logfp);
    return 0;
}
