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

#define LOG_TAG "SKRootUI"
static FILE* g_logfp = nullptr;
#define LOGI(...) do { __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); if(g_logfp) { fprintf(g_logfp, "[I] " __VA_ARGS__); fprintf(g_logfp, "\n"); fflush(g_logfp); } } while(0)
#define LOGE(...) do { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); if(g_logfp) { fprintf(g_logfp, "[E] " __VA_ARGS__); fprintf(g_logfp, "\n"); fflush(g_logfp); } } while(0)

static bool g_running = true;
static int g_port = 10273;
static int g_screen_w = 1080, g_screen_h = 2400;
static ANativeWindow* g_win = nullptr;

// ====== 数据 ======
struct OverlayData {
    double cpu_total = 0;
    double gpu_pct = -1;
    double power_mw = 0;
    int bat_level = -1;
    int bat_temp = 0;
    char fg_app[128] = {};
    double fg_cpu = 0;
    int fg_mem = 0;
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
    close(fd); auto pos=r.find("\r\n\r\n");
    if(pos!=std::string::npos) r=r.substr(pos+4); return r;
}
static void fetch_data() {
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
    pthread_mutex_unlock(&g_data_mtx);
}
static void* data_thread(void*){while(g_running){fetch_data();usleep(2000000);}return nullptr;}

// ====== 5x7 bitmap font ======
static const uint8_t FONT_5x7[][7] = {
    {0x0E,0x11,0x11,0x1F,0x11,0x11,0x11}, // A
    {0x1E,0x11,0x11,0x1E,0x11,0x11,0x1E}, // B
    {0x0E,0x11,0x10,0x10,0x10,0x11,0x0E}, // C
    {0x1E,0x11,0x11,0x11,0x11,0x11,0x1E}, // D
    {0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F}, // E
    {0x1F,0x10,0x10,0x1E,0x10,0x10,0x10}, // F
    {0x0E,0x11,0x10,0x17,0x11,0x11,0x0F}, // G
    {0x11,0x11,0x11,0x1F,0x11,0x11,0x11}, // H
    {0x0E,0x04,0x04,0x04,0x04,0x04,0x0E}, // I
    {0x07,0x02,0x02,0x02,0x02,0x12,0x0C}, // J
    {0x11,0x12,0x14,0x18,0x14,0x12,0x11}, // K
    {0x10,0x10,0x10,0x10,0x10,0x10,0x1F}, // L
    {0x11,0x1B,0x15,0x15,0x11,0x11,0x11}, // M
    {0x11,0x19,0x15,0x13,0x11,0x11,0x11}, // N
    {0x0E,0x11,0x11,0x11,0x11,0x11,0x0E}, // O
    {0x1E,0x11,0x11,0x1E,0x10,0x10,0x10}, // P
    {0x0E,0x11,0x11,0x11,0x15,0x12,0x0D}, // Q
    {0x1E,0x11,0x11,0x1E,0x14,0x12,0x11}, // R
    {0x0E,0x11,0x10,0x0E,0x01,0x11,0x0E}, // S
    {0x1F,0x04,0x04,0x04,0x04,0x04,0x04}, // T
    {0x11,0x11,0x11,0x11,0x11,0x11,0x0E}, // U
    {0x11,0x11,0x11,0x11,0x11,0x0A,0x04}, // V
    {0x11,0x11,0x11,0x15,0x15,0x1B,0x11}, // W
    {0x11,0x11,0x0A,0x04,0x0A,0x11,0x11}, // X
    {0x11,0x11,0x0A,0x04,0x04,0x04,0x04}, // Y
    {0x1F,0x01,0x02,0x04,0x08,0x10,0x1F}, // Z
    {0x0E,0x11,0x13,0x15,0x19,0x11,0x0E}, // 0
    {0x04,0x0C,0x04,0x04,0x04,0x04,0x0E}, // 1
    {0x0E,0x11,0x01,0x06,0x08,0x10,0x1F}, // 2
    {0x0E,0x11,0x01,0x06,0x01,0x11,0x0E}, // 3
    {0x02,0x06,0x0A,0x12,0x1F,0x02,0x02}, // 4
    {0x1F,0x10,0x1E,0x01,0x01,0x11,0x0E}, // 5
    {0x06,0x08,0x10,0x1E,0x11,0x11,0x0E}, // 6
    {0x1F,0x01,0x02,0x04,0x08,0x08,0x08}, // 7
    {0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E}, // 8
    {0x0E,0x11,0x11,0x0F,0x01,0x02,0x0C}, // 9
    {0x00,0x00,0x00,0x00,0x00,0x04,0x00}, // .
    {0x00,0x00,0x00,0x1F,0x00,0x00,0x00}, // -
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00}, // space
    {0x04,0x04,0x04,0x04,0x04,0x00,0x04}, // !
    {0x02,0x04,0x08,0x10,0x08,0x04,0x02}, // <
    {0x08,0x04,0x02,0x01,0x02,0x04,0x08}, // >
    {0x00,0x00,0x00,0x00,0x03,0x02,0x02}, // ,
    {0x0A,0x0A,0x04,0x04,0x0E,0x04,0x04}, // %
    {0x04,0x0A,0x0A,0x0A,0x0A,0x04,0x00}, // degree symbol (for °C)
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
            uint8_t dr = dst & 0xFF, dg = (dst>>8)&0xFF, db = (dst>>16)&0xFF;
            float fa = a / 255.0f;
            pixels[y * stride + x] = make_rgba(
                (uint8_t)(dr + (((int)(color&0xFF) - dr) * fa)),
                (uint8_t)(dg + (((int)((color>>8)&0xFF) - dg) * fa)),
                (uint8_t)(db + (((int)((color>>16)&0xFF) - db) * fa)),
                255);
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
    for (int row = 0; row < 7; row++) {
        uint8_t bits = FONT_5x7[idx][row];
        for (int col = 0; col < 5; col++) {
            if (bits & (0x10 >> col)) {
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
            cx += 6 * scale;
            text += 2;
            // Draw 'C'
            draw_char(pixels, stride, w, h, cx, y, 'C', color, scale);
            cx += 6 * scale;
            text++; // already at 'C', skip
            continue;
        }
        draw_char(pixels, stride, w, h, cx, y, *text, color, scale);
        cx += 6 * scale;
        text++;
    }
}

static int text_width(const char* text, int scale) {
    int w = 0;
    while (*text) { w += 6 * scale; text++; }
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
    uint8_t* bits=nullptr; ssize_t bs=0;
    bool s=false,x=false,y=false; struct input_absinfo ai{};
    while(true){int r=ioctl(fd,EVIOCGBIT(EV_ABS,bs),bits);if(r<bs)break;bs=r+16;bits=(uint8_t*)realloc(bits,bs*2);}
    if(!bits)return false;
    for(int j=0;j<bs;j++)for(int k=0;k<8;k++)if(bits[j]&(1<<k)){
        int c=j*8+k;if(ioctl(fd,EVIOCGABS(c),&ai)==0){
            if(c==ABS_MT_SLOT)s=true;if(c==ABS_MT_POSITION_X)x=true;if(c==ABS_MT_POSITION_Y)y=true;}}
    free(bits);return s&&x&&y;
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
                    int ww=g_screen_w*0.45f;
                    int padding=ww*0.05f;
                    int font_scale=ww/140;
                    if(font_scale<2)font_scale=2;
                    int line_h=8*font_scale;
                    int wh=padding*2+line_h*6+8*font_scale;
                    int hit_pad=20; // 触摸区域比渲染大20px
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
static void render_frame() {
    if (!g_win) return;
    ANativeWindow_Buffer buf;
    if (ANativeWindow_lock(g_win, &buf, nullptr) != 0) return;

    int w = buf.width, h = buf.height;
    static bool logged_buf=false; if(!logged_buf){LOGI("buf=%dx%d screen=%dx%d",w,h,g_screen_w,g_screen_h);logged_buf=true;}
    uint32_t* pixels = (uint32_t*)buf.bits;
    int stride = buf.stride;

    // 清屏（全透明）
    memset(pixels, 0, stride * h * 4);

    // 读数据
    pthread_mutex_lock(&g_data_mtx);
    OverlayData d = g_data;
    pthread_mutex_unlock(&g_data_mtx);

    // 窗口参数（必须和触摸线程用同一变量计算，保持一致）
    int wx = (int)g_win_x, wy = (int)g_win_y;
    int ww = g_screen_w * 0.45f;  // 45% 屏幕宽度
    int padding = ww * 0.05f;
    int font_scale = ww / 140; // 字体缩放
    if (font_scale < 2) font_scale = 2;
    int line_h = 8 * font_scale;
    int content_w = ww - 2 * padding;

    // 计算窗口高度
    int wh = padding * 2 + line_h * 6 + 8 * font_scale; // 6行 + padding

    // 背景：黑色半透明圆角矩形
    uint32_t bg_color = make_rgba(0, 0, 0, 204); // 80% 黑
    fill_rounded_rect(pixels, stride, w, h, wx, wy, ww, wh, ww * 0.03f, bg_color);

    // 内容绘制
    int cy = wy + padding;
    int lx = wx + padding; // 标签左对齐

    uint32_t white = make_rgba(255, 255, 255, 255);
    uint32_t dim = make_rgba(180, 180, 180, 200);

    // CPU 行
    draw_text(pixels, stride, w, h, lx, cy, "CPU", white, font_scale);
    cy += line_h + font_scale * 2;

    // GPU 行
    draw_text(pixels, stride, w, h, lx, cy, "GPU", white, font_scale);
    // 百分比 - 大号
    int big_scale = font_scale * 2;
    char gpu_str[16]; snprintf(gpu_str, sizeof(gpu_str), "%.0f%%", d.gpu_pct);
    int gpu_w = text_width(gpu_str, big_scale);
    int rx = wx + ww - padding - gpu_w; // 右对齐
    uint32_t gpu_color = d.gpu_pct > 80 ? make_rgba(255,100,80,255) : d.gpu_pct > 50 ? make_rgba(255,215,75,255) : make_rgba(100,255,130,255);
    draw_text(pixels, stride, w, h, rx, cy - font_scale/2, gpu_str, gpu_color, big_scale);

    // 进度条
    cy += line_h + font_scale * 2;
    int bar_x = lx, bar_y = cy;
    int bar_w = content_w, bar_h = font_scale * 2;
    fill_rounded_rect(pixels, stride, w, h, bar_x, bar_y, bar_w, bar_h, bar_h/2, make_rgba(50,50,50,180));
    int fill = (int)((d.gpu_pct / 100.0f) * bar_w);
    if (fill > 2) fill_rounded_rect(pixels, stride, w, h, bar_x, bar_y, fill, bar_h, bar_h/2, gpu_color);
    cy += bar_h + font_scale * 3;

    // 频率行 - 大号
    float cpu_freq = 300 + (2438 - 300) * (d.cpu_total / 100.0);
    if (cpu_freq >= 1000) {
        char freq_str[32]; snprintf(freq_str, sizeof(freq_str), "%.0fMHz", cpu_freq);
        draw_text(pixels, stride, w, h, lx, cy, freq_str, white, big_scale);
    } else {
        draw_text(pixels, stride, w, h, lx, cy, "0MHz", dim, big_scale);
    }
    cy += line_h * 2 + font_scale * 2;

    // 温度行
    float temp = d.bat_temp / 10.0f;
    char temp_str[32]; snprintf(temp_str, sizeof(temp_str), "%.1fC", temp);
    uint32_t temp_color = temp > 45 ? make_rgba(255,100,80,255) : temp > 38 ? make_rgba(255,215,75,255) : white;
    draw_text(pixels, stride, w, h, lx, cy, temp_str, temp_color, font_scale);

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
