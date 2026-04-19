//
// module_proc_monitor.cpp — SKRoot Pro 进程行为监控模块
// 功能：/proc 持久扫描 + 可疑进程告警 + WebUI 仪表盘
//

#include <cstdio>
#include <sys/stat.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>

// Android logging
#ifdef ANDROID
#include <android/log.h>
#define LOG_TAG "ProcMonitor"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__)
#define LOGW(...) printf(__VA_ARGS__)
#define LOGE(...) printf(__VA_ARGS__)
#endif

#include "kernel_module_kit_umbrella.h"
#include "proc_scanner.h"

// ============ cJSON 前向声明 ============
// cJSON.cpp 会被编译到同一个 .so 中
typedef struct cJSON cJSON;
extern "C" {
    cJSON* cJSON_CreateArray();
    cJSON* cJSON_CreateObject();
    void   cJSON_Delete(cJSON* item);
    cJSON* cJSON_AddStringToObject(cJSON* object, const char* name, const char* string);
    cJSON* cJSON_AddNumberToObject(cJSON* object, const char* name, double number);
    cJSON* cJSON_AddItemToArray(cJSON* array, cJSON* item);
    cJSON* cJSON_AddItemToObject(cJSON* object, const char* name, cJSON* item);
    cJSON* cJSON_CreateNumber(double num);
    char*  cJSON_PrintUnformatted(const cJSON* item);
    void   cJSON_free(void* ptr);
}

// ============ JSON 构建辅助 ============

static std::string build_event_json(const std::vector<ProcEvent>& events) {
    cJSON* arr = cJSON_CreateArray();
    for (auto& ev : events) {
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "ts",   (double)ev.timestamp);
        cJSON_AddNumberToObject(obj, "type", (double)ev.type);
        cJSON_AddNumberToObject(obj, "pid",  (double)ev.pid);
        cJSON_AddNumberToObject(obj, "ppid", (double)ev.ppid);
        cJSON_AddNumberToObject(obj, "uid",  (double)ev.uid);
        cJSON_AddStringToObject(obj, "comm", ev.comm);
        cJSON_AddStringToObject(obj, "cmdline", ev.cmdline);
        if (ev.type == ProcEventType::ALERT) {
            cJSON_AddStringToObject(obj, "reason", ev.alert_reason);
        }
        cJSON_AddItemToArray(arr, obj);
    }
    char* raw = cJSON_PrintUnformatted(arr);
    std::string result(raw);
    cJSON_free(raw);
    cJSON_Delete(arr);
    return result;
}

static std::string build_procs_json(const std::vector<ProcInfo>& procs) {
    cJSON* arr = cJSON_CreateArray();
    for (auto& p : procs) {
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "pid",  (double)p.pid);
        cJSON_AddNumberToObject(obj, "ppid", (double)p.ppid);
        cJSON_AddNumberToObject(obj, "uid",  (double)p.uid);
        cJSON_AddStringToObject(obj, "comm", p.comm);
        cJSON_AddStringToObject(obj, "cmdline", p.cmdline);
        cJSON_AddNumberToObject(obj, "cpu_sec", p.cpu_usage_pct);
        cJSON_AddItemToArray(arr, obj);
    }
    char* raw = cJSON_PrintUnformatted(arr);
    std::string result(raw);
    cJSON_free(raw);
    cJSON_Delete(arr);
    return result;
}

static std::string build_charging_json(const ChargingInfo& ch) {
    cJSON* obj = cJSON_CreateObject();

    // 电池概览
    cJSON_AddNumberToObject(obj, "battery_level", ch.battery_level);
    cJSON_AddNumberToObject(obj, "battery_temp", ch.battery_temp);
    cJSON_AddNumberToObject(obj, "battery_voltage_mv", ch.battery_voltage_mv);
    cJSON_AddNumberToObject(obj, "battery_current_ma", ch.battery_current_ma);
    cJSON_AddStringToObject(obj, "battery_status", ch.battery_status);
    cJSON_AddStringToObject(obj, "battery_health", ch.battery_health);
    cJSON_AddStringToObject(obj, "battery_technology", ch.battery_technology);
    cJSON_AddStringToObject(obj, "charge_type", ch.charge_type);
    cJSON_AddNumberToObject(obj, "charge_full_uah", ch.charge_full_uah);
    cJSON_AddNumberToObject(obj, "charge_full_design_uah", ch.charge_full_design_uah);
    cJSON_AddStringToObject(obj, "charger_speed", ch.charger_speed);
    cJSON_AddNumberToObject(obj, "input_current_ma", ch.input_current_ma);
    cJSON_AddNumberToObject(obj, "pd_supported", ch.pd_supported);

    // 健康度
    if (ch.charge_full_uah > 0 && ch.charge_full_design_uah > 0) {
        double health_pct = (double)ch.charge_full_uah / (double)ch.charge_full_design_uah * 100.0;
        cJSON_AddNumberToObject(obj, "battery_health_pct", health_pct);
    }

    // 所有电源设备
    cJSON* supplies = cJSON_CreateArray();
    for (int i = 0; i < ch.supply_count; i++) {
        auto& s = ch.supplies[i];
        cJSON* sobj = cJSON_CreateObject();
        cJSON_AddStringToObject(sobj, "name", s.name);
        cJSON_AddStringToObject(sobj, "type", s.type);
        cJSON_AddStringToObject(sobj, "status", s.status);
        cJSON_AddStringToObject(sobj, "health", s.health);
        cJSON_AddStringToObject(sobj, "technology", s.technology);
        cJSON_AddStringToObject(sobj, "charge_type", s.charge_type);
        cJSON_AddNumberToObject(sobj, "capacity", s.capacity);
        cJSON_AddNumberToObject(sobj, "temp", s.temp);
        cJSON_AddNumberToObject(sobj, "voltage_uv", s.voltage_uv);
        cJSON_AddNumberToObject(sobj, "current_ua", s.current_ua);
        cJSON_AddNumberToObject(sobj, "input_current_limit_ua", s.input_current_limit_ua);
        cJSON_AddNumberToObject(sobj, "charge_full_uah", s.charge_full_uah);
        cJSON_AddNumberToObject(sobj, "charge_full_design_uah", s.charge_full_design_uah);
        cJSON_AddNumberToObject(sobj, "pd_allowed", s.pd_allowed);
        cJSON_AddItemToArray(supplies, sobj);
    }
    cJSON_AddItemToObject(obj, "supplies", supplies);

    char* raw = cJSON_PrintUnformatted(obj);
    std::string result(raw);
    cJSON_free(raw);
    cJSON_Delete(obj);
    return result;
}

static std::string build_power_json(const std::vector<AppPowerInfo>& apps) {
    // 读取实际电池功率
    ChargingInfo ch = charging_get_info();
    double sys_mw = 0;
    if (ch.battery_current_ma != -1 && ch.battery_voltage_mv != -1) {
        sys_mw = (double)abs(ch.battery_current_ma) * (double)ch.battery_voltage_mv / 1000.0;
    }

    cJSON* obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "system_power_mw", (int)(sys_mw * 10) / 10.0);
    cJSON_AddStringToObject(obj, "battery_status", ch.battery_status);
    cJSON_AddNumberToObject(obj, "battery_level", ch.battery_level);
    cJSON_AddNumberToObject(obj, "battery_current_ma", ch.battery_current_ma);
    cJSON_AddNumberToObject(obj, "battery_voltage_mv", ch.battery_voltage_mv);
    cJSON_AddNumberToObject(obj, "battery_temp", ch.battery_temp);
    cJSON_AddStringToObject(obj, "charge_type", ch.charge_type);
    cJSON_AddStringToObject(obj, "charger_speed", ch.charger_speed);

    cJSON* arr = cJSON_CreateArray();
    for (auto& app : apps) {
        cJSON* o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "uid", app.uid);
        cJSON_AddStringToObject(o, "package", app.package_name);
        cJSON_AddStringToObject(o, "label", app.label);
        cJSON_AddNumberToObject(o, "cpu_pct", (int)(app.cpu_usage_pct * 10) / 10.0);
        cJSON_AddNumberToObject(o, "mem_mb", (int)(app.mem_rss_kb / 102.4) / 10.0);
        cJSON_AddNumberToObject(o, "io_mb",
            (int)((app.io_read_bytes + app.io_write_bytes) / 1024.0 / 102.4) / 10.0);
        cJSON_AddNumberToObject(o, "procs", app.proc_count);
        cJSON_AddNumberToObject(o, "power_mw", (int)(app.power_mw * 10) / 10.0);
        cJSON_AddNumberToObject(o, "avg_battery_mw", (int)(app.avg_battery_mw * 10) / 10.0);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(obj, "apps", arr);

    char* raw = cJSON_PrintUnformatted(obj);
    std::string result(raw);
    cJSON_free(raw);
    cJSON_Delete(obj);
    return result;
}

static std::string build_overlay_json() {
    OverlayData od = overlay_get_data();
    cJSON* o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "cpu_total", (int)(od.cpu_total_pct * 10) / 10.0);
    cJSON* cores = cJSON_CreateArray();
    for (int i = 0; i < od.cpu_core_count; i++)
        cJSON_AddItemToArray(cores, cJSON_CreateNumber((int)(od.cpu_per_core[i] * 10) / 10.0));
    cJSON_AddItemToObject(o, "cpu_cores", cores);
    if (od.gpu_pct >= 0) {
        cJSON_AddNumberToObject(o, "gpu_pct", (int)(od.gpu_pct * 10) / 10.0);
        cJSON_AddStringToObject(o, "gpu_name", od.gpu_name);
    } else {
        cJSON_AddNumberToObject(o, "gpu_pct", -1);
        cJSON_AddStringToObject(o, "gpu_name", "");
    }
    cJSON_AddNumberToObject(o, "power_mw", (int)(od.power_mw * 10) / 10.0);
    cJSON_AddNumberToObject(o, "bat_level", od.battery_level);
    cJSON_AddNumberToObject(o, "bat_temp", od.battery_temp);
    cJSON_AddStringToObject(o, "bat_status", od.battery_status);
    cJSON_AddStringToObject(o, "fg_app", od.fg_app);
    cJSON_AddNumberToObject(o, "fg_cpu", (int)(od.fg_cpu_pct * 10) / 10.0);
    cJSON_AddNumberToObject(o, "fg_mem", od.fg_mem_mb);
    char* raw = cJSON_PrintUnformatted(o);
    std::string result(raw);
    cJSON_free(raw);
    cJSON_Delete(o);
    return result;
}

// ============ 悬浮窗进程管理 ============

static std::string g_module_dir;

static pid_t g_overlay_pid = -1;

// 通过进程名查找overlay进程PID
static pid_t find_overlay_pid() {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;
    
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(ent->d_name);
        
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE* f = fopen(path, "r");
        if (!f) continue;
        
        char cmd[256] = {0};
        fread(cmd, 1, sizeof(cmd) - 1, f);
        fclose(f);
        
        // 检查是否是skroot_overlay进程
        if (strstr(cmd, "skroot_overlay") != nullptr) {
            closedir(dir);
            return pid;
        }
    }
    closedir(dir);
    return -1;
}

static bool is_overlay_running() {
    // 先检查已知PID
    if (g_overlay_pid > 0) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", g_overlay_pid);
        FILE* f = fopen(path, "r");
        if (f) { fclose(f); return true; }
        g_overlay_pid = -1;
    }
    // PID无效时，尝试通过进程名查找
    pid_t found = find_overlay_pid();
    if (found > 0) {
        g_overlay_pid = found;
        return true;
    }
    return false;
}

static void start_overlay() {
    if (is_overlay_running()) {
        printf("[overlay] already running pid=%d\n", g_overlay_pid);
        return;
    }

    char module_dir[512] = {0};

    // 优先用 g_module_dir（onPrepareCreate 中设置）
    if (!g_module_dir.empty()) {
        strncpy(module_dir, g_module_dir.c_str(), sizeof(module_dir) - 1);
    }

    // 备选：从 /proc/self/maps 找到模块 .so 的路径，推导出模块目录
    if (!module_dir[0]) {
        FILE* maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[1024];
            while (fgets(line, sizeof(line), maps)) {
                char* p = strstr(line, "libmodule_proc_monitor.so");
                if (p) {
                    // 找到路径（从行首到 .so）
                    char* start = strrchr(line, '/');
                    if (start) {
                        int len = (int)(start - line);
                        if (len > 0 && len < (int)sizeof(module_dir)) {
                            strncpy(module_dir, line, len);
                            module_dir[len] = 0;
                            // 去掉行首的地址部分，找到实际路径
                            char* path_start = strchr(line, '/');
                            if (path_start) {
                                len = (int)(start - path_start);
                                if (len < (int)sizeof(module_dir)) {
                                    strncpy(module_dir, path_start, len);
                                    module_dir[len] = 0;
                                }
                            }
                        }
                    }
                    break;
                }
            }
            fclose(maps);
        }
    }

    printf("[overlay] module_dir=%s\n", module_dir);

    if (!module_dir[0]) {
        printf("[overlay] cannot determine module directory\n");
        return;
    }

    char bin_path[512];
    snprintf(bin_path, sizeof(bin_path), "%s/skroot_overlay", module_dir);

    // 检查文件是否存在
    FILE* f = fopen(bin_path, "r");
    if (!f) {
        printf("[overlay] binary not found: %s\n", bin_path);
        return;
    }
    fclose(f);

    pid_t pid = fork();
    if (pid == 0) {
        // 子进程
        setsid();
        execl(bin_path, "skroot_overlay", nullptr);
        _exit(1);
    } else if (pid > 0) {
        g_overlay_pid = pid;
        printf("[overlay] started pid=%d from %s\n", pid, bin_path);
    }
}

static void stop_overlay() {
    if (g_overlay_pid <= 0) return;
    kill(g_overlay_pid, SIGTERM);
    printf("[overlay] stopped pid=%d\n", g_overlay_pid);
    g_overlay_pid = -1;
}

// ============ 模块入口 ============

// API Key 认证（存储在文件中）
static std::string g_api_key;
static bool g_api_key_enabled = false;  // 默认关闭

// 生成随机 API Key
static std::string generate_api_key() {
    const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string key;
    srand(time(nullptr) ^ getpid());
    for (int i = 0; i < 32; i++) {
        key += chars[rand() % (sizeof(chars) - 1)];
    }
    return key;
}

// 加载或生成 API Key
static void init_api_key(const char* module_dir) {
    // 读取 API Key 开关配置
    char config_path[512];
    snprintf(config_path, sizeof(config_path), "%s/api_key_config", module_dir);
    FILE* cf = fopen(config_path, "r");
    if (cf) {
        char line[64];
        while (fgets(line, sizeof(line), cf)) {
            if (strncmp(line, "enabled=", 8) == 0) {
                g_api_key_enabled = (atoi(line + 8) == 1);
            }
        }
        fclose(cf);
    }
    
    // 如果禁用 API Key，直接返回
    if (!g_api_key_enabled) {
        LOGI("[module_proc_monitor] API Key authentication disabled\n");
        return;
    }
    
    char path[512];
    snprintf(path, sizeof(path), "%s/api_key", module_dir);
    
    FILE* f = fopen(path, "r");
    if (f) {
        char buf[64] = {0};
        if (fgets(buf, sizeof(buf), f)) {
            // 去掉换行符
            char* nl = strchr(buf, '\n');
            if (nl) *nl = 0;
            g_api_key = buf;
        }
        fclose(f);
    }
    
    // 如果没有读到，生成新的
    if (g_api_key.empty()) {
        g_api_key = generate_api_key();
        // 保存到文件（权限 0600）
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            write(fd, g_api_key.c_str(), g_api_key.size());
            close(fd);
        }
    }
    
    // 打印 API Key（仅在模块启动时）
    LOGI("[module_proc_monitor] ========================================\n");
    LOGI("[module_proc_monitor] API Key: %s\n", g_api_key.c_str());
    LOGI("[module_proc_monitor] ========================================\n");
}

int skroot_module_main(const char* root_key, const char* module_private_dir) {
    mkdir("/storage/emulated/0/SKMonitor", 0755);

    // 创建存储目录
    mkdir("/storage/emulated/0/SKMonitor", 0755);

    // 创建存储目录
    mkdir("/storage/emulated/0/SKMonitor", 0755);

    // 不打印敏感信息（root_key 长度和模块路径）
    LOGI("[module_proc_monitor] initializing...\n");

    g_module_dir = module_private_dir;

    // 初始化扫描器
    proc_scanner_init(module_private_dir);
    power_tracker_init_with_dir(module_private_dir);

    // 启动后台守护线程
    proc_scanner_start();

    LOGI("[module_proc_monitor] proc scanner daemon started\n");

    // skroot_module_main 返回后模块进程结束，
    // 但 WebUI handler 进程会继续运行
    return 0;
}

// ============ WebUI HTTP Handler ============

class ProcMonitorWebHandler : public kernel_module::WebUIHttpHandler {
public:
    void onPrepareCreate(const char* root_key, const char* module_private_dir, uint32_t port) override {
        LOGI("[proc_monitor] WebUI starting on port %d\n", port);

        // 保存模块目录，供悬浮窗启动使用
        g_module_dir = module_private_dir;

        // 初始化 API Key
        init_api_key(module_private_dir);

        // 写端口到文件，供悬浮窗应用读取（权限 0600）
        int fd = open("/storage/emulated/0/SKMonitor/skroot_webui_port", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            char buf[16];
            int len = snprintf(buf, sizeof(buf), "%u\n", port);
            write(fd, buf, len);
            close(fd);
        }

        // 在 WebUI 进程中也需要启动扫描器
        proc_scanner_init(module_private_dir);
        proc_scanner_start();
        power_tracker_init_with_dir(module_private_dir);
        // 启动后台功耗采样线程（10秒一次）
        power_tracker_start();
    }

    // 验证 API Key
    bool verifyApiKey(struct mg_connection* conn) {
        // 如果禁用 API Key，直接返回 true
        if (!g_api_key_enabled) return true;
        
        // 从请求头获取 API Key
        const char* api_key_header = mg_get_header(conn, "X-API-Key");
        if (!api_key_header) {
            // 也检查查询参数
            const struct mg_request_info* ri = mg_get_request_info(conn);
            if (ri && ri->query_string) {
                const char* key_param = strstr(ri->query_string, "key=");
                if (key_param) {
                    api_key_header = key_param + 4;
                }
            }
        }
        
        // 验证
        if (!api_key_header || g_api_key != api_key_header) {
            kernel_module::webui::send_text(conn, 401, "{\"error\":\"unauthorized\",\"message\":\"Invalid or missing API key\"}");
            return false;
        }
        return true;
    }

    bool handleGet(CivetServer* server, struct mg_connection* conn,
                   const std::string& path, const std::string& query) override {
        // API Key 验证（排除获取 key 的端点）
        if (path.substr(0, 5) == "/api/" && path != "/api/key") {
            if (!verifyApiKey(conn)) return true;
        }
        
        // 获取 API Key（仅限无 key 的首次访问）
        if (path == "/api/key") {
            // 检查是否已有 key（防止泄露）
            const char* api_key_header = mg_get_header(conn, "X-API-Key");
            if (api_key_header && g_api_key == api_key_header) {
                // 已认证，返回当前 key
                char resp[128];
                snprintf(resp, sizeof(resp), "{\"key\":\"%s\"}", g_api_key.c_str());
                kernel_module::webui::send_text(conn, 200, resp);
            } else {
                // 未认证，拒绝访问（key 应从日志获取）
                kernel_module::webui::send_text(conn, 403, "{\"error\":\"forbidden\",\"message\":\"Check module log for API key\"}");
            }
            return true;
        }
        
        // API 端点同时支持 GET（兼容性）
        if (path == "/api/charging") {
            ChargingInfo ch = charging_get_info();
            std::string json = build_charging_json(ch);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }
        if (path == "/api/events") {
            int n = 100;
            if (!query.empty()) {
                auto pos = query.find("limit=");
                if (pos != std::string::npos) {
                    int parsed = atoi(query.c_str() + pos + 6);
                    if (parsed > 0 && parsed <= 2000) n = parsed;
                }
            }
            auto events = g_event_buf.get_recent(n);
            std::string json = build_event_json(events);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }
        if (path == "/api/alerts") {
            int n = 50;
            if (!query.empty()) {
                auto pos = query.find("limit=");
                if (pos != std::string::npos) {
                    int parsed = atoi(query.c_str() + pos + 6);
                    if (parsed > 0 && parsed <= 1000) n = parsed;
                }
            }
            auto alerts = g_event_buf.get_alerts(n);
            std::string json = build_event_json(alerts);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }
        if (path == "/api/stats") {
            char buf[256];
            snprintf(buf, sizeof(buf),
                "{\"total_events\":%lld,\"total_alerts\":%lld}",
                (long long)g_event_buf.total_events(),
                (long long)g_event_buf.total_alerts());
            kernel_module::webui::send_text(conn, 200, buf);
            return true;
        }
        if (path == "/api/procs") {
            auto procs = proc_scanner_get_all_procs();
            std::string json = build_procs_json(procs);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }
        if (path == "/api/power-drain") {
            int n = 20;
            if (!query.empty()) {
                auto pos = query.find("limit=");
                if (pos != std::string::npos) {
                    int parsed = atoi(query.c_str() + pos + 6);
                    if (parsed > 0 && parsed <= 100) n = parsed;
                }
            }
            // 后台线程已定时采样，直接读缓存
            auto apps = power_tracker_get_top(n);
            std::string json = build_power_json(apps);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }
        // 静态文件由 CivetWeb 默认处理
        if (path == "/api/overlay") {
            std::string json = build_overlay_json();
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }
        if (path == "/api/overlay-toggle") {
            char buf[128];
            snprintf(buf, sizeof(buf), "{\"running\":%s,\"pid\":%d}",
                     is_overlay_running() ? "true" : "false", (int)g_overlay_pid);
            kernel_module::webui::send_text(conn, 200, buf);
            return true;
        }
        if (path == "/api/overlay-config") {
            int fast_mode = 0, overlay_style = 0;
            FILE* f = fopen("/storage/emulated/0/SKMonitor/overlay_config", "r");
            if (f) {
                char line[256];
                while (fgets(line, sizeof(line), f)) {
                    if (strncmp(line, "fast_mode=", 10) == 0) {
                        fast_mode = atoi(line + 10);
                    } else if (strncmp(line, "overlay_style=", 14) == 0) {
                        overlay_style = atoi(line + 14);
                    }
                }
                fclose(f);
            }
            char buf[256];
            snprintf(buf, sizeof(buf), "{\"fast_mode\":%d,\"overlay_style\":%d}", fast_mode, overlay_style);
            kernel_module::webui::send_text(conn, 200, buf);
            return true;
        }

        // 获取配置（双电芯等）
        if (path == "/api/config") {
            bool dual_battery = false;
            FILE* rf = fopen("/storage/emulated/0/SKMonitor/proc_monitor_config", "r");
            if (rf) {
                char line[256];
                while (fgets(line, sizeof(line), rf)) {
                    if (strncmp(line, "dual_battery=", 13) == 0) {
                        dual_battery = (atoi(line + 13) == 1);
                    }
                }
                fclose(rf);
            }
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"dual_battery\":%s,\"api_key_enabled\":%s}", 
                     dual_battery ? "true" : "false",
                     g_api_key_enabled ? "true" : "false");
            kernel_module::webui::send_text(conn, 200, resp);
            return true;
        }

        return false;
    }

    bool handlePost(CivetServer* server, struct mg_connection* conn,
                    const std::string& path, const std::string& body) override {
        // API Key 验证
        if (path.substr(0, 5) == "/api/") {
            if (!verifyApiKey(conn)) return true;
        }

        if (path == "/api/events") {
            // 获取最近事件：body = "100" 表示最近 100 条
            int n = 100;
            if (!body.empty()) {
                int parsed = atoi(body.c_str());
                if (parsed > 0 && parsed <= 2000) n = parsed;
            }
            auto events = g_event_buf.get_recent(n);
            std::string json = build_event_json(events);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }

        if (path == "/api/alerts") {
            // 获取最近告警
            int n = 50;
            if (!body.empty()) {
                int parsed = atoi(body.c_str());
                if (parsed > 0 && parsed <= 1000) n = parsed;
            }
            auto alerts = g_event_buf.get_alerts(n);
            std::string json = build_event_json(alerts);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }

        if (path == "/api/stats") {
            // 统计信息
            char buf[256];
            snprintf(buf, sizeof(buf),
                "{\"total_events\":%lld,\"total_alerts\":%lld}",
                (long long)g_event_buf.total_events(),
                (long long)g_event_buf.total_alerts());
            kernel_module::webui::send_text(conn, 200, buf);
            return true;
        }

        if (path == "/api/scan") {
            // 手动触发一次扫描
            proc_scanner_scan_once();
            kernel_module::webui::send_text(conn, 200, "OK");
            return true;
        }

        if (path == "/api/procs") {
            // 获取当前所有进程列表
            auto procs = proc_scanner_get_all_procs();
            std::string json = build_procs_json(procs);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }

        if (path == "/api/charging") {
            // 获取充电信息
            printf("[proc_monitor] /api/charging called\n");
            ChargingInfo ch = charging_get_info();
            printf("[proc_monitor] battery_level=%d status=%s supply_count=%d\n",
                   ch.battery_level, ch.battery_status, ch.supply_count);
            std::string json = build_charging_json(ch);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }

        if (path == "/api/power-drain") {
            int n = 20;
            if (!body.empty()) {
                int parsed = atoi(body.c_str());
                if (parsed > 0 && parsed <= 100) n = parsed;
            }
            // 后台线程已定时采样，直接读缓存
            auto apps = power_tracker_get_top(n);
            std::string json = build_power_json(apps);
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }

        if (path == "/api/overlay") {
            std::string json = build_overlay_json();
            kernel_module::webui::send_text(conn, 200, json);
            return true;
        }

        if (path == "/api/overlay-toggle") {
            if (body == "start") {
                start_overlay();
            } else if (body == "stop") {
                stop_overlay();
            }
            char buf[128];
            snprintf(buf, sizeof(buf), "{\"running\":%s,\"pid\":%d}",
                     is_overlay_running() ? "true" : "false", (int)g_overlay_pid);
            kernel_module::webui::send_text(conn, 200, buf);
            return true;
        }

        if (path == "/api/overlay-config") {
            // 读取现有配置
            std::string config_content;
            FILE* rf = fopen("/storage/emulated/0/SKMonitor/overlay_config", "r");
            if (rf) {
                char buf[4096];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), rf)) > 0) {
                    config_content.append(buf, n);
                }
                fclose(rf);
            }
            
            // 解析现有配置
            std::string new_config;
            bool found_fast = false, found_style = false;
            int current_fast = 0, current_style = 0;
            
            std::istringstream iss(config_content);
            std::string line;
            while (std::getline(iss, line)) {
                if (line.substr(0, 10) == "fast_mode=") {
                    current_fast = atoi(line.substr(10).c_str());
                    found_fast = true;
                } else if (line.substr(0, 14) == "overlay_style=") {
                    current_style = atoi(line.substr(14).c_str());
                    found_style = true;
                }
            }
            
            // 更新配置
            if (body.find("fast_mode=") != std::string::npos) {
                current_fast = (body.find("fast_mode=1") != std::string::npos) ? 1 : 0;
            }
            if (body.find("overlay_style=") != std::string::npos) {
                size_t pos = body.find("overlay_style=");
                if (pos != std::string::npos) {
                    current_style = atoi(body.substr(pos + 14).c_str());
                }
            }
            
            // 构建新配置
            new_config = "fast_mode=" + std::to_string(current_fast) + "\n";
            new_config += "overlay_style=" + std::to_string(current_style) + "\n";
            
            // 写入配置文件
            FILE* wf = fopen("/storage/emulated/0/SKMonitor/overlay_config", "w");
            if (wf) {
                fwrite(new_config.c_str(), 1, new_config.size(), wf);
                fclose(wf);
            }
            
            // 返回当前配置
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"fast_mode\":%d,\"overlay_style\":%d}", current_fast, current_style);
            kernel_module::webui::send_text(conn, 200, resp);
            return true;
        }

        // 更新配置（双电芯等）
        if (path == "/api/config") {
            bool dual_battery = (body.find("dual_battery=1") != std::string::npos) ||
                                (body.find("\"dual_battery\":true") != std::string::npos);
            std::string config = "dual_battery=" + std::string(dual_battery ? "1" : "0") + "\n";
            // 安全写入：使用 open() 设置权限 0600 (仅 root 可读写)
            int fd = open("/storage/emulated/0/SKMonitor/proc_monitor_config", O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0) {
                write(fd, config.c_str(), config.size());
                close(fd);
            }
            // 立即更新运行时变量
            power_tracker_set_dual_battery(dual_battery);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"dual_battery\":%s,\"api_key_enabled\":%s}", 
                     dual_battery ? "true" : "false",
                     g_api_key_enabled ? "true" : "false");
            kernel_module::webui::send_text(conn, 200, resp);
            return true;
        }

        // 结束进程 - 使用 kill 系统调用
        if (path == "/api/kill-process") {
            int uid = -1;
            size_t pos = body.find("uid=");
            if (pos != std::string::npos) {
                uid = atoi(body.c_str() + pos + 4);
            } else {
                pos = body.find("\"uid\":");
                if (pos != std::string::npos) {
                    uid = atoi(body.c_str() + pos + 6);
                }
            }

            if (uid < 0 || uid > 99999) {
                kernel_module::webui::send_text(conn, 400, "{\"error\":\"invalid uid range\"}");
                return true;
            }

            // 获取包名
            char pkg[256] = {0};
            FILE* f = fopen("/data/system/packages.list", "r");
            if (f) {
                char line[512];
                char uid_str[32];
                snprintf(uid_str, sizeof(uid_str), " %d ", uid);
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, uid_str)) {
                        char* space = strchr(line, ' ');
                        if (space) {
                            size_t len = space - line;
                            if (len < sizeof(pkg)) {
                                memcpy(pkg, line, len);
                                pkg[len] = '\0';
                            }
                        }
                        break;
                    }
                }
                fclose(f);
            }

            // 直接杀掉该 UID 的所有进程
            int killed = 0;
            DIR* proc_dir = opendir("/proc");
            if (proc_dir) {
                struct dirent* ent;
                while ((ent = readdir(proc_dir)) != nullptr) {
                    if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
                    pid_t pid = (pid_t)atoi(ent->d_name);
                    
                    char status_path[64];
                    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
                    FILE* sf = fopen(status_path, "r");
                    if (!sf) continue;
                    
                    uid_t proc_uid = (uid_t)-1;
                    char line[256];
                    while (fgets(line, sizeof(line), sf)) {
                        if (strncmp(line, "Uid:", 4) == 0) {
                            proc_uid = (uid_t)strtoul(line + 4, nullptr, 10);
                            break;
                        }
                    }
                    fclose(sf);
                    
                    if (proc_uid == (uid_t)uid) {
                        if (kill(pid, SIGKILL) == 0) {
                            killed++;
                        }
                    }
                }
                closedir(proc_dir);
            }

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"success\":true,\"uid\":%d,\"package\":\"%s\",\"killed\":%d}",
                     uid, pkg, killed);
            kernel_module::webui::send_text(conn, 200, resp);
            return true;
        }
    ServerExitAction onBeforeServerExit() override {
        proc_scanner_stop();
        return ServerExitAction::Exit;
    }
};

// ============ SKRoot 模块名片 ============

// 生成 UUID: python3 -c "import uuid; print(uuid.uuid4().hex)"
SKROOT_MODULE_NAME("进程行为监控")
SKROOT_MODULE_VERSION("2.5.0")
SKROOT_MODULE_DESC("实时监控进程创建/退出，自动检测 Root 检测工具和可疑进程，提供 WebUI 仪表盘")
SKROOT_MODULE_AUTHOR("SKRoot Pro")
SKROOT_MODULE_UUID32("a7c3e1f84b2d4e9f1a6c8d5b3e7f2a90")
SKROOT_MODULE_WEB_UI(ProcMonitorWebHandler)