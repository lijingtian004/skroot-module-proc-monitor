//
// proc_scanner.cpp — /proc 持久扫描器
// 职责：后台线程扫描 /proc，检测新进程 + 可疑进程匹配
//

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <atomic>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

#include "proc_scanner.h"

// 全局事件缓冲区
EventBuffer g_event_buf;

// ============ 内部状态 ============
static std::atomic<bool> g_running{false};
static pthread_t g_scan_thread;
static char g_private_dir[1024] = {0};

// 已知进程表：pid -> comm（用于检测新进程和退出）
static std::unordered_map<pid_t, std::string> g_known_procs;
static pthread_mutex_t g_known_mtx = PTHREAD_MUTEX_INITIALIZER;

// ============ 工具函数 ============

static int64_t now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// 读取 /proc/<pid>/comm
static bool read_proc_comm(pid_t pid, char* out, size_t out_sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, out, out_sz - 1);
    close(fd);
    if (n <= 0) return false;
    out[n - 1] = '\0';  // 去掉换行
    // 去掉尾部空白
    while (n > 1 && (out[n-2] == '\n' || out[n-2] == '\r' || out[n-2] == ' ')) {
        out[n-2] = '\0';
        n--;
    }
    return true;
}

// 读取 /proc/<pid>/cmdline
static bool read_proc_cmdline(pid_t pid, char* out, size_t out_sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, out, out_sz - 1);
    close(fd);
    if (n <= 0) return false;
    out[n] = '\0';
    // cmdline 用 \0 分隔参数，替换为空格方便阅读
    for (ssize_t i = 0; i < n - 1; i++) {
        if (out[i] == '\0') out[i] = ' ';
    }
    return true;
}

// 读取 /proc/<pid>/status 获取 ppid 和 uid
static bool read_proc_status(pid_t pid, pid_t* out_ppid, uid_t* out_uid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE* f = fopen(path, "r");
    if (!f) return false;

    char line[256];
    bool got_ppid = false, got_uid = false;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "PPid:\t%d", out_ppid) == 1) got_ppid = true;
        unsigned int uid;
        if (sscanf(line, "Uid:\t%u", &uid) == 1) {
            *out_uid = (uid_t)uid;
            got_uid = true;
        }
        if (got_ppid && got_uid) break;
    }
    fclose(f);
    return got_ppid;
}

// ============ 可疑进程检测 ============

static const SuspiciousPattern* check_suspicious(const char* comm, const char* cmdline) {
    for (int i = 0; SUSPICIOUS_PATTERNS[i].name != nullptr; i++) {
        const auto& p = SUSPICIOUS_PATTERNS[i];
        // 匹配进程名（不区分大小写）
        std::string comm_lower = comm;
        std::string pattern_lower = p.name;
        std::transform(comm_lower.begin(), comm_lower.end(), comm_lower.begin(), ::tolower);
        std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(), ::tolower);

        if (comm_lower.find(pattern_lower) != std::string::npos) {
            return &p;
        }
        // 可选匹配 cmdline
        if (p.match_cmdline && cmdline[0]) {
            std::string cmd_lower = cmdline;
            std::transform(cmd_lower.begin(), cmd_lower.end(), cmd_lower.begin(), ::tolower);
            if (cmd_lower.find(pattern_lower) != std::string::npos) {
                return &p;
            }
        }
    }
    return nullptr;
}

// ============ 核心扫描逻辑 ============

static void scan_proc_dir() {
    DIR* dir = opendir("/proc");
    if (!dir) return;

    std::unordered_map<pid_t, std::string> current_procs;
    struct dirent* ent;

    while ((ent = readdir(dir)) != nullptr) {
        // 只看数字目录（PID）
        if (ent->d_type != DT_DIR) continue;
        char* endptr;
        long pid = strtol(ent->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        pid_t p = (pid_t)pid;
        char comm[64] = {0};
        if (!read_proc_comm(p, comm, sizeof(comm))) continue;

        current_procs[p] = comm;
    }
    closedir(dir);

    pthread_mutex_lock(&g_known_mtx);

    int64_t ts = now_ms();

    // 检测新进程
    for (auto& [pid, comm] : current_procs) {
        if (g_known_procs.find(pid) == g_known_procs.end()) {
            // 新进程!
            const char* comm_cstr = comm.c_str();
            ProcEvent ev{};
            ev.timestamp = ts;
            ev.pid = pid;
            ev.type = ProcEventType::EXEC;
            strncpy(ev.comm, comm_cstr, sizeof(ev.comm) - 1);

            // 读取详细信息
            char cmdline[256] = {0};
            read_proc_cmdline(pid, cmdline, sizeof(cmdline));
            strncpy(ev.cmdline, cmdline, sizeof(ev.cmdline) - 1);

            read_proc_status(pid, &ev.ppid, &ev.uid);

            g_event_buf.add_event(ev);

            // 可疑进程检测
            const SuspiciousPattern* sp = check_suspicious(comm_cstr, cmdline);
            if (sp) {
                ProcEvent alert{};
                alert.timestamp = ts;
                alert.type = ProcEventType::ALERT;
                alert.pid = pid;
                alert.ppid = ev.ppid;
                alert.uid = ev.uid;
                strncpy(alert.comm, comm_cstr, sizeof(alert.comm) - 1);
                strncpy(alert.cmdline, cmdline, sizeof(alert.cmdline) - 1);
                strncpy(alert.alert_reason, sp->reason, sizeof(alert.alert_reason) - 1);
                g_event_buf.add_event(alert);
            }
        }
    }

    // 检测退出进程
    for (auto& [pid, comm] : g_known_procs) {
        if (current_procs.find(pid) == current_procs.end()) {
            ProcEvent ev{};
            ev.timestamp = ts;
            ev.type = ProcEventType::EXIT;
            ev.pid = pid;
            strncpy(ev.comm, comm.c_str(), sizeof(ev.comm) - 1);
            g_event_buf.add_event(ev);
        }
    }

    // 更新已知进程表
    g_known_procs = std::move(current_procs);

    pthread_mutex_unlock(&g_known_mtx);
}

// ============ 后台扫描线程 ============

static void* scan_thread_func(void* arg) {
    printf("[proc_scanner] daemon thread started, interval=800ms\n");

    // 首次扫描：填充已知进程表，不触发事件
    {
        DIR* dir = opendir("/proc");
        if (dir) {
            struct dirent* ent;
            while ((ent = readdir(dir)) != nullptr) {
                if (ent->d_type != DT_DIR) continue;
                char* endptr;
                long pid = strtol(ent->d_name, &endptr, 10);
                if (*endptr != '\0' || pid <= 0) continue;
                char comm[64] = {0};
                if (read_proc_comm((pid_t)pid, comm, sizeof(comm))) {
                    g_known_procs[(pid_t)pid] = comm;
                }
            }
            closedir(dir);
        }
        printf("[proc_scanner] initial scan: %zu processes\n", g_known_procs.size());
    }

    while (g_running.load()) {
        scan_proc_dir();
        // 800ms 扫描间隔 — 平衡实时性和 CPU 占用
        usleep(800 * 1000);
    }

    printf("[proc_scanner] daemon thread exiting\n");
    return nullptr;
}

// ============ 对外接口 ============

int proc_scanner_init(const char* module_private_dir) {
    if (module_private_dir) {
        strncpy(g_private_dir, module_private_dir, sizeof(g_private_dir) - 1);
    }
    return 0;
}

void proc_scanner_start() {
    if (g_running.exchange(true)) return;  // 已经在跑

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_create(&g_scan_thread, &attr, scan_thread_func, nullptr);
    pthread_attr_destroy(&attr);
}

void proc_scanner_stop() {
    if (!g_running.exchange(false)) return;
    pthread_join(g_scan_thread, nullptr);
}

void proc_scanner_scan_once() {
    scan_proc_dir();
}

std::vector<ProcInfo> proc_scanner_get_all_procs() {
    std::vector<ProcInfo> result;
    DIR* dir = opendir("/proc");
    if (!dir) return result;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_type != DT_DIR) continue;
        char* endptr;
        long pid = strtol(ent->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        ProcInfo info{};
        info.pid = (pid_t)pid;
        
        if (!read_proc_comm(info.pid, info.comm, sizeof(info.comm))) continue;
        read_proc_cmdline(info.pid, info.cmdline, sizeof(info.cmdline));
        read_proc_status(info.pid, &info.ppid, &info.uid);
        
        result.push_back(info);
    }
    closedir(dir);

    // 按 PID 排序
    std::sort(result.begin(), result.end(), [](const ProcInfo& a, const ProcInfo& b) {
        return a.pid < b.pid;
    });

    return result;
}

// ============ 充电信息读取 ============

// 读取 sysfs 文件内容
static bool read_sysfs_string(const char* path, char* out, size_t sz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, out, sz - 1);
    close(fd);
    if (n <= 0) return false;
    out[n] = '\0';
    // 去掉尾部换行
    while (n > 0 && (out[n-1] == '\n' || out[n-1] == '\r')) {
        out[--n] = '\0';
    }
    return true;
}

static int read_sysfs_int(const char* path) {
    char buf[32] = {0};
    if (!read_sysfs_string(path, buf, sizeof(buf))) return -1;
    return atoi(buf);
}

// 读取单个 power_supply 设备信息
static bool read_power_supply(const char* devname, PowerSupplyInfo* info) {
    memset(info, 0, sizeof(*info));
    strncpy(info->name, devname, sizeof(info->name) - 1);

    char base[256];
    snprintf(base, sizeof(base), "/sys/class/power_supply/%s", devname);

    char path[512];

    // type (Battery, USB, Mains, Wireless)
    snprintf(path, sizeof(path), "%s/type", base);
    read_sysfs_string(path, info->type, sizeof(info->type));

    // status
    snprintf(path, sizeof(path), "%s/status", base);
    read_sysfs_string(path, info->status, sizeof(info->status));

    // health
    snprintf(path, sizeof(path), "%s/health", base);
    read_sysfs_string(path, info->health, sizeof(info->health));

    // technology
    snprintf(path, sizeof(path), "%s/technology", base);
    read_sysfs_string(path, info->technology, sizeof(info->technology));

    // charge_type (Fast, Standard, Trickle)
    snprintf(path, sizeof(path), "%s/charge_type", base);
    read_sysfs_string(path, info->charge_type, sizeof(info->charge_type));

    // capacity
    snprintf(path, sizeof(path), "%s/capacity", base);
    info->capacity = read_sysfs_int(path);

    // temp
    snprintf(path, sizeof(path), "%s/temp", base);
    info->temp = read_sysfs_int(path);

    // voltage_now (μV)
    snprintf(path, sizeof(path), "%s/voltage_now", base);
    info->voltage_uv = read_sysfs_int(path);

    // current_now (μA)
    snprintf(path, sizeof(path), "%s/current_now", base);
    info->current_ua = read_sysfs_int(path);

    // input_current_limit (μA)
    snprintf(path, sizeof(path), "%s/input_current_limit", base);
    info->input_current_limit_ua = read_sysfs_int(path);

    // charge_full (μAh)
    snprintf(path, sizeof(path), "%s/charge_full", base);
    info->charge_full_uah = read_sysfs_int(path);

    // charge_full_design (μAh)
    snprintf(path, sizeof(path), "%s/charge_full_design", base);
    info->charge_full_design_uah = read_sysfs_int(path);

    // pd_allowed
    snprintf(path, sizeof(path), "%s/pd_allowed", base);
    info->pd_allowed = read_sysfs_int(path);
    if (info->pd_allowed < 0) info->pd_allowed = 0;

    return true;
}

// 判断充电速度等级
static const char* classify_charger_speed(int input_current_ma, const char* charge_type) {
    if (input_current_ma < 0) return "unknown";
    if (input_current_ma >= 4000) return "super";   // VOOC/SCP
    if (input_current_ma >= 2000) return "fast";     // QC3+/PD
    if (input_current_ma >= 1000) return "normal";   // 标准充电
    return "slow";                                    // USB 慢充
}

ChargingInfo charging_get_info() {
    ChargingInfo info{};
    info.supply_count = 0;
    info.battery_level = -1;
    info.battery_temp = -1;
    info.battery_voltage_mv = -1;
    info.battery_current_ma = -1;
    info.charge_full_uah = -1;
    info.charge_full_design_uah = -1;
    info.input_current_ma = -1;
    info.pd_supported = 0;

    // 扫描 /sys/class/power_supply/ 目录
    DIR* dir = opendir("/sys/class/power_supply");
    if (!dir) return info;

    struct dirent* ent;
    int max_input_current = -1;

    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        if (info.supply_count >= 8) break;

        PowerSupplyInfo* ps = &info.supplies[info.supply_count];
        if (read_power_supply(ent->d_name, ps)) {
            info.supply_count++;

            // 找主电池设备
            if (strcasecmp(ps->type, "Battery") == 0) {
                if (ps->capacity >= 0) info.battery_level = ps->capacity;
                if (ps->temp > 0) info.battery_temp = ps->temp;
                if (ps->voltage_uv > 0) info.battery_voltage_mv = ps->voltage_uv / 1000;
                // 自适应判断 current_now 单位 + 正负号修正：
                // |值| > 100000 → μA，除以 1000 得 mA
                // |值| <= 100000 → mA，直接用
                // 正负号：有些设备充电为负、放电为正，用 status 修正
                if (ps->current_ua != 0) {
                    int abs_val = ps->current_ua < 0 ? -ps->current_ua : ps->current_ua;
                    int ma = (abs_val > 100000) ? (ps->current_ua / 1000) : ps->current_ua;
                    // 如果 status 是 Charging 但电流为负，翻转
                    if (strcasecmp(ps->status, "Charging") == 0 && ma < 0) ma = -ma;
                    // 如果 status 是 Discharging 但电流为正，翻转
                    if (strcasecmp(ps->status, "Discharging") == 0 && ma > 0) ma = -ma;
                    info.battery_current_ma = ma;
                }
                if (ps->charge_full_uah > 0) info.charge_full_uah = ps->charge_full_uah;
                if (ps->charge_full_design_uah > 0) info.charge_full_design_uah = ps->charge_full_design_uah;
                if (ps->status[0]) strncpy(info.battery_status, ps->status, sizeof(info.battery_status) - 1);
                if (ps->health[0]) strncpy(info.battery_health, ps->health, sizeof(info.battery_health) - 1);
                if (ps->technology[0]) strncpy(info.battery_technology, ps->technology, sizeof(info.battery_technology) - 1);
                if (ps->charge_type[0] && strcmp(ps->charge_type, "N/A") != 0)
                    strncpy(info.charge_type, ps->charge_type, sizeof(info.charge_type) - 1);
            }

            // 收集充电来源设备的输入电流
            if (strcasecmp(ps->type, "USB") == 0 || strcasecmp(ps->type, "Mains") == 0 ||
                strcasecmp(ps->type, "Wireless") == 0) {
                if (ps->input_current_limit_ua > max_input_current)
                    max_input_current = ps->input_current_limit_ua;
                if (ps->pd_allowed > 0) info.pd_supported = 1;
            }
        }
    }
    closedir(dir);

    if (max_input_current > 0) {
        info.input_current_ma = max_input_current / 1000;
    }
    strncpy(info.charger_speed, classify_charger_speed(info.input_current_ma, info.charge_type),
            sizeof(info.charger_speed) - 1);

    return info;
}

// ============ 悬浮窗实时数据 ============

static uid_t find_foreground_uid();  // 前向声明（定义在采样历史部分）

// 上次各核心的 CPU 时间（用于计算占用率）
static unsigned long g_prev_cpu_total[16] = {};
static unsigned long g_prev_cpu_idle[16] = {};
static bool g_cpu_initialized = false;

// 读取逐核心 CPU 占用率
static void read_per_core_cpu(double* per_core, int max_cores, int* out_count, double* total_pct) {
    FILE* f = fopen("/proc/stat", "r");
    if (!f) { *out_count = 0; *total_pct = 0; return; }

    char line[256];
    int core = 0;
    double total_sum = 0;

    // 跳过第一行（汇总的 "cpu"），从 "cpu0" 开始
    fgets(line, sizeof(line), f); // skip "cpu ..." line

    while (fgets(line, sizeof(line), f) && core < max_cores) {
        if (strncmp(line, "cpu", 3) != 0 || line[3] < '0' || line[3] > '9') break;

        unsigned long user, nice, sys, idle, iowait, irq, softirq, steal;
        int n = sscanf(line + 4, "%lu %lu %lu %lu %lu %lu %lu %lu",
                       &user, &nice, &sys, &idle, &iowait, &irq, &softirq, &steal);
        if (n < 4) { core++; continue; }

        unsigned long total = user + nice + sys + idle + iowait + irq + softirq + (n >= 8 ? steal : 0);
        unsigned long idle_total = idle + iowait;

        if (g_cpu_initialized && total > g_prev_cpu_total[core]) {
            unsigned long d_total = total - g_prev_cpu_total[core];
            unsigned long d_idle = idle_total - g_prev_cpu_idle[core];
            per_core[core] = d_total > 0 ? (double)(d_total - d_idle) / d_total * 100.0 : 0;
        } else {
            per_core[core] = 0;
        }

        g_prev_cpu_total[core] = total;
        g_prev_cpu_idle[core] = idle_total;
        total_sum += per_core[core];
        core++;
    }
    fclose(f);

    g_cpu_initialized = true;
    *out_count = core;
    *total_pct = core > 0 ? total_sum / core : 0;
}

// 读取 GPU 占用率（尝试多种路径）
static double read_gpu_pct(char* name_out, int name_sz) {
    name_out[0] = 0;

    // 高通 Adreno: /sys/class/kgsl/kgsl-3d0/gpubusy
    {
        FILE* f = fopen("/sys/class/kgsl/kgsl-3d0/gpubusy", "r");
        if (f) {
            unsigned long busy = 0, total = 0;
            if (fscanf(f, "%lu %lu", &busy, &total) == 2 && total > 0) {
                fclose(f);
                strncpy(name_out, "Adreno", name_sz - 1);
                return (double)busy / total * 100.0;
            }
            fclose(f);
        }
    }

    // 高通 Adreno 备选: /sys/class/kgsl/kgsl-3d0/gpu_busy_percentage
    {
        FILE* f = fopen("/sys/class/kgsl/kgsl-3d0/gpu_busy_percentage", "r");
        if (f) {
            char buf[32] = {};
            fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            strncpy(name_out, "Adreno", name_sz - 1);
            return atof(buf);
        }
    }

    // Mali: /sys/devices/platform/mali/utilization
    {
        FILE* f = fopen("/sys/devices/platform/mali/utilization", "r");
        if (f) {
            int val = 0;
            if (fscanf(f, "%d", &val) == 1) {
                fclose(f);
                strncpy(name_out, "Mali", name_sz - 1);
                return val / 100.0; // 通常是千分比
            }
            fclose(f);
        }
    }

    // Mali 备选: /sys/class/devfreq/mali/ 或 /sys/kernel/gpu/
    {
        FILE* f = fopen("/sys/kernel/gpu/gpu_busy", "r");
        if (f) {
            int val = 0;
            if (fscanf(f, "%d", &val) == 1) {
                fclose(f);
                strncpy(name_out, "GPU", name_sz - 1);
                return val;
            }
            fclose(f);
        }
    }

    return -1; // 不可用
}

// 读取前台 App 的 CPU 和内存
static void get_fg_app_info(char* pkg_out, int pkg_sz, double* cpu_pct, int64_t* mem_mb) {
    pkg_out[0] = 0;
    *cpu_pct = 0;
    *mem_mb = 0;

    // 从功耗缓存中找前台 App
    uid_t fg_uid = find_foreground_uid();
    if (fg_uid == (uid_t)-1) return;

    auto it = g_power_cache.find(fg_uid);
    if (it != g_power_cache.end()) {
        strncpy(pkg_out, it->second.package_name, pkg_sz - 1);
        *cpu_pct = it->second.cpu_usage_pct;
        *mem_mb = it->second.mem_rss_kb / 1024;
    }
}

OverlayData overlay_get_data() {
    OverlayData data{};
    memset(&data, 0, sizeof(data));
    data.gpu_pct = -1;
    data.cpu_core_count = 0;

    // CPU
    read_per_core_cpu(data.cpu_per_core, 16, &data.cpu_core_count, &data.cpu_total_pct);

    // GPU
    data.gpu_pct = read_gpu_pct(data.gpu_name, sizeof(data.gpu_name));

    // 电池
    ChargingInfo ch = charging_get_info();
    data.power_mw = 0;
    if (ch.battery_current_ma != -1 && ch.battery_voltage_mv != -1)
        data.power_mw = abs(ch.battery_current_ma) * (double)ch.battery_voltage_mv / 1000.0;
    data.battery_level = ch.battery_level;
    data.battery_temp = ch.battery_temp;
    strncpy(data.battery_status, ch.battery_status, sizeof(data.battery_status) - 1);

    // 前台应用
    get_fg_app_info(data.fg_app, sizeof(data.fg_app), &data.fg_cpu_pct, &data.fg_mem_mb);

    return data;
}

// ============ 应用功耗追踪 ============

#include <vector>

// 每个 UID 的采样数据
struct UidSample {
    uid_t uid;
    double cpu_time_sec;    // 累计 CPU 时间
    int64_t mem_rss_kb;     // RSS
    int64_t io_read;        // 读字节
    int64_t io_write;       // 写字节
    int     proc_count;
    char    comm[64];       // 最活跃进程名
    char    cmdline[128];   // 命令行（取包名用）
};

static std::unordered_map<uid_t, UidSample> g_prev_samples;
static std::unordered_map<uid_t, AppPowerInfo> g_power_cache;
static double g_last_sample_time = 0;
static double g_prev_total_cpu_sec = 0;
static double g_battery_power_mw = 0;  // 实际电池功率 mW（从 sysfs 读取）

// ============ 采样历史（用于整机模式的 App 功耗平均值）============
#define SAMPLE_HISTORY_SIZE 60  // 60 个采样点 = 10 分钟（10s 间隔）
#define MAX_TRACKED_UIDS 8      // 每个采样点最多记录的前台 UID 数

struct SampleEntry {
    double battery_mw;                      // 该采样点的电池功率
    uid_t uids[MAX_TRACKED_UIDS];           // 该采样点的前台 UID（固定数组，避免 STL）
    int   uid_count;                        // 实际 UID 数量
};

static SampleEntry g_sample_history[SAMPLE_HISTORY_SIZE];
static int g_sample_history_idx = 0;
static int g_sample_history_count = 0;

// 读取进程的 oom_score_adj（值越低越可能是前台）
static int read_oom_score_adj(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", pid);
    FILE* f = fopen(path, "r");
    if (!f) return 999;
    int val = 999;
    fscanf(f, "%d", &val);
    fclose(f);
    return val;
}

// 找当前前台 App 的 UID（oom_score_adj 最低的第三方 App）
static uid_t find_foreground_uid() {
    DIR* dir = opendir("/proc");
    if (!dir) return (uid_t)-1;

    struct dirent* ent;
    uid_t fg_uid = (uid_t)-1;
    int fg_oom = 999;

    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(ent->d_name);

        // 读 UID
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        FILE* f = fopen(path, "r");
        if (!f) continue;
        uid_t uid = (uid_t)-1;
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                uid = (uid_t)strtoul(line + 4, nullptr, 10);
                break;
            }
        }
        fclose(f);
        if (uid == (uid_t)-1 || uid < 10000) continue;

        int oom = read_oom_score_adj(pid);
        if (oom < fg_oom) {
            fg_oom = oom;
            fg_uid = uid;
        }
    }
    closedir(dir);
    return fg_uid;
}

// 计算某 UID 在历史采样中的平均电池功率（只算它在前台的采样点）
static double calc_avg_battery_for_uid(uid_t uid) {
    if (g_sample_history_count == 0) return 0;
    double sum = 0;
    int count = 0;
    for (int i = 0; i < g_sample_history_count; i++) {
        const SampleEntry& e = g_sample_history[i];
        for (int j = 0; j < e.uid_count; j++) {
            if (e.uids[j] == uid) {
                sum += e.battery_mw;
                count++;
                break;
            }
        }
    }
    return count > 0 ? sum / count : 0;
}

// 自定义标签映射（从 labels.conf 加载）
static std::unordered_map<std::string, std::string> g_custom_labels;
// UID → 包名 映射（从 packages.list 加载）
static std::unordered_map<uid_t, std::string> g_uid_pkg_map;
// 第三方应用 UID 集合（从 pm list packages -3 获取）
static std::unordered_set<uid_t> g_third_party_uids;

static void load_custom_labels(const char* module_dir) {
    g_custom_labels.clear();
    char path[512];
    snprintf(path, sizeof(path), "%s/labels.conf", module_dir);
    FILE* f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char* val = eq + 1;
        char* nl = strchr(val, '\n');
        if (nl) *nl = 0;
        g_custom_labels[line] = val;
    }
    fclose(f);
}

// 尝试从 APK 提取 App 显示名
// 解析二进制 AndroidManifest.xml: 字符串池 + XML树的属性
static bool extract_label_from_apk(const char* apk_path, char* label_out, int label_len) {
    label_out[0] = 0;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "unzip -p '%s' AndroidManifest.xml 2>/dev/null", apk_path);
    FILE* f = popen(cmd, "r");
    if (!f) return false;

    unsigned char buf[131072];
    int n = fread(buf, 1, sizeof(buf), f);
    pclose(f);
    if (n < 28) return false;

    unsigned short type = buf[0] | (buf[1] << 8);
    if (type != 0x0003) return false;

    // 第一步：解析字符串池
    char** strings = nullptr;
    unsigned int str_count = 0;
    int str_pool_end = 0;

    int pos = 8;
    while (pos + 8 < n) {
        unsigned short chunk_type = buf[pos] | (buf[pos+1] << 8);
        unsigned short hdr_size = buf[pos+2] | (buf[pos+3] << 8);
        unsigned int chunk_size = buf[pos+4] | (buf[pos+5]<<8) | (buf[pos+6]<<16) | (buf[pos+7]<<24);
        if (chunk_size < 8 || pos + (int)chunk_size > n) break;

        if (chunk_type == 0x0001 && chunk_size >= 28) {
            str_count = buf[pos+8] | (buf[pos+9]<<8) | (buf[pos+10]<<16) | (buf[pos+11]<<24);
            unsigned int flags = buf[pos+16] | (buf[pos+17]<<8) | (buf[pos+18]<<16) | (buf[pos+19]<<24);
            unsigned int str_start = buf[pos+20] | (buf[pos+21]<<8) | (buf[pos+22]<<16) | (buf[pos+23]<<24);
            bool is_utf8 = (flags & 0x00000100) != 0;

            if (str_count == 0 || str_count > 10000 || str_start < 28 || str_start >= chunk_size) break;

            unsigned int* offsets = (unsigned int*)(buf + pos + 28);
            unsigned char* str_data = buf + pos + str_start;

            strings = (char**)calloc(str_count, sizeof(char*));
            for (unsigned int i = 0; i < str_count; i++) {
                strings[i] = (char*)calloc(1, 512);
                if (pos + 28 + i * 4 + 4 > n) continue;
                unsigned int off = offsets[i];
                if (str_start + off >= chunk_size) continue;
                if (pos + str_start + off >= (unsigned)n) continue;

                unsigned char* p = str_data + off;
                if (is_utf8) {
                    int slen;
                    if (p[0] & 0x80) {
                        if (pos + str_start + off + 2 > n) continue;
                        slen = ((p[0] & 0x7F) << 8) | p[1]; p += 2;
                    } else {
                        slen = p[0]; p += 1;
                    }
                    if (slen > 0 && slen < 500 && pos + str_start + off + slen <= n) {
                        memcpy(strings[i], p, slen);
                        strings[i][slen] = 0;
                    }
                } else {
                    if (pos + str_start + off + 2 > n) continue;
                    int slen = p[0] | (p[1] << 8); p += 2;
                    int j = 0;
                    for (int k = 0; k < slen && j < 490; k++) {
                        if (pos + str_start + off + 2 + k * 2 + 2 > n) break;
                        unsigned short ch = p[k*2] | (p[k*2+1] << 8);
                        if (ch < 0x80) strings[i][j++] = ch;
                        else if (ch < 0x800) { strings[i][j++]=0xC0|(ch>>6); strings[i][j++]=0x80|(ch&0x3F); }
                        else { strings[i][j++]=0xE0|(ch>>12); strings[i][j++]=0x80|((ch>>6)&0x3F); strings[i][j++]=0x80|(ch&0x3F); }
                    }
                    strings[i][j] = 0;
                }
            }
            str_pool_end = pos + chunk_size;
            break;
        }
        pos += chunk_size;
    }

    if (!strings || str_count == 0) return false;

    int idx_application = -1, idx_label = -1, idx_android_ns = -1;
    for (unsigned int i = 0; i < str_count; i++) {
        if (strcmp(strings[i], "application") == 0) idx_application = i;
        if (strcmp(strings[i], "label") == 0) idx_label = i;
        if (strcmp(strings[i], "http://schemas.android.com/apk/res/android") == 0) idx_android_ns = i;
    }

    // 第二步：扫描 XML 树找 <application> 的 label 属性
    bool found = false;
    pos = str_pool_end;
    while (pos + 8 < n) {
        unsigned short chunk_type = buf[pos] | (buf[pos+1] << 8);
        unsigned int chunk_size = buf[pos+4] | (buf[pos+5]<<8) | (buf[pos+6]<<16) | (buf[pos+7]<<24);
        if (chunk_size < 8 || pos + (int)chunk_size > n) break;

        // StartElement (0x0102)
        if (chunk_type == 0x0102 && chunk_size >= 36) {
            unsigned int elem_ns = buf[pos+12] | (buf[pos+13]<<8) | (buf[pos+14]<<16) | (buf[pos+15]<<24);
            unsigned int elem_name = buf[pos+16] | (buf[pos+17]<<8) | (buf[pos+18]<<16) | (buf[pos+19]<<24);
            // Binary XML StartElement layout:
            // +20: attributeStart (u16) - offset from chunk start to first attribute
            // +22: attributeSize (u16) - size of each attribute (usually 20)
            // +24: attributeCount (u16)
            unsigned short attr_start = buf[pos+20] | (buf[pos+21]<<8);
            unsigned short attr_size = buf[pos+22] | (buf[pos+23]<<8);
            unsigned short attr_count = buf[pos+24] | (buf[pos+25]<<8);

            if ((int)elem_name == idx_application && attr_size >= 20 && attr_count > 0) {
                int attr_pos = pos + attr_start;
                for (int a = 0; a < attr_count && attr_pos + attr_size <= pos + (int)chunk_size && attr_pos + 12 <= n; a++) {
                    unsigned int a_ns = buf[attr_pos] | (buf[attr_pos+1]<<8) | (buf[attr_pos+2]<<16) | (buf[attr_pos+3]<<24);
                    unsigned int a_name = buf[attr_pos+4] | (buf[attr_pos+5]<<8) | (buf[attr_pos+6]<<16) | (buf[attr_pos+7]<<24);
                    unsigned int a_val = buf[attr_pos+8] | (buf[attr_pos+9]<<8) | (buf[attr_pos+10]<<16) | (buf[attr_pos+11]<<24);

                    bool ns_ok = ((int)a_ns == idx_android_ns) || (a_ns == 0xFFFFFFFF);
                    if (ns_ok && (int)a_name == idx_label && a_val < str_count && strings[a_val][0]) {
                        strncpy(label_out, strings[a_val], label_len - 1);
                        label_out[label_len - 1] = 0;
                        found = true;
                        break;
                    }
                    attr_pos += attr_size;
                }
                if (found) break;
            }
        }
        pos += chunk_size;
    }

    for (unsigned int i = 0; i < str_count; i++) free(strings[i]);
    free(strings);
    return found;
}

// 用 pm list packages -f 获取所有包名，再逐个提取 label
static void auto_extract_labels(const char* module_dir) {
    char labels_path[512];
    snprintf(labels_path, sizeof(labels_path), "%s/labels.conf", module_dir);

    // 加载已有映射
    std::unordered_map<std::string, std::string> existing;
    {
        FILE* f = fopen(labels_path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (line[0] == '#' || line[0] == '\n') continue;
                char* eq = strchr(line, '=');
                if (!eq) continue;
                *eq = 0;
                char* val = eq + 1;
                char* nl = strchr(val, '\n');
                if (nl) *nl = 0;
                existing[line] = val;
            }
            fclose(f);
        }
    }

    // pm list packages -f
    FILE* pm = popen("pm list packages -f 2>/dev/null", "r");
    if (!pm) return;

    char line[1024];
    int count = 0;
    while (fgets(line, sizeof(line), pm)) {
        char* eq = strrchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char* apk_path = line + 8; // skip "package:"
        char pkg[128];
        strncpy(pkg, eq + 1, sizeof(pkg) - 1);
        char* nl = strchr(pkg, '\n');
        if (nl) *nl = 0;

        if (existing.find(pkg) != existing.end()) continue;

        char label[256] = {};
        if (extract_label_from_apk(apk_path, label, sizeof(label)) && label[0]) {
            existing[pkg] = label;
            count++;
            if (count <= 5) printf("[proc_monitor] %s → %s\n", pkg, label);
        }
    }
    pclose(pm);

    if (count > 0) {
        FILE* f = fopen(labels_path, "w");
        if (f) {
            fprintf(f, "# 自动提取的 App 名称 (%d 个)\n", count);
            for (auto& [pkg, label] : existing) {
                fprintf(f, "%s=%s\n", pkg.c_str(), label.c_str());
            }
            fclose(f);
            printf("[proc_monitor] 共提取 %d 个 App 名称 → %s\n", count, labels_path);
        }
    }

    load_custom_labels(module_dir);
}

// 从 /data/system/packages.list 加载 UID→包名映射
static void load_uid_pkg_map() {
    g_uid_pkg_map.clear();
    const char* paths[] = {
        "/data/system/packages.list",
        "/data/misc/packages.list",
        nullptr
    };
    for (int i = 0; paths[i]; i++) {
        FILE* f = fopen(paths[i], "r");
        if (!f) continue;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            char pkg[128];
            unsigned int uid;
            if (sscanf(line, "%127s %u", pkg, &uid) == 2) {
                g_uid_pkg_map[(uid_t)uid] = pkg;
            }
        }
        fclose(f);
        break;
    }
}

// 用 pm list packages -f 获取用户应用 UID（APK 在 /data/ 下的才是用户应用）
static void load_third_party_uids() {
    g_third_party_uids.clear();
    // pm list packages -f 格式: package:/data/app/~~xxx/base.apk=com.xxx.yyy
    FILE* f = popen("pm list packages -f 2>/dev/null", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        // 检查 APK 路径是否在 /data/ 下（参考 Tweak-Android 的 isSystemApp 逻辑）
        if (strncmp(line, "package:/data/", 14) != 0) continue;
        // 这是用户应用，提取包名
        char* eq = strrchr(line, '=');
        if (!eq) continue;
        char pkg[128];
        strncpy(pkg, eq + 1, sizeof(pkg) - 1);
        char* nl = strchr(pkg, '\n');
        if (nl) *nl = 0;
        // 查找对应的 UID
        for (auto& [uid, pname] : g_uid_pkg_map) {
            if (pname == pkg) {
                g_third_party_uids.insert(uid);
                break;
            }
        }
    }
    pclose(f);
}

// 从 sysfs 读取实际电池功率（mW）
// 参考 Tweak-Android: 从 uevent 文件解析 POWER_SUPPLY_CURRENT_NOW 和 VOLTAGE_NOW
static double read_battery_power_mw() {
    const char* paths[] = {
        "/sys/class/power_supply/bms/uevent",
        "/sys/class/power_supply/battery/uevent",
        nullptr
    };

    double cur_val = 0, vol_val = 0;

    for (int i = 0; paths[i]; i++) {
        FILE* f = fopen(paths[i], "r");
        if (!f) continue;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "POWER_SUPPLY_CURRENT_NOW=", 25) == 0) {
                cur_val = atof(line + 25);
            } else if (strncmp(line, "POWER_SUPPLY_VOLTAGE_NOW=", 25) == 0) {
                vol_val = atof(line + 25);
            } else if (strncmp(line, "POWER_SUPPLY_CONSTANT_CHARGE_CURRENT=", 38) == 0) {
                // 充电时用这个
                if (cur_val == 0) cur_val = atof(line + 38);
            }
        }
        fclose(f);
        if (cur_val != 0 && vol_val != 0) break;
    }

    // 兜底：读单个文件
    if (cur_val == 0) {
        FILE* f = fopen("/sys/class/power_supply/battery/current_now", "r");
        if (f) { fscanf(f, "%lf", &cur_val); fclose(f); }
    }
    if (vol_val == 0) {
        FILE* f = fopen("/sys/class/power_supply/battery/voltage_now", "r");
        if (f) { fscanf(f, "%lf", &vol_val); fclose(f); }
    }

    if (cur_val == 0 || vol_val == 0) return 0;

    cur_val = cur_val < 0 ? -cur_val : cur_val;  // 放电时为负

    // 单位判断（参考 Tweak-Android 的 strToVoltage 逻辑）
    // current: >1e6 → μA，>1000 → mA，否则已是 mA
    double cur_ma;
    if (cur_val > 1e6) cur_ma = cur_val / 1000.0;
    else if (cur_val > 1000) cur_ma = cur_val / 1000.0;
    else cur_ma = cur_val;

    // voltage: >1e6 → μV，>1000 → mV，否则已是 mV
    double vol_mv;
    if (vol_val > 1e6) vol_mv = vol_val / 1000.0;
    else if (vol_val > 1000) vol_mv = vol_val / 1000.0;
    else vol_mv = vol_val;

    // P(mW) = I(mA) × V(mV) / 1000
    return cur_ma * vol_mv / 1000.0;
}

// 包名 → 中文名 映射
static const char* pkg_to_label(const char* pkg) {
    struct { const char* pkg; const char* name; } MAP[] = {
        {"com.tencent.mm",          "微信"},
        {"com.tencent.mobileqq",    "QQ"},
        {"com.tencent.tim",         "TIM"},
        {"com.ss.android.ugc.aweme","抖音"},
        {"com.zhiliaoapp.musically", "TikTok"},
        {"com.xiaomi.misuper",      "小米社区"},
        {"com.xiaomi.mirecycle",    "小米商城"},
        {"com.sina.weibo",          "微博"},
        {"com.taobao.taobao",       "淘宝"},
        {"com.tmall.wireless",      "天猫"},
        {"com.jingdong.app",        "京东"},
        {"com.eg.android.AlipayGphone", "支付宝"},
        {"com.baidu.searchbox",     "百度"},
        {"com.UCMobile",            "UC浏览器"},
        {"com.quark.browser",       "夸克"},
        {"com.android.chrome",      "Chrome"},
        {"com.android.browser",     "浏览器"},
        {"com.google.android.youtube", "YouTube"},
        {"com.spotify.music",       "Spotify"},
        {"com.netease.cloudmusic",  "网易云音乐"},
        {"com.kugou.android",       "酷狗音乐"},
        {"com.tencent.qqmusic",     "QQ音乐"},
        {"tv.danmaku.bili",         "哔哩哔哩"},
        {"com.youku.phone",         "优酷"},
        {"com.iqiyi.player",        "爱奇艺"},
        {"com.ss.android.article.news", "今日头条"},
        {"com.tencent.news",        "腾讯新闻"},
        {"com.sohu.newsclient",     "搜狐新闻"},
        {"com.duokan.reader",       "多看阅读"},
        {"com.chaozh.iReader",      "掌阅"},
        {"com.tencent.weread",      "微信读书"},
        {"com.tencent.qqpimsecure", "腾讯手机管家"},
        {"com.miui.securitycenter", "手机管家"},
        {"com.android.deskclock",   "时钟"},
        {"com.android.calendar",    "日历"},
        {"com.android.camera",      "相机"},
        {"com.miui.gallery",        "相册"},
        {"com.android.mms",         "短信"},
        {"com.android.contacts",    "联系人"},
        {"com.android.settings",    "设置"},
        {"com.android.phone",       "电话"},
        {"com.android.vending",     "Google Play"},
        {"com.xiaomi.market",       "应用商店"},
        {"com.xiaomi.mipicks",      "小米商城"},
        {"com.mi.android.globalFileexplorer", "文件管理"},
        {"com.android.fileexplorer", "文件管理"},
        {"com.miui.notes",          "笔记"},
        {"com.xiaomi.scanner",      "扫一扫"},
        {"com.xiaomi.voiceassistant", "小爱同学"},
        {"com.android.soundrecorder", "录音机"},
        {"com.android.email",       "邮箱"},
        {"com.microsoft.office.outlook", "Outlook"},
        {"com.google.android.gm",   "Gmail"},
        {"com.termux",              "Termux"},
        {"com.topjohnwu.magisk",    "Magisk"},
        {nullptr, nullptr}
    };
    for (int i = 0; MAP[i].pkg; i++) {
        if (strcmp(pkg, MAP[i].pkg) == 0) return MAP[i].name;
    }
    return nullptr;
}

// 从 /proc/<pid>/stat 读 CPU 时间（user + system，单位秒）
static double read_proc_cpu_time(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);

    // 跳过 comm（可能含空格/括号）
    char* p = strchr(buf, ')');
    if (!p) return -1;
    p += 2; // skip ") "

    unsigned long utime = 0, stime = 0;
    // field 14=utime, 15=stime (从 ) 后第12、13个字段)
    int field = 0;
    char* tok = strtok(p, " ");
    while (tok && field < 15) {
        if (field == 11) utime = strtoul(tok, nullptr, 10);
        if (field == 12) stime = strtoul(tok, nullptr, 10);
        tok = strtok(nullptr, " ");
        field++;
    }
    long clk = sysconf(_SC_CLK_TCK);
    if (clk <= 0) clk = 100;
    return (double)(utime + stime) / (double)clk;
}

// 从 /proc/stat 读总 CPU 时间（所有核心，单位秒）
static double read_total_cpu_sec() {
    FILE* f = fopen("/proc/stat", "r");
    if (!f) return 0;
    char line[256];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    fclose(f);
    // 格式: cpu  user nice system idle iowait irq softirq steal
    unsigned long user, nice, sys, idle, iowait, irq, softirq, steal;
    if (sscanf(line, "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
               &user, &nice, &sys, &idle, &iowait, &irq, &softirq, &steal) < 8) return 0;
    long clk = sysconf(_SC_CLK_TCK);
    if (clk <= 0) clk = 100;
    return (double)(user + nice + sys + idle + iowait + irq + softirq + steal) / (double)clk;
}

// 从 /proc/<pid>/status 读 RSS
static int64_t read_proc_rss_kb(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            fclose(f);
            return strtoll(line + 6, nullptr, 10);
        }
    }
    fclose(f);
    return 0;
}

// 从 /proc/<pid>/io 读磁盘 IO
static void read_proc_io(pid_t pid, int64_t& rbytes, int64_t& wbytes) {
    rbytes = wbytes = 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/io", pid);
    FILE* f = fopen(path, "r");
    if (!f) return;  // 可能没权限
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "read_bytes:", 11) == 0)
            rbytes = strtoll(line + 11, nullptr, 10);
        else if (strncmp(line, "write_bytes:", 12) == 0)
            wbytes = strtoll(line + 12, nullptr, 10);
    }
    fclose(f);
}

void power_tracker_init() {
    g_prev_samples.clear();
    g_power_cache.clear();
    g_last_sample_time = 0;
    g_prev_total_cpu_sec = 0;
}

// 带 module_dir 的初始化
void power_tracker_init_with_dir(const char* module_dir) {
    power_tracker_init();
    load_custom_labels(module_dir);
    load_uid_pkg_map();
    load_third_party_uids();
}

// ============ 后台采样线程 ============
static pthread_t g_power_thread;
static std::atomic<bool> g_power_running{false};

static void* power_tracker_thread_func(void*) {
    // 先等 2 秒，让系统稳定
    sleep(2);
    // 首次采样建立基准（不产生有效 delta）
    power_tracker_sample();

    while (g_power_running.load()) {
        sleep(10);
        if (!g_power_running.load()) break;
        power_tracker_sample();
    }
    return nullptr;
}

void power_tracker_start() {
    if (g_power_running.exchange(true)) return; // 已在运行
    pthread_create(&g_power_thread, nullptr, power_tracker_thread_func, nullptr);
    printf("[proc_monitor] power tracker background thread started (10s interval)\n");
}

void power_tracker_stop() {
    if (!g_power_running.exchange(false)) return;
    pthread_join(g_power_thread, nullptr);
    printf("[proc_monitor] power tracker background thread stopped\n");
}

void power_tracker_sample() {
    double now = (double)time(nullptr);
    double dt = g_last_sample_time > 0 ? (now - g_last_sample_time) : 1.0;
    if (dt < 0.5) return;  // 至少间隔 0.5 秒

    // 读总 CPU 时间（用于算绝对占用率）
    double total_cpu_now = read_total_cpu_sec();
    double total_cpu_delta = total_cpu_now - g_prev_total_cpu_sec;
    if (total_cpu_delta < 0) total_cpu_delta = 0;

    // 收集当前快照
    std::unordered_map<uid_t, UidSample> cur_samples;

    DIR* dir = opendir("/proc");
    if (!dir) return;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(ent->d_name);

        // 读 UID
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        FILE* f = fopen(path, "r");
        if (!f) continue;
        uid_t uid = (uid_t)-1;
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                uid = (uid_t)strtoul(line + 4, nullptr, 10);
                break;
            }
        }
        fclose(f);
        if (uid == (uid_t)-1) continue;

        // 只追踪第三方应用（pm list packages -3 的结果）
        if (uid < 10000) continue;
        if (g_third_party_uids.find(uid) == g_third_party_uids.end()) continue;

        double cpu = read_proc_cpu_time(pid);
        if (cpu < 0) continue;

        int64_t rss = read_proc_rss_kb(pid);
        int64_t io_r, io_w;
        read_proc_io(pid, io_r, io_w);

        // 读 comm
        char comm[64] = {};
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        f = fopen(path, "r");
        if (f) { fgets(comm, sizeof(comm), f); fclose(f); }
        char* nl = strchr(comm, '\n');
        if (nl) *nl = 0;

        // 读 cmdline
        char cmdline[128] = {};
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        f = fopen(path, "r");
        if (f) { fread(cmdline, 1, sizeof(cmdline) - 1, f); fclose(f); }

        auto& s = cur_samples[uid];
        s.uid = uid;
        s.cpu_time_sec += cpu;
        s.mem_rss_kb += rss;
        s.io_read += io_r;
        s.io_write += io_w;
        s.proc_count++;
        if (strlen(cmdline) > strlen(s.cmdline))
            strncpy(s.cmdline, cmdline, sizeof(s.cmdline) - 1);
        if (strlen(comm) > 0)
            strncpy(s.comm, comm, sizeof(s.comm) - 1);
    }
    closedir(dir);

    // 计算每个 UID 的 CPU 增量
    std::unordered_map<uid_t, double> cpu_deltas;
    for (auto& [uid, cur] : cur_samples) {
        double prev = 0;
        auto it = g_prev_samples.find(uid);
        if (it != g_prev_samples.end()) prev = it->second.cpu_time_sec;
        double delta = cur.cpu_time_sec - prev;
        if (delta < 0) delta = 0;
        cpu_deltas[uid] = delta;
    }


    // 读取实际电池功率（一次即可）
    g_battery_power_mw = read_battery_power_mw();

    g_power_cache.clear();
    for (auto& [uid, cur] : cur_samples) {
        AppPowerInfo info = {};
        info.uid = uid;

        // 绝对 CPU 占用率（total_cpu_delta 已包含所有核心，无需 *nprocs）
        if (total_cpu_delta > 0 && g_last_sample_time > 0)
            info.cpu_usage_pct = cpu_deltas[uid] / total_cpu_delta * 100.0;
        else
            info.cpu_usage_pct = 0;

        info.cpu_time_sec = cur.cpu_time_sec;
        info.mem_rss_kb = cur.mem_rss_kb;
        info.io_read_bytes = cur.io_read;
        info.io_write_bytes = cur.io_write;
        info.proc_count = cur.proc_count;

        // 提取包名：优先用 packages.list 的映射
        const char* pkg = cur.cmdline;
        auto pkg_it = g_uid_pkg_map.find(uid);
        if (pkg_it != g_uid_pkg_map.end()) {
            pkg = pkg_it->second.c_str();
        } else {
            const char* sp = strrchr(cur.cmdline, ' ');
            if (sp && *(sp + 1)) pkg = sp + 1;
        }
        strncpy(info.package_name, pkg, sizeof(info.package_name) - 1);

        // 显示名：优先用自定义映射 → 内置映射 → 包名最后一段
        const char* label = nullptr;
        // 1. 自定义 labels.conf
        auto it = g_custom_labels.find(pkg);
        if (it != g_custom_labels.end()) label = it->second.c_str();
        // 2. 内置映射
        if (!label) label = pkg_to_label(pkg);
        // 3. 包名最后一段
        if (!label) {
            const char* last_dot = strrchr(pkg, '.');
            if (last_dot && strlen(last_dot + 1) > 1)
                label = last_dot + 1;
            else
                label = cur.comm;
        }
        strncpy(info.label, label, sizeof(info.label) - 1);

        // App 模式功耗：电池功率 × CPU 占比
        if (g_battery_power_mw > 0 && total_cpu_delta > 0 && g_last_sample_time > 0) {
            double frac = cpu_deltas[uid] / total_cpu_delta;
            if (frac > 1.0) frac = 1.0;
            info.power_mw = g_battery_power_mw * frac;
        } else {
            info.power_mw = 0;
        }

        // 整机模式功耗：该 App 在前台时的平均电池功率
        info.avg_battery_mw = calc_avg_battery_for_uid(uid);

        g_power_cache[uid] = info;
    }

    // 记录本次采样到历史环形缓冲区（只记前台 App）
    if (g_battery_power_mw > 0) {
        uid_t fg_uid = find_foreground_uid();
        SampleEntry& entry = g_sample_history[g_sample_history_idx];
        entry.battery_mw = g_battery_power_mw;
        entry.uid_count = 0;
        if (fg_uid != (uid_t)-1 && entry.uid_count < MAX_TRACKED_UIDS) {
            entry.uids[entry.uid_count++] = fg_uid;
        }
        g_sample_history_idx = (g_sample_history_idx + 1) % SAMPLE_HISTORY_SIZE;
        if (g_sample_history_count < SAMPLE_HISTORY_SIZE) g_sample_history_count++;
    }

    g_prev_samples = std::move(cur_samples);
    g_prev_total_cpu_sec = total_cpu_now;
    g_last_sample_time = now;
}

std::vector<AppPowerInfo> power_tracker_get_top(int n) {
    std::vector<AppPowerInfo> result;
    for (auto& [uid, info] : g_power_cache) {
        result.push_back(info);
    }
    std::sort(result.begin(), result.end(),
        [](const AppPowerInfo& a, const AppPowerInfo& b) {
            return a.power_mw > b.power_mw;
        });
    if ((int)result.size() > n) result.resize(n);
    return result;
}
