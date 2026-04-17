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
