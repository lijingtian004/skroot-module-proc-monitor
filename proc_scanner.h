#pragma once
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>
#include <ctime>
#include <atomic>

// 进程事件类型
enum class ProcEventType : uint8_t {
    EXEC    = 0,    // 新进程创建
    EXIT    = 1,    // 进程退出
    ALERT   = 2,    // 可疑进程检测
};

// 单条进程事件记录
struct ProcEvent {
    int64_t     timestamp;      // 毫秒时间戳
    ProcEventType type;
    pid_t       pid;
    pid_t       ppid;
    uid_t       uid;
    char        comm[64];       // 进程名
    char        cmdline[256];   // 完整命令行（截断）
    char        alert_reason[128]; // 告警原因（仅 ALERT 类型有效）
};

// 可疑进程检测规则
struct SuspiciousPattern {
    const char* name;           // 匹配关键字
    const char* reason;         // 告警原因
    bool        match_cmdline;  // 是否同时匹配 cmdline
};

// 可疑进程名单 — 覆盖主流 Root 检测工具
static const SuspiciousPattern SUSPICIOUS_PATTERNS[] = {
    {"momo",                "检测工具: Momo (Root/环境检测)",              true},
    {"Ruru",                "检测工具: Ruru (Root 检测)",                  true},
    {"ruru",                "检测工具: Ruru (Root 检测)",                  true},
    {"frida-server",        "注入框架: Frida Server",                     true},
    {"frida",               "注入框架: Frida",                            false},
    {"magiskd",             "Root守护进程: Magisk",                       false},
    {"magisk",              "Magisk 相关进程",                            false},
    {"lsposed",             "Xposed框架: LSPosed",                        false},
    {"lsposedd",            "Xposed框架: LSPosed Daemon",                 false},
    {"riru",                "注入框架: Riru",                             false},
    {"zygisk",              "注入框架: Zygisk",                           false},
    {"shamiko",             "隐藏模块: Shamiko",                          false},
    {"xposed",              "Xposed框架",                                false},
    {"edxposed",            "Xposed框架: EdXposed",                       false},
    {"kernelsu",            "Root方案: KernelSU",                         false},
    {"apatch",              "Root方案: APatch",                           false},
    {"su",                  "su 二进制调用",                              false},
    {"libfrida-gadget",     "Frida Gadget 注入",                          true},
    {"libriru",             "Riru 注入库",                                true},
    {"strace",              "系统调用跟踪工具",                            false},
    {"ltrace",              "库函数跟踪工具",                              false},
    {"gdb",                 "调试器: GDB",                                false},
    {"gdbserver",           "调试器: GDB Server",                         false},
    {nullptr, nullptr, false}  // 终止标记
};

// ============ 环形缓冲区 ============
#define MAX_EVENTS 4096
#define MAX_ALERTS 512

class EventBuffer {
public:
    void add_event(const ProcEvent& ev) {
        std::lock_guard<std::mutex> lock(mtx_);
        events_[write_idx_ % MAX_EVENTS] = ev;
        write_idx_++;
        if (ev.type == ProcEventType::ALERT) {
            alerts_[alert_idx_ % MAX_ALERTS] = ev;
            alert_idx_++;
        }
    }

    // 返回最近 n 条事件（按时间倒序）
    std::vector<ProcEvent> get_recent(int n) {
        std::lock_guard<std::mutex> lock(mtx_);
        std::vector<ProcEvent> result;
        int total = std::min((int)write_idx_, MAX_EVENTS);
        int count = std::min(n, total);
        for (int i = 0; i < count; i++) {
            int idx = (write_idx_ - 1 - i) % MAX_EVENTS;
            result.push_back(events_[idx]);
        }
        return result;
    }

    // 返回最近 n 条告警
    std::vector<ProcEvent> get_alerts(int n) {
        std::lock_guard<std::mutex> lock(mtx_);
        std::vector<ProcEvent> result;
        int total = std::min((int)alert_idx_, MAX_ALERTS);
        int count = std::min(n, total);
        for (int i = 0; i < count; i++) {
            int idx = (alert_idx_ - 1 - i) % MAX_ALERTS;
            result.push_back(alerts_[idx]);
        }
        return result;
    }

    int64_t total_events() {
        std::lock_guard<std::mutex> lock(mtx_);
        return (int64_t)write_idx_;
    }

    int64_t total_alerts() {
        std::lock_guard<std::mutex> lock(mtx_);
        return (int64_t)alert_idx_;
    }

private:
    std::mutex mtx_;
    ProcEvent events_[MAX_EVENTS] = {};
    ProcEvent alerts_[MAX_ALERTS] = {};
    uint32_t write_idx_ = 0;
    uint32_t alert_idx_ = 0;
};

// 全局事件缓冲区
extern EventBuffer g_event_buf;

// 当前进程信息（用于 /api/procs）
struct ProcInfo {
    pid_t   pid;
    pid_t   ppid;
    uid_t   uid;
    char    comm[64];
    char    cmdline[256];
};

// 进程扫描器接口
int  proc_scanner_init(const char* module_private_dir);
void proc_scanner_start();
void proc_scanner_stop();
void proc_scanner_scan_once();   // 手动触发一次扫描
std::vector<ProcInfo> proc_scanner_get_all_procs();  // 获取当前所有进程

// ============ 充电信息 ============

// 单个 power_supply 设备信息
struct PowerSupplyInfo {
    char name[64];              // 设备名 (battery, usb, ac, wireless...)
    char type[32];              // 类型 (Battery, USB, Mains, Wireless...)
    char status[32];            // 状态 (Charging, Discharging, Full, Not charging)
    char health[32];            // 健康 (Good, Overheat, Dead, Cold...)
    char technology[32];        // 电池技术 (Li-ion, Li-poly...)
    char charge_type[32];       // 充电类型 (Fast, Standard, Trickle, N/A)
    int  capacity;              // 电量百分比 0-100
    int  temp;                  // 温度 (单位 0.1°C)
    int  voltage_uv;            // 电压 (μV)
    int  current_ua;            // 电流 (μA, 负=放电)
    int  input_current_limit_ua; // 输入电流上限 (μA)
    int  charge_full_uah;       // 满电容量 (μAh)
    int  charge_full_design_uah; // 设计容量 (μAh)
    int  pd_allowed;            // PD 充电支持
};

// 完整充电信息快照
struct ChargingInfo {
    PowerSupplyInfo supplies[8]; // 最多 8 个电源设备
    int supply_count;
    int battery_level;          // 主电池电量 %
    int battery_temp;           // 温度 (0.1°C)
    int battery_voltage_mv;     // 电压 mV
    int battery_current_ma;     // 电流 mA
    char battery_status[32];    // 状态
    char battery_health[32];    // 健康
    char battery_technology[32]; // 技术
    char charge_type[32];       // 充电类型
    int  charge_full_uah;       // 满电容量
    int  charge_full_design_uah; // 设计容量
    char charger_speed[16];     // 充电速度等级: slow/normal/fast/super
    int  input_current_ma;      // 输入电流上限 mA
    int  pd_supported;          // PD 支持
};

// 读取当前充电信息
ChargingInfo charging_get_info();

// ============ 悬浮窗实时数据 ============

struct OverlayData {
    // CPU
    double cpu_total_pct;       // 总 CPU 占用 %
    double cpu_per_core[16];    // 每核心占用 %（最多 16 核）
    int    cpu_core_count;

    // GPU
    double gpu_pct;             // GPU 占用 %（-1 表示不可用）
    char   gpu_name[32];        // GPU 驱动名

    // 电池
    double power_mw;            // 实时功率 mW
    int    battery_level;       // 电量 %
    int    battery_temp;        // 温度 0.1°C
    char   battery_status[32];  // 状态

    // 前台应用
    char   fg_app[128];         // 前台 App 包名
    double fg_cpu_pct;          // 前台 App CPU 占用
    int64_t fg_mem_mb;          // 前台 App 内存 MB
};

// 读取悬浮窗实时数据
OverlayData overlay_get_data();

// ============ 应用功耗追踪 ============

// 单个应用(UID)的功耗信息
struct AppPowerInfo {
    uid_t   uid;
    char    package_name[128];  // 包名（从 cmdline 提取）
    char    label[64];          // 显示名（通常是 comm）
    double  cpu_time_sec;       // 累计 CPU 时间（秒）
    double  cpu_usage_pct;      // CPU 占用率 %（占总 CPU 时间的比例）
    int64_t mem_rss_kb;         // RSS 内存 KB
    int64_t io_read_bytes;      // 磁盘读取字节
    int64_t io_write_bytes;     // 磁盘写入字节
    int     proc_count;         // 该 UID 下进程数
    double  power_mw;           // 估算功耗 mW（基于实际电池功率 × CPU占比）
    double  avg_battery_mw;     // 该 App 存活期间的平均电池功率 mW（整机模式用）
};

// 应用功耗追踪接口
void power_tracker_init();
void power_tracker_init_with_dir(const char* module_dir);  // 带 labels.conf 加载
void power_tracker_start();     // 启动后台采样线程（10秒一次）
void power_tracker_stop();      // 停止后台采样
void power_tracker_sample();    // 采样一次（后台线程周期调用）
std::vector<AppPowerInfo> power_tracker_get_top(int n);  // 取 top N 功耗应用
