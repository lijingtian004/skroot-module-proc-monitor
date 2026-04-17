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
