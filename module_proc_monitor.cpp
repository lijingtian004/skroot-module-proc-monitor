//
// module_proc_monitor.cpp — SKRoot Pro 进程行为监控模块
// 功能：/proc 持久扫描 + 可疑进程告警 + WebUI 仪表盘
//

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>

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
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(obj, "apps", arr);

    char* raw = cJSON_PrintUnformatted(obj);
    std::string result(raw);
    cJSON_free(raw);
    cJSON_Delete(obj);
    return result;
}

// ============ 模块入口 ============

static std::string g_module_dir;

int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("[module_proc_monitor] starting...\n");
    printf("[module_proc_monitor] root_key len=%zu\n", strlen(root_key));
    printf("[module_proc_monitor] module_private_dir=%s\n", module_private_dir);

    g_module_dir = module_private_dir;

    // 初始化扫描器
    proc_scanner_init(module_private_dir);
    power_tracker_init_with_dir(module_private_dir);

    // 启动后台守护线程
    proc_scanner_start();

    printf("[module_proc_monitor] proc scanner daemon started\n");

    // skroot_module_main 返回后模块进程结束，
    // 但 WebUI handler 进程会继续运行
    return 0;
}

// ============ WebUI HTTP Handler ============

class ProcMonitorWebHandler : public kernel_module::WebUIHttpHandler {
public:
    void onPrepareCreate(const char* root_key, const char* module_private_dir, uint32_t port) override {
        printf("[proc_monitor] WebUI starting on port %d\n", port);

        // 在 WebUI 进程中也需要启动扫描器
        proc_scanner_init(module_private_dir);
        proc_scanner_start();
        power_tracker_init_with_dir(module_private_dir);
        // 启动后台功耗采样线程（10秒一次）
        power_tracker_start();
    }

    bool handleGet(CivetServer* server, struct mg_connection* conn,
                   const std::string& path, const std::string& query) override {
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
        return false;
    }

    bool handlePost(CivetServer* server, struct mg_connection* conn,
                    const std::string& path, const std::string& body) override {

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

        return false;
    }

    ServerExitAction onBeforeServerExit() override {
        proc_scanner_stop();
        return ServerExitAction::Exit;
    }
};

// ============ SKRoot 模块名片 ============

// 生成 UUID: python3 -c "import uuid; print(uuid.uuid4().hex)"
SKROOT_MODULE_NAME("进程行为监控")
SKROOT_MODULE_VERSION("2.1.8")
SKROOT_MODULE_DESC("实时监控进程创建/退出，自动检测 Root 检测工具和可疑进程，提供 WebUI 仪表盘")
SKROOT_MODULE_AUTHOR("SKRoot Pro")
SKROOT_MODULE_UUID32("a7c3e1f84b2d4e9f1a6c8d5b3e7f2a90")
SKROOT_MODULE_WEB_UI(ProcMonitorWebHandler)
