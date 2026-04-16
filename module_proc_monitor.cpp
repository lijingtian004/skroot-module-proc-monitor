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

// ============ 模块入口 ============

static std::string g_module_dir;

int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("[module_proc_monitor] starting...\n");
    printf("[module_proc_monitor] root_key len=%zu\n", strlen(root_key));
    printf("[module_proc_monitor] module_private_dir=%s\n", module_private_dir);

    g_module_dir = module_private_dir;

    // 初始化扫描器
    proc_scanner_init(module_private_dir);

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
    }

    bool handleGet(CivetServer* server, struct mg_connection* conn,
                   const std::string& path, const std::string& query) override {
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
SKROOT_MODULE_VERSION("1.0.0")
SKROOT_MODULE_DESC("实时监控进程创建/退出，自动检测 Root 检测工具和可疑进程，提供 WebUI 仪表盘")
SKROOT_MODULE_AUTHOR("SKRoot Pro")
SKROOT_MODULE_UUID32("a7c3e1f84b2d4e9f1a6c8d5b3e7f2a90")
SKROOT_MODULE_WEB_UI(ProcMonitorWebHandler)
