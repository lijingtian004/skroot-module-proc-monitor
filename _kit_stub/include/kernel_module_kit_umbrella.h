#pragma once
#include <string>
#include <vector>
#include <cstdint>

// SKRoot module metadata macros
#define SKROOT_MODULE_NAME(name)
#define SKROOT_MODULE_VERSION(ver)
#define SKROOT_MODULE_DESC(desc)
#define SKROOT_MODULE_AUTHOR(auth)
#define SKROOT_MODULE_UUID32(uuid)
#define SKROOT_MODULE_WEB_UI(handler)

// Forward declarations
struct CivetServer;
struct mg_connection;

enum class ServerExitAction { Exit, KeepRunning };

// WebUI
namespace kernel_module {
    class WebUIHttpHandler {
    public:
        virtual void onPrepareCreate(const char* root_key, const char* module_private_dir, uint32_t port) {}
        virtual bool handleGet(CivetServer* server, mg_connection* conn, const std::string& path, const std::string& query) { return false; }
        virtual bool handlePost(CivetServer* server, mg_connection* conn, const std::string& path, const std::string& body) { return false; }
        virtual ServerExitAction onBeforeServerExit() { return ServerExitAction::Exit; }
        virtual ~WebUIHttpHandler() {}
    };
    namespace webui {
        inline void send_text(mg_connection* conn, int code, const std::string& text) {}
    }
}
