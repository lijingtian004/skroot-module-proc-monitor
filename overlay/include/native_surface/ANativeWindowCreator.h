/*
 * MIT License
 * Based on: https://github.com/AFan4724/AndroidSurfaceImgui-Enhanced
 * Adapted for SKRoot proc_monitor overlay
 */

#ifndef ANativeWindowCreator_H
#define ANativeWindowCreator_H

#include <android/native_window.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "SKRootOverlay"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define ResolveMethod(ClassName, MethodName, Handle, Sig) \
    ClassName##__##MethodName = (decltype(ClassName##__##MethodName))dlsym(Handle, Sig); \
    if (!ClassName##__##MethodName) LOGE("Symbol not found: %s", Sig);

namespace android {

namespace detail {
    struct LayerStack { uint32_t id = UINT32_MAX; };
    enum class Rotation { Rotation0=0, Rotation90=1, Rotation180=2, Rotation270=3 };
    struct Size { int32_t width=-1, height=-1; };
    struct DisplayState { LayerStack layerStack; Rotation orientation=Rotation::Rotation0; Size layerStackSpaceRect; };

    template <typename T> struct sp {
        T* pointer;
        T* operator->() const { return pointer; }
        T* get() const { return pointer; }
        explicit operator bool() const { return pointer != nullptr; }
    };

    struct SurfaceControl;
    struct Surface;

    struct Functionals {
        void (*RefBase__IncStrong)(void*, void*) = nullptr;
        void (*RefBase__DecStrong)(void*, void*) = nullptr;
        sp<void> (*SurfaceComposerClient__GetInternalDisplayToken)() = nullptr;
        std::vector<uint64_t> (*SurfaceComposerClient__GetPhysicalDisplayIds)() = nullptr;
        sp<void> (*SurfaceComposerClient__GetPhysicalDisplayToken)(uint64_t) = nullptr;
        int32_t (*SurfaceComposerClient__GetDisplayState)(sp<void>&, DisplayState*) = nullptr;
        sp<void> (*SurfaceComposerClient__CreateSurface)(void*, const char*, uint32_t, uint32_t, int32_t, uint32_t, void*, void*, uint32_t*) = nullptr;
        void (*SurfaceComposerClient__Transaction__Constructor)(void*) = nullptr;
        void* (*SurfaceComposerClient__Transaction__SetLayer)(void*, sp<void>&, int32_t) = nullptr;
        void* (*SurfaceComposerClient__Transaction__SetTrustedOverlay)(void*, sp<void>&, bool) = nullptr;
        void* (*SurfaceComposerClient__Transaction__Show)(void*, sp<void>&) = nullptr;
        int32_t (*SurfaceComposerClient__Transaction__Apply)(void*, bool, bool) = nullptr;
        sp<Surface> (*SurfaceControl__GetSurface)(void*) = nullptr;
        void (*SurfaceControl__DisConnect)(void*) = nullptr;

        void* (*SurfaceComposerClient__Constructor_Ptr)(void*) = nullptr;
        int32_t (*SurfaceComposerClient__Destructor)(void*) = nullptr;

        size_t systemVersion = 13;

        static Functionals& GetInstance() {
            static Functionals instance;
            return instance;
        }

        Functionals() {
            char ver_str[128] = {0};
            __system_property_get("ro.build.version.release", ver_str);
            systemVersion = atoi(ver_str);
            if (systemVersion < 5) { LOGE("Android version too old: %zu", systemVersion); return; }

            auto libgui = dlopen("/system/lib64/libgui.so", RTLD_LAZY);
            auto libutils = dlopen("/system/lib64/libutils.so", RTLD_LAZY);
            if (!libgui || !libutils) {
                libgui = dlopen("/system/lib/libgui.so", RTLD_LAZY);
                libutils = dlopen("/system/lib/libutils.so", RTLD_LAZY);
            }
            if (!libgui || !libutils) { LOGE("Failed to load libgui/libutils"); return; }

            RefBase__IncStrong = (decltype(RefBase__IncStrong))dlsym(libutils, "_ZNK7android7RefBase9incStrongEPKv");
            RefBase__DecStrong = (decltype(RefBase__DecStrong))dlsym(libutils, "_ZNK7android7RefBase9decStrongEPKv");

            if (systemVersion >= 14) {
                auto ids_fn = (std::vector<uint64_t>(*)())dlsym(libgui, "_ZN7android21SurfaceComposerClient21getPhysicalDisplayIdsEv");
                if (ids_fn) {
                    auto token_fn = (sp<void>(*)(uint64_t))dlsym(libgui, "_ZN7android21SurfaceComposerClient23getPhysicalDisplayTokenENS_17PhysicalDisplayIdE");
                    SurfaceComposerClient__GetPhysicalDisplayIds = ids_fn;
                    SurfaceComposerClient__GetPhysicalDisplayToken = token_fn;
                }
            } else if (systemVersion >= 10) {
                SurfaceComposerClient__GetInternalDisplayToken = (sp<void>(*)())dlsym(libgui, "_ZN7android21SurfaceComposerClient23getInternalDisplayTokenEv");
            }

            if (systemVersion >= 11) {
                SurfaceComposerClient__GetDisplayState = (int32_t(*)(sp<void>&, DisplayState*))dlsym(libgui, "_ZN7android21SurfaceComposerClient15getDisplayStateERKNS_2spINS_7IBinderEEEPNS_2ui12DisplayStateE");
            }

            SurfaceComposerClient__Constructor_Ptr = (void*(*)(void*))dlsym(libgui, "_ZN7android21SurfaceComposerClientC2Ev");

            if (systemVersion >= 14) {
                SurfaceComposerClient__CreateSurface = (sp<void>(*)(void*, const char*, uint32_t, uint32_t, int32_t, uint32_t, void*, void*, uint32_t*))dlsym(libgui, "_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjiiRKNS_2spINS_7IBinderEEENS_3gui13LayerMetadataEPj");
            } else if (systemVersion >= 12) {
                SurfaceComposerClient__CreateSurface = (sp<void>(*)(void*, const char*, uint32_t, uint32_t, int32_t, uint32_t, void*, void*, uint32_t*))dlsym(libgui, "_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjijRKNS_2spINS_7IBinderEEENS_13LayerMetadataEPj");
            } else if (systemVersion >= 11) {
                SurfaceComposerClient__CreateSurface = (sp<void>(*)(void*, const char*, uint32_t, uint32_t, int32_t, uint32_t, void*, void*, uint32_t*))dlsym(libgui, "_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjijPNS_14SurfaceControlENS_13LayerMetadataEPj");
            }

            SurfaceComposerClient__Transaction__Constructor = (void(*)(void*))dlsym(libgui, "_ZN7android21SurfaceComposerClient11TransactionC2Ev");
            SurfaceComposerClient__Transaction__SetLayer = (void*(*)(void*, sp<void>&, int32_t))dlsym(libgui, "_ZN7android21SurfaceComposerClient11Transaction8setLayerERKNS_2spINS_14SurfaceControlEEEi");
            SurfaceComposerClient__Transaction__Show = (void*(*)(void*, sp<void>&))dlsym(libgui, "_ZN7android21SurfaceComposerClient11Transaction4showERKNS_2spINS_14SurfaceControlEEE");
            SurfaceComposerClient__Transaction__Apply = (int32_t(*)(void*, bool, bool))dlsym(libgui, "_ZN7android21SurfaceComposerClient11Transaction5applyEb");
            SurfaceControl__GetSurface = (sp<Surface>(*)(void*))dlsym(libgui, "_ZN7android14SurfaceControl10getSurfaceEv");

            if (systemVersion >= 12) {
                SurfaceComposerClient__Transaction__SetTrustedOverlay = (void*(*)(void*, sp<void>&, bool))dlsym(libgui, "_ZN7android21SurfaceComposerClient11Transaction17setTrustedOverlayERKNS_2spINS_14SurfaceControlEEEb");
            }

            LOGI("ANativeWindowCreator initialized (Android %zu), GetPhysicalDisplayIds=%p, GetPhysicalDisplayToken=%p",
                 systemVersion,
                 (void*)SurfaceComposerClient__GetPhysicalDisplayIds,
                 (void*)SurfaceComposerClient__GetPhysicalDisplayToken);
        }
    };
} // namespace detail

class ANativeWindowCreator {
public:
    struct DisplayInfo { int32_t orientation=0, width=0, height=0; };

    static DisplayInfo GetDisplayInfo() {
        DisplayInfo info{};
        auto& F = detail::Functionals::GetInstance();
        LOGI("GetDisplayInfo: systemVersion=%zu", F.systemVersion);
        detail::sp<void> display;

        if (F.systemVersion >= 14) {
            if (F.SurfaceComposerClient__GetPhysicalDisplayIds) {
                auto ids = F.SurfaceComposerClient__GetPhysicalDisplayIds();
                LOGI("GetPhysicalDisplayIds: count=%zu", ids.size());
                if (!ids.empty()) {
                    display = F.SurfaceComposerClient__GetPhysicalDisplayToken(ids[0]);
                    LOGI("GetPhysicalDisplayToken: %s", display.get() ? "OK" : "NULL");
                }
            } else {
                LOGE("GetPhysicalDisplayIds is NULL");
            }
        } else if (F.systemVersion >= 10) {
            display = F.SurfaceComposerClient__GetInternalDisplayToken();
            LOGI("GetInternalDisplayToken: %s", display.get() ? "OK" : "NULL");
        }

        if (!display.get()) { LOGE("display token is NULL"); return info; }

        detail::DisplayState state{};
        if (F.SurfaceComposerClient__GetDisplayState(display, &state) != 0) return info;

        int32_t pw = state.layerStackSpaceRect.width;
        int32_t ph = state.layerStackSpaceRect.height;
        info.orientation = static_cast<int32_t>(state.orientation);

        if (info.orientation == 0 || info.orientation == 2) {
            info.width = pw < ph ? pw : ph;
            info.height = pw > ph ? pw : ph;
        } else {
            info.width = pw > ph ? pw : ph;
            info.height = pw < ph ? pw : ph;
        }
        return info;
    }

    static ANativeWindow* Create(const char* name, int32_t width = -1, int32_t height = -1) {
        auto& F = detail::Functionals::GetInstance();

        if (width == -1 || height == -1) {
            auto di = GetDisplayInfo();
            width = di.width; height = di.height;
        }

        // Allocate SurfaceComposerClient on stack (constructor writes into it)
        char scc_buf[256] = {0};
        if (F.SurfaceComposerClient__Constructor_Ptr) {
            F.SurfaceComposerClient__Constructor_Ptr(scc_buf);
        }

        // Create surface
        detail::sp<void> surfaceControl;
        if (F.SurfaceComposerClient__CreateSurface) {
            surfaceControl = F.SurfaceComposerClient__CreateSurface(scc_buf, name, width, height, 0x1, 0x00004000, nullptr, nullptr, nullptr);
        }

        if (!surfaceControl.get()) {
            LOGE("CreateSurface failed for %s", name);
            return nullptr;
        }

        // Get ANativeWindow from SurfaceControl
        detail::sp<detail::Surface> surface;
        if (F.SurfaceControl__GetSurface) {
            surface = F.SurfaceControl__GetSurface(surfaceControl.get());
        }

        auto* window = reinterpret_cast<ANativeWindow*>(surface.get());
        if (!window) {
            LOGE("GetSurface failed");
            return nullptr;
        }

        // Show the surface via Transaction
        char txn_buf[256] = {0};
        if (F.SurfaceComposerClient__Transaction__Constructor) {
            F.SurfaceComposerClient__Transaction__Constructor(txn_buf);
            detail::sp<void> scPtr{surfaceControl.get()};
            if (F.SurfaceComposerClient__Transaction__Show) {
                F.SurfaceComposerClient__Transaction__Show(txn_buf, scPtr);
            }
            if (F.SurfaceComposerClient__Transaction__SetTrustedOverlay) {
                F.SurfaceComposerClient__Transaction__SetTrustedOverlay(txn_buf, scPtr, true);
            }
            if (F.SurfaceComposerClient__Transaction__Apply) {
                F.SurfaceComposerClient__Transaction__Apply(txn_buf, false, true);
            }
        }

        // Increment ref count so surface stays alive
        if (F.RefBase__IncStrong && surfaceControl.get()) {
            F.RefBase__IncStrong(surfaceControl.get(), &s_surfaceRefs);
        }

        LOGI("ANativeWindow created: %dx%d %p", width, height, window);
        return window;
    }

    static void Destroy(ANativeWindow* window) {
        if (window) {
            ANativeWindow_release(window);
        }
    }

private:
    static inline void* s_surfaceRefs = nullptr;
};

} // namespace android

#endif
