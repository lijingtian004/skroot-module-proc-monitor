/*
 * SKRoot proc_monitor ANativeWindowCreator
 * Based on AndroidSurfaceImgui (MIT License)
 * Reference: https://github.com/Bzi-Han/AndroidSurfaceImgui
 */

#ifndef ANativeWindowCreator_H
#define ANativeWindowCreator_H

#include <android/native_window.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include <cstdint>
#include <vector>

#define LOG_TAG "SKRootOverlay"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

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

    struct Functionals {
        // libutils
        void (*RefBase__IncStrong)(void*, void*) = nullptr;
        void (*RefBase__DecStrong)(void*, void*) = nullptr;
        void (*String8__Constructor)(void*, const char*) = nullptr;
        void (*String8__Destructor)(void*) = nullptr;

        // libgui
        void (*LayerMetadata__ctor)(void*) = nullptr;
        void (*SurfaceComposerClient__Constructor)(void*) = nullptr;
        void* (*SCC_getDefault)() = nullptr;  // SurfaceComposerClient::getDefault()
        void* (*SurfaceComposerClient__CreateSurface)(void*, void*, uint32_t, uint32_t, int32_t, uint32_t, void**, void*, uint32_t*) = nullptr;
        sp<void> (*SurfaceComposerClient__GetInternalDisplayToken)() = nullptr;
        std::vector<uint64_t> (*SurfaceComposerClient__GetPhysicalDisplayIds)() = nullptr;
        sp<void> (*SurfaceComposerClient__GetPhysicalDisplayToken)(uint64_t) = nullptr;
        int32_t (*SurfaceComposerClient__GetDisplayState)(sp<void>&, DisplayState*) = nullptr;

        // Transaction
        void (*Transaction__Constructor)(void*) = nullptr;
        void* (*Transaction__SetLayer)(void*, void*, int32_t) = nullptr;
        void* (*Transaction__SetTrustedOverlay)(void*, void*, bool) = nullptr;
        void* (*Transaction__Show)(void*, void*) = nullptr;
        int32_t (*Transaction__Apply)(void*, bool, bool) = nullptr;

        // SurfaceControl
        sp<void> (*SurfaceControl__GetSurface)(void*) = nullptr;

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

            // libutils symbols
            RefBase__IncStrong = (decltype(RefBase__IncStrong))dlsym(libutils, "_ZNK7android7RefBase9incStrongEPKv");
            LOGI("dlsym RefBase::IncStrong: %p %s", (void*)RefBase__IncStrong, dlerror());
            RefBase__DecStrong = (decltype(RefBase__DecStrong))dlsym(libutils, "_ZNK7android7RefBase9decStrongEPKv");
            LOGI("dlsym RefBase::DecStrong: %p %s", (void*)RefBase__DecStrong, dlerror());
            String8__Constructor = (decltype(String8__Constructor))dlsym(libutils, "_ZN7android7String8C2EPKc");
            LOGI("dlsym String8::Ctor: %p %s", (void*)String8__Constructor, dlerror());
            String8__Destructor = (decltype(String8__Destructor))dlsym(libutils, "_ZN7android7String8D2Ev");
            LOGI("dlsym String8::Dtor: %p %s", (void*)String8__Destructor, dlerror());

            // SurfaceComposerClient constructor (C2 for base, works fine)
            SurfaceComposerClient__Constructor = (decltype(SurfaceComposerClient__Constructor))dlsym(libgui, "_ZN7android21SurfaceComposerClientC2Ev");
            LOGI("dlsym SCC::C2: %p %s", (void*)SurfaceComposerClient__Constructor, dlerror());

            // getDefault() - returns pre-initialized SCC instance
            SCC_getDefault = (void*(*)())dlsym(libgui, "_ZN7android21SurfaceComposerClient10getDefaultEv");
            LOGI("dlsym SCC::getDefault: %p %s", (void*)SCC_getDefault, dlerror());

            // createSurface - Android 14+ uses gui::LayerMetadata
            if (systemVersion >= 14) {
                SurfaceComposerClient__CreateSurface = (decltype(SurfaceComposerClient__CreateSurface))dlsym(libgui,
                    "_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjiiRKNS_2spINS_7IBinderEEENS_3gui13LayerMetadataEPj");
                LOGI("dlsym createSurface (A14+ gui::LayerMetadata): %p", (void*)SurfaceComposerClient__CreateSurface);

                // LayerMetadata C2 (base constructor, like AndroidSurfaceImgui)
                LayerMetadata__ctor = (decltype(LayerMetadata__ctor))dlsym(libgui, "_ZN7android3gui13LayerMetadataC2Ev");
                LOGI("dlsym gui::LayerMetadata::C2: %p", (void*)LayerMetadata__ctor);
            } else if (systemVersion >= 12) {
                SurfaceComposerClient__CreateSurface = (decltype(SurfaceComposerClient__CreateSurface))dlsym(libgui,
                    "_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjijRKNS_2spINS_7IBinderEEENS_13LayerMetadataEPj");
                LOGI("dlsym createSurface (A12-13): %p", (void*)SurfaceComposerClient__CreateSurface);

                LayerMetadata__ctor = (decltype(LayerMetadata__ctor))dlsym(libgui, "_ZN7android13LayerMetadataC2Ev");
                LOGI("dlsym LayerMetadata::C2: %p", (void*)LayerMetadata__ctor);
            } else if (systemVersion >= 11) {
                SurfaceComposerClient__CreateSurface = (decltype(SurfaceComposerClient__CreateSurface))dlsym(libgui,
                    "_ZN7android21SurfaceComposerClient13createSurfaceERKNS_7String8EjjijPNS_14SurfaceControlENS_13LayerMetadataEPj");
                LOGI("dlsym createSurface (A11): %p", (void*)SurfaceComposerClient__CreateSurface);
            }

            // Display token methods
            if (systemVersion >= 14) {
                SurfaceComposerClient__GetPhysicalDisplayIds = (decltype(SurfaceComposerClient__GetPhysicalDisplayIds))dlsym(libgui, "_ZN7android21SurfaceComposerClient21getPhysicalDisplayIdsEv");
                SurfaceComposerClient__GetPhysicalDisplayToken = (decltype(SurfaceComposerClient__GetPhysicalDisplayToken))dlsym(libgui, "_ZN7android21SurfaceComposerClient23getPhysicalDisplayTokenENS_17PhysicalDisplayIdE");
            }
            if (systemVersion >= 10 && systemVersion <= 13) {
                SurfaceComposerClient__GetInternalDisplayToken = (decltype(SurfaceComposerClient__GetInternalDisplayToken))dlsym(libgui, "_ZN7android21SurfaceComposerClient23getInternalDisplayTokenEv");
            }
            LOGI("dlsym GetPhysicalDisplayIds: %p GetPhysicalDisplayToken: %p GetInternalDisplayToken: %p",
                 (void*)SurfaceComposerClient__GetPhysicalDisplayIds,
                 (void*)SurfaceComposerClient__GetPhysicalDisplayToken,
                 (void*)SurfaceComposerClient__GetInternalDisplayToken);

            if (systemVersion >= 11) {
                SurfaceComposerClient__GetDisplayState = (decltype(SurfaceComposerClient__GetDisplayState))dlsym(libgui, "_ZN7android21SurfaceComposerClient15getDisplayStateERKNS_2spINS_7IBinderEEEPNS_2ui12DisplayStateE");
                LOGI("dlsym GetDisplayState: %p", (void*)SurfaceComposerClient__GetDisplayState);
            }

            // Transaction
            if (systemVersion >= 12) {
                Transaction__Constructor = (decltype(Transaction__Constructor))dlsym(libgui, "_ZN7android21SurfaceComposerClient11TransactionC2Ev");
            } else if (systemVersion >= 11) {
                // v11 uses copy constructor
                auto copy_ctor = (void(*)(void*, void*))dlsym(libgui, "_ZN7android21SurfaceComposerClient11TransactionC2ERKS1_");
                LOGI("dlsym Transaction::C2(copy): %p", (void*)copy_ctor);
                // We'll handle this differently
            }
            Transaction__SetLayer = (decltype(Transaction__SetLayer))dlsym(libgui, "_ZN7android21SurfaceComposerClient11Transaction8setLayerERKNS_2spINS_14SurfaceControlEEEi");
            if (systemVersion >= 12) {
                Transaction__SetTrustedOverlay = (decltype(Transaction__SetTrustedOverlay))dlsym(libgui, "_ZN7android21SurfaceComposerClient11Transaction17setTrustedOverlayERKNS_2spINS_14SurfaceControlEEEb");
            }
            Transaction__Show = (decltype(Transaction__Show))dlsym(libgui, "_ZN7android21SurfaceComposerClient11Transaction4showERKNS_2spINS_14SurfaceControlEEE");
            if (systemVersion >= 13) {
                Transaction__Apply = (decltype(Transaction__Apply))dlsym(libgui, "_ZN7android21SurfaceComposerClient11Transaction5applyEbb");
            } else if (systemVersion >= 9) {
                auto apply2 = (int32_t(*)(void*, bool))dlsym(libgui, "_ZN7android21SurfaceComposerClient11Transaction5applyEb");
                // Wrap it
                Transaction__Apply = (decltype(Transaction__Apply))(void*)apply2;
            }
            LOGI("dlsym Transaction::C2: %p SetLayer: %p SetTrustedOverlay: %p Show: %p Apply: %p",
                 (void*)Transaction__Constructor, (void*)Transaction__SetLayer,
                 (void*)Transaction__SetTrustedOverlay, (void*)Transaction__Show, (void*)Transaction__Apply);

            // SurfaceControl::getSurface - v12+ uses non-const version
            if (systemVersion >= 12) {
                SurfaceControl__GetSurface = (decltype(SurfaceControl__GetSurface))dlsym(libgui, "_ZN7android14SurfaceControl10getSurfaceEv");
            } else {
                SurfaceControl__GetSurface = (decltype(SurfaceControl__GetSurface))dlsym(libgui, "_ZNK7android14SurfaceControl10getSurfaceEv");
            }
            LOGI("dlsym SurfaceControl::getSurface: %p", (void*)SurfaceControl__GetSurface);

            LOGI("ANativeWindowCreator initialized for Android %zu", systemVersion);
        }
    };
} // namespace detail

class ANativeWindowCreator {
public:
    struct DisplayInfo { int32_t orientation=0, width=0, height=0; };

    static DisplayInfo GetDisplayInfo() {
        DisplayInfo info{};
        auto& F = detail::Functionals::GetInstance();

        detail::sp<void> display;

        // Get display token
        if (F.systemVersion >= 14) {
            // Android 15: skip GetPhysicalDisplayToken (ABI incompatible), use defaults
            if (F.systemVersion >= 15) {
                LOGI("A15: skip GetPhysicalDisplayToken, using defaults 1080x2400");
                info.width = 1080; info.height = 2400; info.orientation = 0;
                return info;
            }
            if (F.SurfaceComposerClient__GetPhysicalDisplayIds && F.SurfaceComposerClient__GetPhysicalDisplayToken) {
                auto ids = F.SurfaceComposerClient__GetPhysicalDisplayIds();
                if (!ids.empty()) {
                    display = F.SurfaceComposerClient__GetPhysicalDisplayToken(ids[0]);
                }
            }
        } else if (F.systemVersion >= 10 && F.SurfaceComposerClient__GetInternalDisplayToken) {
            display = F.SurfaceComposerClient__GetInternalDisplayToken();
        }

        if (!display.get()) {
            LOGE("display token NULL, using defaults");
            info.width = 1080; info.height = 2400;
            return info;
        }

        if (F.SurfaceComposerClient__GetDisplayState && F.systemVersion >= 11) {
            detail::DisplayState state{};
            if (F.SurfaceComposerClient__GetDisplayState(display, &state) == 0) {
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
            }
        }

        if (info.width <= 0) { info.width = 1080; info.height = 2400; }
        return info;
    }

    static ANativeWindow* Create(const char* name, int32_t width = -1, int32_t height = -1) {
        // 直接写 stderr（已 dup2 到日志文件），不依赖 LOGI 宏
        fprintf(stderr, "[Create-RAW] ENTER name=%s\n", name); fflush(stderr);
        auto& F = detail::Functionals::GetInstance();
        fprintf(stderr, "[Create-RAW] Functionals OK ver=%zu\n", F.systemVersion); fflush(stderr);

        if (width <= 0 || height <= 0) {
            auto di = GetDisplayInfo();
            width = di.width; height = di.height;
        }
        fprintf(stderr, "[Create-RAW] display %dx%d\n", width, height); fflush(stderr);

        // 1. Get pre-initialized SurfaceComposerClient
        char scc_buf[4096] = {0};
        void* scc = nullptr;

        fprintf(stderr, "[Create-RAW] SCC_getDefault=%p\n", (void*)F.SCC_getDefault); fflush(stderr);
        if (F.SCC_getDefault) {
            fprintf(stderr, "[Create-RAW] calling getDefault()...\n"); fflush(stderr);
            scc = F.SCC_getDefault();
            fprintf(stderr, "[Create-RAW] getDefault => %p\n", scc); fflush(stderr);
        }

        if (!scc) {
            fprintf(stderr, "[Create-RAW] getDefault null, trying fallback...\n"); fflush(stderr);
            auto scc_ctor_param = (void(*)(void*, void*))dlsym(dlopen("/system/lib64/libgui.so", RTLD_LAZY),
                "_ZN7android21SurfaceComposerClientC1ERKNS_2spINS_3gui22ISurfaceComposerClientEEE");
            fprintf(stderr, "[Create-RAW] C1(ISurfaceComposerClient)=%p\n", (void*)scc_ctor_param); fflush(stderr);
            if (scc_ctor_param) {
                void* null_client = nullptr;
                scc_ctor_param(scc_buf, &null_client);
                scc = scc_buf;
                fprintf(stderr, "[Create-RAW] param ctor done scc=%p\n", scc); fflush(stderr);
            } else if (F.SurfaceComposerClient__Constructor) {
                fprintf(stderr, "[Create-RAW] using C2 ctor=%p\n", (void*)F.SurfaceComposerClient__Constructor); fflush(stderr);
                F.SurfaceComposerClient__Constructor(scc_buf);
                if (F.RefBase__IncStrong) F.RefBase__IncStrong(scc_buf, scc_buf);
                scc = scc_buf;
                fprintf(stderr, "[Create-RAW] C2 done scc=%p\n", scc); fflush(stderr);
            }
        }

        if (!scc) {
            fprintf(stderr, "[Create-RAW] ALL SCC INIT FAILED\n"); fflush(stderr);
            return nullptr;
        }

        // 2. Construct String8
        fprintf(stderr, "[Create-RAW] step 2 String8 ctor=%p\n", (void*)F.String8__Constructor); fflush(stderr);
        char name_buf[1024] = {0};
        if (F.String8__Constructor) {
            F.String8__Constructor(name_buf, name);
            fprintf(stderr, "[Create-RAW] String8 OK\n"); fflush(stderr);
        } else {
            fprintf(stderr, "[Create-RAW] String8 NULL, using strncpy\n"); fflush(stderr);
            strncpy(name_buf, name, sizeof(name_buf)-1);
        }

        // 3. Construct LayerMetadata
        fprintf(stderr, "[Create-RAW] step 3 LayerMetadata ctor=%p\n", (void*)F.LayerMetadata__ctor); fflush(stderr);
        char lm_buf[1024] = {0};
        void* lm_ptr = nullptr;
        if (F.LayerMetadata__ctor) {
            F.LayerMetadata__ctor(lm_buf);
            lm_ptr = lm_buf;
            fprintf(stderr, "[Create-RAW] LayerMetadata OK\n"); fflush(stderr);
        }

        // 4. Create surface
        fprintf(stderr, "[Create-RAW] step 4 CreateSurface=%p\n", (void*)F.SurfaceComposerClient__CreateSurface); fflush(stderr);
        static void* parentHandle = nullptr;
        parentHandle = nullptr;

        if (!F.SurfaceComposerClient__CreateSurface) {
            fprintf(stderr, "[Create-RAW] CreateSurface is NULL!\n"); fflush(stderr);
            if (F.String8__Destructor) F.String8__Destructor(name_buf);
            return nullptr;
        }

        fprintf(stderr, "[Create-RAW] calling CreateSurface...\n"); fflush(stderr);
        void* surfaceControl = F.SurfaceComposerClient__CreateSurface(
            scc, name_buf, (uint32_t)width, (uint32_t)height,
            1 /*RGBA_8888*/, 0 /*flags*/,
            &parentHandle, lm_ptr, nullptr);
        fprintf(stderr, "[Create-RAW] CreateSurface => %p\n", surfaceControl); fflush(stderr);

        if (F.String8__Destructor) F.String8__Destructor(name_buf);

        if (!surfaceControl) {
            fprintf(stderr, "[Create-RAW] CreateSurface FAILED\n"); fflush(stderr);
            return nullptr;
        }

        // 5. Get ANativeWindow from SurfaceControl
        fprintf(stderr, "[Create-RAW] step 5 GetSurface=%p\n", (void*)F.SurfaceControl__GetSurface); fflush(stderr);
        detail::sp<void> surface;
        if (F.SurfaceControl__GetSurface) {
            surface = F.SurfaceControl__GetSurface(surfaceControl);
            fprintf(stderr, "[Create-RAW] GetSurface => %p\n", surface.get()); fflush(stderr);
        }

        auto* window = reinterpret_cast<ANativeWindow*>(surface.get());
        if (!window) {
            fprintf(stderr, "[Create-RAW] window is NULL\n"); fflush(stderr);
            return nullptr;
        }

        // 6. Apply Transaction
        fprintf(stderr, "[Create-RAW] step 6 Transaction ctor=%p ver=%zu\n", (void*)F.Transaction__Constructor, F.systemVersion); fflush(stderr);
        if (F.systemVersion >= 11 && F.Transaction__Constructor) {
            char txn_buf[4096] = {0};
            memset(txn_buf, 0, sizeof(txn_buf));
            F.Transaction__Constructor(txn_buf);
            fprintf(stderr, "[Create-RAW] Transaction constructed\n"); fflush(stderr);

            void* scPtr = surfaceControl;
            if (F.Transaction__SetLayer) {
                F.Transaction__SetLayer(txn_buf, scPtr, INT32_MAX);
                fprintf(stderr, "[Create-RAW] setLayer OK\n"); fflush(stderr);
            }
            if (F.Transaction__Show) {
                F.Transaction__Show(txn_buf, scPtr);
                fprintf(stderr, "[Create-RAW] show OK\n"); fflush(stderr);
            }
            if (F.Transaction__SetTrustedOverlay) {
                F.Transaction__SetTrustedOverlay(txn_buf, scPtr, true);
                fprintf(stderr, "[Create-RAW] setTrustedOverlay OK\n"); fflush(stderr);
            }
            if (F.Transaction__Apply) {
                auto ret = F.Transaction__Apply(txn_buf, false, true);
                fprintf(stderr, "[Create-RAW] apply => %d\n", ret); fflush(stderr);
            } else {
                fprintf(stderr, "[Create-RAW] Apply is NULL!\n"); fflush(stderr);
            }
        }

        if (F.RefBase__IncStrong) F.RefBase__IncStrong(surfaceControl, &surfaceControl);

        fprintf(stderr, "[Create-RAW] DONE window=%p\n", window); fflush(stderr);
        return window;
    }

    static void Destroy(ANativeWindow* window) {
        if (window) {
            ANativeWindow_release(window);
        }
    }
};

} // namespace android

#endif
