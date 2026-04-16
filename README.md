# module_proc_monitor — 进程行为监控模块

## 功能
- 后台 Daemon 持续扫描 `/proc`（800ms 间隔），检测所有进程创建/退出
- 自动匹配 25+ 种可疑进程（momo、Ruru、Frida、Magisk、LSPosed、KernelSU 等）
- 环形缓冲区存储最近 4096 条事件 + 512 条告警
- 内置 WebUI 仪表盘：实时事件流 / 告警面板 / 历史搜索筛选

## 文件结构
```
module_proc_monitor/
├── module_proc_monitor.cpp    # 模块入口 + WebUI HTTP Handler
├── proc_scanner.h             # 扫描器头文件（事件结构、可疑规则、环形缓冲区）
├── proc_scanner.cpp           # /proc 持久扫描守护线程
├── cJSON.cpp / cJSON.h        # JSON 序列化（从现有模块复制）
├── jni/
│   ├── Android.mk             # NDK 构建配置
│   ├── Application.mk         # ABI + STL 配置
│   └── build_macros.mk        # 公共编译参数
└── webroot/
    ├── index.html             # WebUI 页面
    ├── main.js                # 前端逻辑（轮询、渲染、筛选）
    └── style.css              # 暗色主题样式
```

## 编译方法
```bash
# 1. 设置 NDK 环境变量
export ANDROID_NDK=/path/to/android-ndk

# 2. 在 jni/ 目录下执行 ndk-build
cd module_proc_monitor
$ANDROID_NDK/ndk-build NDK_PROJECT_PATH=. NDK_APPLICATION_MK=jni/Application.mk

# 3. 编译产物：libs/arm64-v8a/libmodule_proc_monitor.so
```

## 打包模块 ZIP
```bash
# ZIP 结构：
# ├── module.prop              # 模块描述（由 SKRoot 模块宏生成）
# ├── module_proc_monitor.so   # 编译产物 .so
# └── webroot/                 # WebUI 静态文件
#     ├── index.html
#     ├── main.js
#     └── style.css

# 参考 SKRoot 模块打包指南
zip -r module_proc_monitor.zip module_proc_monitor.so webroot/
```

## WebUI API
| 端点 | 方法 | 参数 | 说明 |
|------|------|------|------|
| `/api/events` | POST | body=`"100"` | 获取最近 N 条事件（JSON 数组） |
| `/api/alerts` | POST | body=`"50"` | 获取最近 N 条告警 |
| `/api/stats` | POST | 无 | 获取统计 `{total_events, total_alerts}` |
| `/api/scan` | POST | 无 | 手动触发一次扫描 |

## 可疑进程检测规则
详见 `proc_scanner.h` 中 `SUSPICIOUS_PATTERNS` 数组，当前覆盖：
- Root 检测工具：momo、Ruru
- Root 方案：Magisk、KernelSU、APatch
- 注入框架：Frida、Riru、Zygisk
- Xposed：LSPosed、EdXposed、Xposed
- 隐藏模块：Shamiko
- 调试工具：GDB、strace、ltrace
