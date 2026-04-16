#!/bin/bash
set -e

NDK="/tmp/ndk/android-ndk-r25c"
CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
SYSROOT="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"

KIT="/tmp/module_proc_monitor/_kit_stub"
CXX="$CLANG/aarch64-linux-android31-clang++"
OUT="/tmp/module_proc_monitor/libs/arm64-v8a"
mkdir -p "$OUT"

CXXFLAGS="--target=aarch64-linux-android31 -std=c++20 -fPIC -fvisibility=hidden \
  -fno-stack-protector --sysroot=$SYSROOT \
  -I/tmp/module_proc_monitor -I$KIT/include \
  -DANDROID"

echo "=== Verify stub ==="
cat "$KIT/include/kernel_module_kit_umbrella.h" | head -5
echo "..."
echo "=== Compiling module_proc_monitor.cpp ==="
$CXX $CXXFLAGS -c /tmp/module_proc_monitor/module_proc_monitor.cpp -o $OUT/module_proc_monitor.o 2>&1

echo "=== Compiling proc_scanner.cpp ==="
$CXX $CXXFLAGS -c /tmp/module_proc_monitor/proc_scanner.cpp -o $OUT/proc_scanner.o 2>&1

echo "=== Compiling cJSON.cpp ==="
$CXX $CXXFLAGS -c /tmp/module_proc_monitor/cJSON.cpp -o $OUT/cJSON.o 2>&1

echo "=== Linking ==="
$CXX --target=aarch64-linux-android31 -shared \
  --sysroot=$SYSROOT \
  $OUT/module_proc_monitor.o $OUT/proc_scanner.o $OUT/cJSON.o \
  -static-libstdc++ -lc -lm \
  -o $OUT/libmodule_proc_monitor.so 2>&1

echo "=== Result ==="
file $OUT/libmodule_proc_monitor.so
ls -lh $OUT/
