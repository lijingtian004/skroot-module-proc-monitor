LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := module_proc_monitor

LOCAL_SRC_FILES := ../module_proc_monitor.cpp ../proc_scanner.cpp ../cJSON.cpp

KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../_kit_stub
LOCAL_C_INCLUDES  += $(KERNEL_MODULE_KIT)/include
LOCAL_LDFLAGS  += $(KERNEL_MODULE_KIT)/lib/libkernel_module_kit_static.a

include $(LOCAL_PATH)/build_macros.mk

include $(BUILD_SHARED_LIBRARY)
