# Root-My-Pixel Payloads Makefile
# Builds the CVE-2026-43499 exploit payload for Google Pixel devices.

API ?= 35
TARGET ?= frankel-CP2A.260605.012
OUTDIR ?= build/$(TARGET)

TARGET_HEADER := src/targets/$(TARGET)/target.h
TARGET_INCLUDE := targets/$(TARGET)/target.h
TARGET_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(shell uname -s | tr A-Z a-z)-x86_64/bin/aarch64-linux-android$(API)-clang

ifeq ($(wildcard $(TARGET_CC)),)
$(error set ANDROID_NDK_HOME to an Android NDK containing $(TARGET_CC))
endif

# Output binaries
APP_PRELOAD := $(OUTDIR)/cve-2026-43499-app.so
APP_RELEASE := $(OUTDIR)/cve-2026-43499-app.release.so
ROOT_HELPER := $(OUTDIR)/cve-2026-43499-root

# Source files for the app payload variant (APP_PAYLOAD mode)
APP_PRELOAD_SRCS := \
  src/main.c \
  src/util.c \
  src/slide.c \
  src/fops.c \
  src/pipe.c \
  src/root.c \
  src/preload.c

COMMON_CFLAGS := \
  -O2 -g0 -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare \
  -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"' -DTARGET_CONFIG_H='"$(TARGET_INCLUDE)"'

.DEFAULT_GOAL := all

.PHONY: all clean info release

all: $(APP_PRELOAD) $(ROOT_HELPER)

release: $(APP_RELEASE)

$(OUTDIR):
	mkdir -p $@

$(ROOT_HELPER): src/su_daemon.c | $(OUTDIR)
	$(TARGET_CC) -fPIE -pie -O2 -g0 -Wall -Wextra $< -ldl -o $@

$(APP_PRELOAD): $(APP_PRELOAD_SRCS) $(TARGET_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC $(COMMON_CFLAGS) $(APP_PRELOAD_SRCS) \
	  -shared -pthread -o $@

$(APP_RELEASE): $(APP_PRELOAD_SRCS) $(TARGET_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC -Oz -g0 \
	  -fno-unwind-tables -fno-asynchronous-unwind-tables \
	  -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
	  -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"' -DTARGET_CONFIG_H='"$(TARGET_INCLUDE)"' \
	  $(APP_PRELOAD_SRCS) -shared -pthread \
	  -Wl,--gc-sections -Wl,--icf=all -s -o $@

info:
	@echo "TARGET=$(TARGET)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "OUTDIR=$(OUTDIR)"

clean:
	rm -rf $(OUTDIR)

# Convenience targets for common Pixel models
pixel10:
	$(MAKE) TARGET=frankel-CP2A.260605.012

pixel10proxl:
	$(MAKE) TARGET=mustang-CP2A.260705.006

pixel10profold:
	$(MAKE) TARGET=rango-CP2A.260705.006

pixel9pro:
	$(MAKE) TARGET=caiman-CP2A.260605.012

pixel9proxl:
	$(MAKE) TARGET=komodo-CP2A.260605.012.C1

pixel9:
	$(MAKE) TARGET=tokay-CP2A.260605.012

pixel8pro:
	$(MAKE) TARGET=comet-CP2A.260605.012

pixel8a:
	$(MAKE) TARGET=rango-CP2A.260605.012

pixel7:
	$(MAKE) TARGET=panther-CP2A.260605.012

pixel6:
	$(MAKE) TARGET=oriole-CP2A.260605.012
