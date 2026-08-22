# Root-My-Pixel Payloads Makefile
# Builds the CVE-2026-43499 exploit payload for Google Pixel devices.

API ?= 35
TARGET ?= frankel-CP2A.260705.006
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

# ---------------------------------------------------------------------------
# Kernel-family split — DO NOT mix the two source sets.
#
# android15-6.6 targets (mustang/rango/...) compile the PROVEN pre-6.1
# baseline under src/ (slide.c, pselect main route, pre61 kernelsnitch).
# This set is FROZEN: any 6.1 change must go under src/61/, otherwise the
# 6.6 binary drifts from the tested baseline (regression observed 2026-08-10
# when the tokay/6.1 pselect-route rewrite in fops.c broke mustang).
#
# android14-6.1 targets (husky/tegu/lynx/...) compile src/61/* (slide61.c,
# TCP main route, rounded futex_hash) + the mirrored shared TUs that must
# live in src/61/ so their #include "common.h" resolves to src/61/common.h.
# ---------------------------------------------------------------------------
sixone-targets := oriole-CP2A.260705.006 bluejay-CP1A.260405.005 bluejay-CP2A.260705.006 shiba-CP2A.260705.006 husky-CP2A.260705.006 tokay-CP2A.260705.006 komodo-CP2A.260705.006 tegu-CP2A.260705.006 lynx-CP2A.260705.006 panther-CP2A.260705.006 cheetah-CP2A.260705.006 comet-CP2A.260705.006 akita-CP2A.260805.005 caiman-CP2A.260705.006
ifneq ($(filter $(TARGET),$(sixone-targets)),)
SLIDE_SRC := src/61/slide61.c
APP_PRELOAD_SRCS := \
  src/61/main.c \
  src/61/util.c \
  $(SLIDE_SRC) \
  src/61/fops.c \
  src/61/pipe.c \
  src/61/root.c \
  src/61/preload.c
COMMON_INC := -Isrc/61 -Isrc
COMMON_DEPS := src/61/common.h src/61/kernelsnitch/*.h
else
SLIDE_SRC := src/slide.c
APP_PRELOAD_SRCS := \
  src/main.c \
  src/util.c \
  $(SLIDE_SRC) \
  src/fops.c \
  src/pipe.c \
  src/root.c \
  src/preload.c
COMMON_INC := -Isrc
COMMON_DEPS := src/common.h src/kernelsnitch/*.h
endif

COMMON_CFLAGS := \
  -O2 -g0 -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare \
  $(COMMON_INC) -DTARGET_HEADER='"$(TARGET_INCLUDE)"' -DTARGET_CONFIG_H='"$(TARGET_INCLUDE)"'

.DEFAULT_GOAL := all

.PHONY: all clean info release

all: $(APP_PRELOAD) $(ROOT_HELPER)

release: $(APP_RELEASE)

$(OUTDIR):
	mkdir -p $@

$(ROOT_HELPER): src/su_daemon.c | $(OUTDIR)
	$(TARGET_CC) -fPIE -pie -O2 -g0 -Wall -Wextra $< -ldl -o $@

$(APP_PRELOAD): $(APP_PRELOAD_SRCS) $(TARGET_HEADER) src/offset.h $(COMMON_DEPS) | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC $(COMMON_CFLAGS) $(APP_PRELOAD_SRCS) \
	  -shared -pthread -o $@

$(APP_RELEASE): $(APP_PRELOAD_SRCS) $(TARGET_HEADER) src/offset.h $(COMMON_DEPS) | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC -Oz -g0 \
	  -fno-unwind-tables -fno-asynchronous-unwind-tables \
	  -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
	  $(COMMON_INC) -DTARGET_HEADER='"$(TARGET_INCLUDE)"' -DTARGET_CONFIG_H='"$(TARGET_INCLUDE)"' \
	  $(APP_PRELOAD_SRCS) -shared -pthread \
	  -Wl,--gc-sections -Wl,--icf=all -s -o $@

info:
	@echo "TARGET=$(TARGET)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "OUTDIR=$(OUTDIR)"

clean:
	rm -rf $(OUTDIR)

# Convenience targets for common Pixel models
pixel10profold:
	$(MAKE) TARGET=rango-CP2A.260705.006

pixel10pro:
	$(MAKE) TARGET=blazer-CP2A.260705.006

pixel10:
	$(MAKE) TARGET=frankel-CP2A.260705.006

pixel10proxl:
	$(MAKE) TARGET=mustang-CP2A.260705.006

pixel9profold:
	$(MAKE) TARGET=comet-CP2A.260705.006

pixel9pro:
	$(MAKE) TARGET=caiman-CP2A.260705.006

pixel9proxl:
	$(MAKE) TARGET=komodo-CP2A.260705.006

pixel9:
	$(MAKE) TARGET=tokay-CP2A.260705.006

pixel8pro:
	$(MAKE) TARGET=husky-CP2A.260705.006

pixel8:
	$(MAKE) TARGET=shiba-CP2A.260705.006

pixel8a:
	$(MAKE) TARGET=akita-CP2A.260805.005

pixel7a:
	$(MAKE) TARGET=lynx-CP2A.260705.006

pixel7pro:
	$(MAKE) TARGET=cheetah-CP2A.260705.006

pixel7:
	$(MAKE) TARGET=panther-CP2A.260705.006

pixel6a:
	$(MAKE) TARGET=bluejay-CP1A.260405.005
	$(MAKE) TARGET=bluejay-CP2A.260705.006

pixel6:
	$(MAKE) TARGET=oriole-CP2A.260705.006
