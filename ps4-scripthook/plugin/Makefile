# OrbisScriptHook — GoldHEN plugin build.
#
# Requires the OpenOrbis PS4 Toolchain (which is what the GoldHEN Plugin SDK
# targets) and LLVM 10+. Set OO_PS4_TOOLCHAIN to your install, or export it
# once in your shell:
#
#   export OO_PS4_TOOLCHAIN=/opt/OpenOrbis/PS4Toolchain
#   make            # -> build/orbis_scripthook.prx
#   make sample     # -> build/godmode_demo.prx
#
# The portable half of this code also builds for the host; see tests/Makefile,
# and run those first — they cover the fiber switch, scheduler, pattern matcher,
# JSON codec and inline detour without needing a console.

OO_PS4_TOOLCHAIN ?= /opt/OpenOrbis/PS4Toolchain
GOLDHEN_SDK      ?= /opt/GoldHEN_Plugins_SDK

TARGET  := orbis_scripthook
BUILD   := build
OUT     := $(BUILD)/$(TARGET).prx

CC      := clang
CXX     := clang++
LD      := ld.lld
CREATE_FSELF := $(OO_PS4_TOOLCHAIN)/bin/linux/create-fself

SOURCES := \
	core/fiber.cpp \
	core/json.cpp \
	core/pattern.cpp \
	core/ringlog.cpp \
	core/scriptmgr.cpp \
	orbis/api.cpp \
	orbis/crossmap.cpp \
	orbis/game.cpp \
	orbis/hook.cpp \
	orbis/ipc.cpp \
	orbis/main.cpp \
	orbis/orbis_compat.cpp

OBJECTS := $(patsubst %.cpp,$(BUILD)/%.o,$(SOURCES))

COMMON_FLAGS := \
	--target=x86_64-scei-ps4-elf \
	-isysroot $(OO_PS4_TOOLCHAIN) \
	-isystem $(OO_PS4_TOOLCHAIN)/include \
	-I$(GOLDHEN_SDK)/include \
	-Iinclude \
	-fPIC -fno-builtin -funwind-tables \
	-O2 -Wall -Wextra -Wno-unused-parameter

CXXFLAGS := $(COMMON_FLAGS) \
	-isystem $(OO_PS4_TOOLCHAIN)/include/c++/v1 \
	-std=c++17 -fno-exceptions -fno-rtti

LDFLAGS := \
	-m elf_x86_64 -pie --script $(OO_PS4_TOOLCHAIN)/link.x \
	--eh-frame-hdr -e plugin_load \
	-L$(OO_PS4_TOOLCHAIN)/lib -L$(GOLDHEN_SDK)/build \
	$(OO_PS4_TOOLCHAIN)/lib/crt1.o

LIBS := -lSceLibcInternal -lkernel -lSceNet -lc++

.PHONY: all sample clean check-toolchain test

all: check-toolchain $(OUT)

check-toolchain:
	@test -d "$(OO_PS4_TOOLCHAIN)" || { \
		echo "OO_PS4_TOOLCHAIN is not set to a real directory ($(OO_PS4_TOOLCHAIN))."; \
		echo "Install the OpenOrbis PS4 Toolchain and export OO_PS4_TOOLCHAIN."; \
		exit 1; }

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BUILD)/$(TARGET).elf: $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

$(OUT): $(BUILD)/$(TARGET).elf
	$(CREATE_FSELF) -in $< -out $(BUILD)/$(TARGET).oelf --lib $@ --paid 0x3800000000000011

# Sample scripts are separate .prx modules loaded by the plugin at runtime.
sample: check-toolchain $(BUILD)/godmode_demo.prx

$(BUILD)/godmode_demo.elf: samples/godmode_demo.cpp
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -c -o $(BUILD)/godmode_demo.o $<
	$(LD) $(LDFLAGS) -e module_start -o $@ $(BUILD)/godmode_demo.o $(LIBS)

$(BUILD)/godmode_demo.prx: $(BUILD)/godmode_demo.elf
	$(CREATE_FSELF) -in $< -out $(BUILD)/godmode_demo.oelf --lib $@ --paid 0x3800000000000011

# Host tests — no toolchain needed.
test:
	$(MAKE) -C tests run

clean:
	rm -rf $(BUILD)
	$(MAKE) -C tests clean
