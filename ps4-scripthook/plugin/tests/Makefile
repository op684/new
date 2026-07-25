# Host build of the portable code, so the fiber switch, scheduler, pattern
# matcher, native-call ABI and inline detour can be exercised without a console.
# The PS4 is x86-64 like this machine, so these tests cover the real bytes.
#
#   make run

CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O1 -g -Wall -Wextra -Wno-unused-parameter -fno-omit-frame-pointer
BUILD    := build

CORE_SOURCES := ../core/fiber.cpp ../core/json.cpp ../core/pattern.cpp ../core/ringlog.cpp ../core/scriptmgr.cpp
HOOK_SOURCES := ../orbis/hook.cpp ../core/ringlog.cpp

.PHONY: all run clean

all: $(BUILD)/test_core $(BUILD)/test_hook

$(BUILD)/test_core: test_core.cpp $(CORE_SOURCES) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ test_core.cpp $(CORE_SOURCES)

$(BUILD)/test_hook: test_hook.cpp $(HOOK_SOURCES) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ test_hook.cpp $(HOOK_SOURCES)

$(BUILD):
	mkdir -p $(BUILD)

run: all
	$(BUILD)/test_core
	@echo
	$(BUILD)/test_hook

clean:
	rm -rf $(BUILD)
