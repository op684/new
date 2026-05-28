#include "input.h"
#include "../util/logger.h"
#include "../util/memory.h"

#include <android/input.h>
#include <atomic>
#include <dobby.h>

namespace input_hook {

static std::atomic<bool> g_toggle{false};
static std::atomic<float> g_x{0}, g_y{0};
static std::atomic<bool>  g_down{false};
static std::atomic<bool>  g_have_pointer{false};

using GetEventFn = int32_t (*)(void *queue, AInputEvent **outEvent);
static GetEventFn orig_AInputQueue_getEvent = nullptr;

static int32_t my_AInputQueue_getEvent(void *queue, AInputEvent **outEvent) {
    int32_t rc = orig_AInputQueue_getEvent(queue, outEvent);
    if (rc < 0 || !outEvent || !*outEvent) return rc;

    AInputEvent *ev = *outEvent;
    int32_t type = AInputEvent_getType(ev);
    if (type == AINPUT_EVENT_TYPE_KEY) {
        int32_t kc = AKeyEvent_getKeyCode(ev);
        int32_t action = AKeyEvent_getAction(ev);
        // Volume Up = AKEYCODE_VOLUME_UP (24)
        if (kc == AKEYCODE_VOLUME_UP && action == AKEY_EVENT_ACTION_DOWN) {
            if (AKeyEvent_getRepeatCount(ev) == 0) {
                g_toggle.store(true, std::memory_order_release);
            }
        }
    } else if (type == AINPUT_EVENT_TYPE_MOTION) {
        size_t idx = 0;
        g_x.store(AMotionEvent_getX(ev, idx), std::memory_order_release);
        g_y.store(AMotionEvent_getY(ev, idx), std::memory_order_release);
        int32_t action = AMotionEvent_getAction(ev) & AMOTION_EVENT_ACTION_MASK;
        bool down = action == AMOTION_EVENT_ACTION_DOWN
                 || action == AMOTION_EVENT_ACTION_POINTER_DOWN
                 || action == AMOTION_EVENT_ACTION_MOVE;
        g_down.store(down, std::memory_order_release);
        g_have_pointer.store(true, std::memory_order_release);
    }
    return rc;
}

void install() {
    void *sym = mem::resolve("libandroid.so", "AInputQueue_getEvent");
    if (!sym) {
        LOGE("AInputQueue_getEvent not resolvable");
        return;
    }
    int rc = DobbyHook(sym,
                       reinterpret_cast<void *>(my_AInputQueue_getEvent),
                       reinterpret_cast<void **>(&orig_AInputQueue_getEvent));
    if (rc) LOGE("DobbyHook(AInputQueue_getEvent) failed: %d", rc);
    else    LOGI("AInputQueue_getEvent hooked at %p", sym);
}

bool consume_toggle() {
    return g_toggle.exchange(false, std::memory_order_acq_rel);
}

bool current_pointer(float *x, float *y, bool *down) {
    if (!g_have_pointer.load(std::memory_order_acquire)) return false;
    *x = g_x.load(std::memory_order_acquire);
    *y = g_y.load(std::memory_order_acquire);
    *down = g_down.load(std::memory_order_acquire);
    return true;
}

} // namespace input_hook
