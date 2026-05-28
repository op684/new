#include "egl.h"
#include "../util/logger.h"
#include "../util/memory.h"
#include "../menu/menu.h"

#include <EGL/egl.h>
#include <dobby.h>

namespace egl_hook {

using SwapBuffersFn = EGLBoolean (*)(EGLDisplay, EGLSurface);
static SwapBuffersFn orig_eglSwapBuffers = nullptr;

static EGLBoolean my_eglSwapBuffers(EGLDisplay display, EGLSurface surface) {
    menu::on_frame(display, surface);
    return orig_eglSwapBuffers(display, surface);
}

void install() {
    void *sym = mem::resolve("libEGL.so", "eglSwapBuffers");
    if (!sym) {
        LOGE("eglSwapBuffers not resolvable");
        return;
    }
    int rc = DobbyHook(sym,
                       reinterpret_cast<void *>(my_eglSwapBuffers),
                       reinterpret_cast<void **>(&orig_eglSwapBuffers));
    if (rc) LOGE("DobbyHook(eglSwapBuffers) failed: %d", rc);
    else    LOGI("eglSwapBuffers hooked at %p", sym);
}

} // namespace egl_hook
