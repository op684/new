#pragma once
#include <EGL/egl.h>

namespace menu {

// Called from inside the eglSwapBuffers hook, every frame, before the swap.
// Initializes ImGui on the first call and draws the menu UI.
void on_frame(EGLDisplay display, EGLSurface surface);

} // namespace menu
