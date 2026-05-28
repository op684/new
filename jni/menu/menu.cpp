#include "menu.h"
#include "../mods/manager.h"
#include "../hooks/input.h"
#include "../util/logger.h"

#include <EGL/egl.h>
#include <GLES3/gl3.h>

#include "imgui.h"
#include "backends/imgui_impl_opengl3.h"

namespace menu {

static bool g_inited = false;
static bool g_open   = false;
static int  g_w = 0, g_h = 0;
static double g_last_time = 0;

static double now_seconds() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void init_imgui() {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavNoCaptureKeyboard;
    ImGui::StyleColorsDark();
    ImGui_ImplOpenGL3_Init("#version 300 es");
    LOGI("ImGui initialized");
}

static void draw_ui() {
    ImGui::SetNextWindowPos(ImVec2(40, 80), ImGuiCond_Once);
    ImGui::SetNextWindowSize(ImVec2(420, 520), ImGuiCond_Once);
    if (ImGui::Begin("MCPE Mod Menu", &g_open,
                     ImGuiWindowFlags_NoCollapse |
                     ImGuiWindowFlags_NoSavedSettings)) {
        for (auto *m : mods::all()) {
            bool e = m->enabled();
            if (ImGui::Checkbox(m->name().c_str(), &e)) m->set_enabled(e);
        }
        ImGui::Separator();
        ImGui::TextDisabled("Volume Up to hide");
    }
    ImGui::End();
}

void on_frame(EGLDisplay /*display*/, EGLSurface surface) {
    if (!g_inited) {
        init_imgui();
        g_inited = true;
    }

    if (input_hook::consume_toggle()) g_open = !g_open;
    if (!g_open) {
        mods::dispatch_render();
        return;
    }

    EGLDisplay disp = eglGetCurrentDisplay();
    EGLint w = 0, h = 0;
    eglQuerySurface(disp, surface, EGL_WIDTH,  &w);
    eglQuerySurface(disp, surface, EGL_HEIGHT, &h);
    if (w > 0 && h > 0) { g_w = w; g_h = h; }

    ImGuiIO &io = ImGui::GetIO();
    io.DisplaySize = ImVec2(float(g_w), float(g_h));

    double now = now_seconds();
    io.DeltaTime = g_last_time > 0 ? float(now - g_last_time) : 1.f/60.f;
    g_last_time = now;

    float px, py; bool down;
    if (input_hook::current_pointer(&px, &py, &down)) {
        io.MousePos = ImVec2(px, py);
        io.MouseDown[0] = down;
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui::NewFrame();
    draw_ui();
    mods::dispatch_render();
    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
}

} // namespace menu
