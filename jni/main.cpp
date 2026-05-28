#include "zygisk.hpp"
#include "util/logger.h"
#include "hooks/egl.h"
#include "hooks/input.h"
#include "hooks/mcpe.h"
#include "mods/manager.h"

#include <pthread.h>
#include <string>
#include <unistd.h>

using zygisk::Api;
using zygisk::AppSpecializeArgs;

static void *boot_thread(void *) {
    LOGI("boot thread up; waiting for libminecraftpe.so");
    mods::init();
    mcpe::install();
    egl_hook::install();
    input_hook::install();
    LOGI("all hooks installed");
    return nullptr;
}

class MCPEModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *name = env_->GetStringUTFChars(args->nice_name, nullptr);
        bool ours = name && std::string(name) == "com.mojang.minecraftpe";
        env_->ReleaseStringUTFChars(args->nice_name, name);

        if (!ours) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        LOGI("attaching to com.mojang.minecraftpe (uid=%d)", args->uid);
    }

    void postAppSpecialize(const AppSpecializeArgs *) override {
        pthread_t t;
        pthread_create(&t, nullptr, boot_thread, nullptr);
        pthread_detach(t);
    }

private:
    Api    *api_ = nullptr;
    JNIEnv *env_ = nullptr;
};

REGISTER_ZYGISK_MODULE(MCPEModule)
