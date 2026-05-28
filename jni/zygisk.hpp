// SPDX-License-Identifier: GPL-3.0-or-later
// Zygisk module API. Mirrors the public header from topjohnwu/Magisk.
// https://github.com/topjohnwu/Magisk/blob/master/native/src/zygisk/api.hpp
#pragma once

#include <jni.h>

#define ZYGISK_API_VERSION 4

namespace zygisk {

struct AppSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jobjectArray &rlimits;
    jint &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jstring &instruction_set;
    jstring &app_data_dir;

    // Available in Android 11+
    jboolean *const is_top_app;
    jobjectArray *const pkg_data_info_list;
    jobjectArray *const whitelisted_data_info_list;
    jboolean *const mount_data_dirs;
    jboolean *const mount_storage_dirs;
};

struct ServerSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jlong &permitted_capabilities;
    jlong &effective_capabilities;
};

enum Option : int {
    FORCE_DENYLIST_UNMOUNT = 0,
    DLCLOSE_MODULE_LIBRARY = 1,
};

enum StateFlag : uint32_t {
    PROCESS_GRANTED_ROOT     = (1u << 0),
    PROCESS_ON_DENYLIST      = (1u << 1),
};

class Api;

class ModuleBase {
public:
    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
};

struct ApiTable;

class Api {
public:
    void setOption(Option opt);
    uint32_t getFlags();
    int connectCompanion();
    int getModuleDir();
    bool pltHookRegister(const char *regex, const char *symbol, void *fn, void **backup);
    bool pltHookExclude(const char *regex, const char *symbol);
    bool pltHookCommit();

private:
    ApiTable *tbl;
};

#define REGISTER_ZYGISK_MODULE(clazz) \
void zygisk_module_entry(zygisk::ApiTable *table, JNIEnv *env) { \
    static clazz module;                                          \
    zygisk_module_init(table, env, &module);                      \
}

#define REGISTER_ZYGISK_COMPANION(func) \
void zygisk_companion_entry(int client) { func(client); }

// Defined in api impl section below.
void zygisk_module_init(ApiTable *table, JNIEnv *env, ModuleBase *module);

struct ApiTable {
    struct {
        ModuleBase *_this;
        void (*preAppSpecialize)(ModuleBase *, AppSpecializeArgs *);
        void (*postAppSpecialize)(ModuleBase *, const AppSpecializeArgs *);
        void (*preServerSpecialize)(ModuleBase *, ServerSpecializeArgs *);
        void (*postServerSpecialize)(ModuleBase *, const ServerSpecializeArgs *);
    } base;

    void (*hookFn)(ApiTable *, Option);
    uint32_t (*getFlags)(ApiTable *);
    int (*connectCompanion)(ApiTable *);
    int (*getModuleDir)(ApiTable *);
    void (*setOption)(ApiTable *, Option);
    bool (*pltHookRegister)(const char *, const char *, void *, void **);
    bool (*pltHookExclude)(const char *, const char *);
    bool (*pltHookCommit)();
};

inline void Api::setOption(Option opt)                    { tbl->setOption(tbl, opt); }
inline uint32_t Api::getFlags()                           { return tbl->getFlags(tbl); }
inline int Api::connectCompanion()                        { return tbl->connectCompanion(tbl); }
inline int Api::getModuleDir()                            { return tbl->getModuleDir(tbl); }
inline bool Api::pltHookRegister(const char *r, const char *s, void *f, void **b) {
    return tbl->pltHookRegister(r, s, f, b);
}
inline bool Api::pltHookExclude(const char *r, const char *s) { return tbl->pltHookExclude(r, s); }
inline bool Api::pltHookCommit()                              { return tbl->pltHookCommit(); }

inline void zygisk_module_init(ApiTable *table, JNIEnv *env, ModuleBase *module) {
    static Api api;
    api = {};
    *reinterpret_cast<ApiTable **>(&api) = table;
    table->base._this = module;
    table->base.preAppSpecialize      = [](ModuleBase *m, AppSpecializeArgs *a)        { m->preAppSpecialize(a); };
    table->base.postAppSpecialize     = [](ModuleBase *m, const AppSpecializeArgs *a)  { m->postAppSpecialize(a); };
    table->base.preServerSpecialize   = [](ModuleBase *m, ServerSpecializeArgs *a)     { m->preServerSpecialize(a); };
    table->base.postServerSpecialize  = [](ModuleBase *m, const ServerSpecializeArgs *a){ m->postServerSpecialize(a); };
    module->onLoad(&api, env);
}

} // namespace zygisk
