#pragma once
#include "../hooks/mcpe.h"
#include <string>

namespace mods {

class Mod {
public:
    explicit Mod(std::string name) : name_(std::move(name)) {}
    virtual ~Mod() = default;

    const std::string &name() const { return name_; }
    bool enabled() const { return enabled_; }
    void set_enabled(bool v) {
        if (v == enabled_) return;
        enabled_ = v;
        if (v) on_enable(); else on_disable();
    }

    virtual void on_enable()  {}
    virtual void on_disable() {}
    virtual void on_tick()    {}
    virtual void on_render()  {}
    virtual bool on_should_render_face(mcpe::BlockLegacy *, int /*face*/) { return true; }

protected:
    std::string name_;
    bool enabled_ = false;
};

} // namespace mods
