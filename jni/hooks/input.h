#pragma once
#include <cstdint>

namespace input_hook {

void install();

// Was the menu drawer toggled this frame?
bool consume_toggle();

// Pull the most recent pointer position in window coords.
// Returns false if no pointer event has been seen yet.
bool current_pointer(float *x, float *y, bool *down);

} // namespace input_hook
