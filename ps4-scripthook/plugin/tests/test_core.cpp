// Host tests for the portable half of OrbisScriptHook.
//
// The PS4 is x86-64 running a FreeBSD-derived kernel; the fiber switch, the
// scheduler, the pattern matcher and the native-call ABI are all plain user-mode
// code that behaves identically on a Linux x86-64 host. Building them here means
// the tricky parts are actually exercised instead of merely written.
//
//   make -C plugin/tests && plugin/tests/build/test_core

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../core/fiber.h"
#include "../core/joaat.h"
#include "../core/json.h"
#include "../core/native_context.h"
#include "../core/pattern.h"
#include "../core/ringlog.h"
#include "../core/scriptmgr.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const char* what, int line) {
  ++g_checks;
  if (condition) return;
  ++g_failures;
  std::printf("  FAIL (line %d): %s\n", line, what);
}

#define CHECK(cond) check((cond), #cond, __LINE__)

void section(const char* name) { std::printf("== %s\n", name); }

// ---------------------------------------------------------------- fibers

int g_fiber_steps = 0;

void counting_fiber(void* user) {
  auto* fiber = static_cast<osh::Fiber*>(user);
  for (int i = 0; i < 3; ++i) {
    ++g_fiber_steps;
    fiber->yield();
  }
}

// Uses a chunk of stack and recurses a little, to prove the fiber really is
// running on its own mapping and not scribbling over the host stack.
void stack_hungry_fiber(void* user) {
  auto* fiber = static_cast<osh::Fiber*>(user);
  volatile std::uint8_t scratch[32 * 1024];
  for (std::size_t i = 0; i < sizeof(scratch); ++i) scratch[i] = static_cast<std::uint8_t>(i);
  fiber->yield();
  // The point is that the fiber's own stack survived a round trip through the
  // host context untouched.
  bool intact = true;
  for (std::size_t i = 0; i < sizeof(scratch); ++i) {
    if (scratch[i] != static_cast<std::uint8_t>(i)) {
      intact = false;
      break;
    }
  }
  g_fiber_steps = intact ? 42 : -1;
  fiber->yield();
}

void test_fibers() {
  section("fiber context switching");

  osh::Fiber fiber;
  CHECK(fiber.create(&counting_fiber, &fiber));
  CHECK(!fiber.started());
  CHECK(fiber.alive());

  g_fiber_steps = 0;
  fiber.resume();
  CHECK(g_fiber_steps == 1);
  CHECK(fiber.started());
  fiber.resume();
  CHECK(g_fiber_steps == 2);
  fiber.resume();
  CHECK(g_fiber_steps == 3);
  CHECK(!fiber.finished());
  fiber.resume();  // the body returns here
  CHECK(fiber.finished());
  CHECK(!fiber.alive());
  fiber.resume();  // resuming a finished fiber must be a no-op, not a crash
  CHECK(g_fiber_steps == 3);
  fiber.destroy();

  osh::Fiber hungry;
  CHECK(hungry.create(&stack_hungry_fiber, &hungry, 256 * 1024));
  g_fiber_steps = 0;
  hungry.resume();
  hungry.resume();
  CHECK(g_fiber_steps == 42);
  hungry.destroy();

  // Two fibers interleaving keeps each one's locals intact.
  static int order[8];
  static int order_len = 0;
  struct Interleaved {
    static void a(void* user) {
      auto* f = static_cast<osh::Fiber*>(user);
      for (int i = 0; i < 3; ++i) {
        order[order_len++] = 10 + i;
        f->yield();
      }
    }
    static void b(void* user) {
      auto* f = static_cast<osh::Fiber*>(user);
      for (int i = 0; i < 3; ++i) {
        order[order_len++] = 20 + i;
        f->yield();
      }
    }
  };
  osh::Fiber fa;
  osh::Fiber fb;
  CHECK(fa.create(&Interleaved::a, &fa));
  CHECK(fb.create(&Interleaved::b, &fb));
  for (int i = 0; i < 3; ++i) {
    fa.resume();
    fb.resume();
  }
  const int expected[6] = {10, 20, 11, 21, 12, 22};
  CHECK(order_len == 6);
  CHECK(std::memcmp(order, expected, sizeof(expected)) == 0);
}

// -------------------------------------------------------------- scheduler

std::uint64_t g_clock_ms = 0;
std::uint64_t fake_clock() { return g_clock_ms; }

int g_alpha_runs = 0;
int g_beta_runs = 0;
int g_short_runs = 0;

void alpha_script() {
  for (;;) {
    ++g_alpha_runs;
    osh::scriptWait(0);  // every tick
  }
}

void beta_script() {
  for (;;) {
    ++g_beta_runs;
    osh::scriptWait(100);  // every 100 ms
  }
}

void short_script() {
  ++g_short_runs;
  osh::scriptWait(10);
  ++g_short_runs;
  // returns -> should be reaped
}

void test_scheduler() {
  section("script scheduler");

  auto& manager = osh::ScriptManager::instance();
  manager.shutdown();
  manager.set_clock(&fake_clock);
  g_clock_ms = 0;
  g_alpha_runs = g_beta_runs = g_short_runs = 0;

  CHECK(manager.add("alpha", &alpha_script));
  CHECK(manager.add("beta", &beta_script));
  CHECK(!manager.add("alpha", &alpha_script));  // duplicate names rejected
  CHECK(manager.count() == 2);

  manager.tick();
  CHECK(g_alpha_runs == 1);
  CHECK(g_beta_runs == 1);

  // 10 ms later: alpha is due again, beta is still sleeping.
  g_clock_ms = 10;
  manager.tick();
  CHECK(g_alpha_runs == 2);
  CHECK(g_beta_runs == 1);

  g_clock_ms = 99;
  manager.tick();
  CHECK(g_beta_runs == 1);

  g_clock_ms = 100;
  manager.tick();
  CHECK(g_beta_runs == 2);
  CHECK(g_alpha_runs == 4);

  // A script that returns is reaped automatically.
  g_clock_ms = 200;
  CHECK(manager.add("short", &short_script));
  CHECK(manager.count() == 3);
  manager.tick();
  CHECK(g_short_runs == 1);
  g_clock_ms = 210;
  manager.tick();
  CHECK(g_short_runs == 2);
  g_clock_ms = 220;
  manager.tick();  // notices the fiber finished and frees it
  CHECK(manager.count() == 2);

  CHECK(manager.remove("beta"));
  CHECK(!manager.remove("beta"));
  CHECK(manager.count() == 1);

  osh::ScriptInfo info{};
  CHECK(manager.info(0, &info));
  CHECK(std::strcmp(info.name, "alpha") == 0);
  CHECK(info.ticks > 0);
  CHECK(!manager.info(5, &info));

  // scriptWait outside a fiber must return instead of suspending the caller.
  osh::scriptWait(1000);

  manager.shutdown();
  CHECK(manager.count() == 0);
}

// ---------------------------------------------------------------- patterns

void test_patterns() {
  section("pattern scanning");

  const std::uint8_t haystack[] = {0x48, 0x8b, 0x05, 0x11, 0x22, 0x33, 0x44, 0x48, 0x85,
                                   0xc0, 0x90, 0x48, 0x8b, 0x05, 0xaa, 0xbb, 0xcc, 0xdd};

  osh::Pattern pattern;
  CHECK(pattern.compile("48 8B 05 ?? ?? ?? ??"));
  CHECK(pattern.size() == 7);

  const std::uint8_t* first = pattern.find(haystack, sizeof(haystack));
  CHECK(first == haystack);
  const std::uint8_t* second = pattern.find_nth(haystack, sizeof(haystack), 1);
  CHECK(second == haystack + 11);
  CHECK(pattern.find_nth(haystack, sizeof(haystack), 2) == nullptr);
  CHECK(pattern.count(haystack, sizeof(haystack), 8) == 2);

  osh::Pattern exact;
  CHECK(exact.compile("48 85 C0"));
  CHECK(exact.find(haystack, sizeof(haystack)) == haystack + 7);

  osh::Pattern missing;
  CHECK(missing.compile("DE AD BE EF"));
  CHECK(missing.find(haystack, sizeof(haystack)) == nullptr);

  // Malformed input is rejected rather than silently mis-parsed.
  osh::Pattern bad;
  CHECK(!bad.compile("48 ZZ"));
  CHECK(!bad.compile("4"));
  CHECK(!bad.compile(""));
  CHECK(!bad.compile(nullptr));

  // Single-token and lowercase patterns both work.
  osh::Pattern one;
  CHECK(one.compile("90"));
  CHECK(one.find(haystack, sizeof(haystack)) == haystack + 10);
  osh::Pattern lower;
  CHECK(lower.compile("48 8b 05"));
  CHECK(lower.find(haystack, sizeof(haystack)) == haystack);

  // RIP-relative resolution: "48 8B 05 <disp32>" is 7 bytes long and the
  // displacement starts at +3, so a disp of +0x10 targets hit+7+0x10.
  std::uint8_t insn[16] = {0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00};
  CHECK(osh::rip_target(insn, 3, 7) == insn + 7 + 0x10);
  std::int32_t negative = -0x20;
  std::memcpy(insn + 3, &negative, sizeof(negative));
  CHECK(osh::rip_target(insn, 3, 7) == insn + 7 - 0x20);
}

// ----------------------------------------------------------- native context

// Stand-in for a real native handler: reads two args and writes a result the
// same way the engine's handlers do.
void fake_add_native(osh::NativeContext* context) {
  const std::uint64_t* args = context->slots();
  std::int32_t a = 0;
  std::int32_t b = 0;
  std::memcpy(&a, &args[0], sizeof(a));
  std::memcpy(&b, &args[1], sizeof(b));
  const std::int32_t sum = a + b;
  // Handlers write through the return pointer, which aliases slot 0.
  std::memcpy(const_cast<std::uint64_t*>(&args[0]), &sum, sizeof(sum));
}

void fake_vector_native(osh::NativeContext* context) {
  auto* slots = const_cast<std::uint64_t*>(context->slots());
  const float components[3] = {1.5f, -2.5f, 3.25f};
  for (int i = 0; i < 3; ++i) {
    slots[i] = 0;
    std::memcpy(&slots[i], &components[i], sizeof(float));
  }
}

void test_native_context() {
  section("native call ABI");

  // Compile-time assertions on the engine-visible field offsets.
  osh::NativeContext::verify_layout();
  CHECK(sizeof(void*) == 8);

  osh::NativeContext context;
  CHECK(context.arg_count() == 0);
  CHECK(context.push<std::int32_t>(20));
  CHECK(context.push<std::int32_t>(22));
  CHECK(context.arg_count() == 2);

  osh::NativeHandler handler = &fake_add_native;
  handler(&context);
  CHECK(context.result<std::int32_t>() == 42);

  // Floats keep their bit pattern through a slot.
  context.reset();
  CHECK(context.arg_count() == 0);
  CHECK(context.push<float>(1.25f));
  CHECK(context.slots()[0] != 0);
  float roundtrip = 0.0f;
  std::memcpy(&roundtrip, &context.slots()[0], sizeof(roundtrip));
  CHECK(roundtrip == 1.25f);

  // Pushing a narrow value must zero the rest of the slot, or a native reading
  // 8 bytes sees garbage from a previous call.
  context.reset();
  CHECK(context.push<std::uint64_t>(0xffffffffffffffffull));
  context.reset();
  CHECK(context.push<std::uint8_t>(1));
  CHECK(context.slots()[0] == 1);

  // Vector3 arguments expand to three float slots.
  context.reset();
  CHECK(context.push_vector({1.0f, 2.0f, 3.0f}));
  CHECK(context.arg_count() == 3);

  // Vector3 results are one component per slot.
  context.reset();
  fake_vector_native(&context);
  const osh::Vector3 v = context.vector_result();
  CHECK(v.x == 1.5f);
  CHECK(v.y == -2.5f);
  CHECK(v.z == 3.25f);

  // The argument array is bounded.
  context.reset();
  for (std::uint32_t i = 0; i < osh::NativeContext::kMaxArgs; ++i) {
    CHECK(context.push<std::int32_t>(static_cast<std::int32_t>(i)));
  }
  CHECK(!context.push<std::int32_t>(999));
}

// ---------------------------------------------------------------- misc

void test_joaat() {
  section("joaat");
  // Verified against an independent implementation of Jenkins one-at-a-time.
  CHECK(osh::joaat("") == 0u);
  CHECK(osh::joaat("GET_PLAYER_PED") == 0x6e31e993u);
  CHECK(osh::joaat("SET_ENTITY_COORDS") == 0xdf70b41bu);
  CHECK(osh::joaat("ADDER") == osh::joaat("adder"));
  // constexpr evaluation works, so hashes can be baked into switch labels.
  static_assert(osh::joaat("adder") == osh::joaat("ADDER"), "joaat must be constexpr");
}

void test_ringlog() {
  section("ring log");
  osh::RingLog log;
  CHECK(log.size() == 0);
  log.writef("hello %d", 42);
  CHECK(log.size() == 1);

  std::vector<char> out(osh::RingLog::kLines * osh::RingLog::kLineLength);
  CHECK(log.tail(out.data(), 10) == 1);
  CHECK(std::strcmp(out.data(), "hello 42") == 0);

  // Overflow keeps the newest lines and counts the losses.
  for (std::size_t i = 0; i < osh::RingLog::kLines + 5; ++i) log.writef("line %zu", i);
  CHECK(log.size() == osh::RingLog::kLines);
  CHECK(log.dropped() == 6);  // 1 seed line + 5 overflowed
  const std::size_t got = log.tail(out.data(), 3);
  CHECK(got == 3);
  char expected[64];
  std::snprintf(expected, sizeof(expected), "line %zu", osh::RingLog::kLines + 4);
  CHECK(std::strcmp(out.data() + 2 * osh::RingLog::kLineLength, expected) == 0);

  // Over-long lines are truncated, never overflowed.
  osh::RingLog small;
  std::string huge(osh::RingLog::kLineLength * 2, 'x');
  small.write(huge.c_str());
  CHECK(small.tail(out.data(), 1) == 1);
  CHECK(std::strlen(out.data()) == osh::RingLog::kLineLength - 1);
}

void test_json() {
  section("json reader / writer");

  // A realistic control-channel request.
  char request[] =
      R"({"op":"native","name":"SET_ENTITY_HEALTH","return_type":"void",)"
      R"("args":[{"type":"int","value":42},{"type":"float","value":1.5},)"
      R"({"type":"bool","value":true},{"type":"string","value":"hi \"there\"\n"}]})";

  osh::Json json;
  CHECK(json.parse(request, std::strlen(request)));
  CHECK(std::strcmp(json.string_field(json.root(), "op"), "native") == 0);
  CHECK(std::strcmp(json.string_field(json.root(), "name"), "SET_ENTITY_HEALTH") == 0);
  CHECK(std::strcmp(json.string_field(json.root(), "missing", "fallback"), "fallback") == 0);

  const int args = json.find(json.root(), "args");
  CHECK(json.type(args) == osh::Json::Type::kArray);
  CHECK(json.size(args) == 4);

  int arg = json.first_child(args);
  CHECK(std::strcmp(json.string_field(arg, "type"), "int") == 0);
  CHECK(json.number_field(arg, "value") == 42.0);

  arg = json.next_sibling(arg);
  CHECK(json.number_field(arg, "value") == 1.5);

  arg = json.next_sibling(arg);
  CHECK(json.bool_field(arg, "value"));

  arg = json.next_sibling(arg);
  // Escapes are decoded in place.
  CHECK(std::strcmp(json.string_field(arg, "value"), "hi \"there\"\n") == 0);
  CHECK(json.next_sibling(arg) == osh::Json::kNone);

  // Hex strings are accepted where a number is expected, which is how the MCP
  // server sends native hashes.
  char hashed[] = R"({"hash":"0xDEADBEEF","count":7})";
  osh::Json numbers;
  CHECK(numbers.parse(hashed, std::strlen(hashed)));
  CHECK(numbers.number_field(numbers.root(), "hash") == 3735928559.0);
  CHECK(numbers.number_field(numbers.root(), "count") == 7.0);

  // Malformed input is rejected, not half-parsed.
  const char* bad[] = {"{", "{\"a\":}", "{\"a\" 1}", "[1,2", "\"unterminated", "{} trailing"};
  for (const char* text : bad) {
    char scratch[64];
    std::snprintf(scratch, sizeof(scratch), "%s", text);
    osh::Json broken;
    CHECK(!broken.parse(scratch, std::strlen(scratch)));
    CHECK(std::strlen(broken.error()) > 0);
  }

  char empty_object[] = "{}";
  osh::Json empty;
  CHECK(empty.parse(empty_object, 2));
  CHECK(empty.size(empty.root()) == 0);

  // Writer round-trips through the reader.
  char out[512];
  osh::JsonWriter writer(out, sizeof(out));
  writer.begin_object();
  writer.field_bool("ok", true);
  writer.field_number("result", 328);
  writer.field_string("note", "quote \" and \\ and newline \n");
  writer.key("lines");
  writer.begin_array();
  writer.value_string("one");
  writer.value_string("two");
  writer.end_array();
  writer.end_object();
  CHECK(!writer.overflowed());

  osh::Json reparsed;
  CHECK(reparsed.parse(out, writer.length()));
  CHECK(reparsed.bool_field(reparsed.root(), "ok"));
  CHECK(reparsed.number_field(reparsed.root(), "result") == 328.0);
  CHECK(std::strcmp(reparsed.string_field(reparsed.root(), "note"),
                    "quote \" and \\ and newline \n") == 0);
  CHECK(reparsed.size(reparsed.find(reparsed.root(), "lines")) == 2);

  // A tiny buffer truncates and reports it rather than running off the end.
  char tiny[8];
  osh::JsonWriter small(tiny, sizeof(tiny));
  small.begin_object();
  small.field_string("a", "a very long value indeed");
  small.end_object();
  CHECK(small.overflowed());
  CHECK(std::strlen(tiny) < sizeof(tiny));
}

}  // namespace

int main() {
  test_fibers();
  test_scheduler();
  test_patterns();
  test_native_context();
  test_joaat();
  test_ringlog();
  test_json();

  std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
