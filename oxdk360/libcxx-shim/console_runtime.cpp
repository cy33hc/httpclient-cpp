/*
 * The C++ runtime entry points clang emits for this target, which nothing else
 * supplies.
 *
 * OXDK's own oxdk360/builtins/builtins.c covers most of this ground and is
 * linked into every title. Three things fall outside it, and this file is those
 * three. They are in the library's archive rather than in a title because they
 * are reached by the library's own code, and a title should not have to know
 * that.
 *
 * ---------------------------------------------------------------------------
 * 1. std::to_string
 *
 * libc++ declares the nine to_string overloads in <string> and defines them in
 * string.cpp, which is part of the compiled library. There is no compiled libc++
 * for this target, and OXDK's libcxx-lib makefile deliberately leaves string.cpp
 * out of its source list: it is the one file that includes <charconv>, and
 * <charconv> in this release reaches into private headers that are not shipped.
 * Building it fails twice over:
 *
 *   string.cpp:9:10: fatal error: '__assert' file not found
 *   string.cpp:133:59: error: reference to unresolved using declaration
 *
 * httpclient-cpp names one of the nine -- the unsigned long long overload, from
 * a byte count -- so the choice is between these few lines and an edit to
 * upstream's source. The signatures are libc++'s, and they have to match it
 * exactly or the definition is a different function and the link still fails.
 *
 * ---------------------------------------------------------------------------
 * 2. _Unwind_Resume and __cxa_rethrow
 *
 * clang emits landing pads for any function that can throw, and a landing pad's
 * exit is _Unwind_Resume. There is no unwinder for this target and none is
 * wanted: OXDK builds with -fno-exceptions, and the one place upstream's source
 * throws is behind a define. These two are the residues that survive that -- they
 * are named by code the optimizer cannot prove unreachable -- so they are
 * defined here to say so and stop, the way libHttpClient's port defines them.
 *
 * ---------------------------------------------------------------------------
 * 3. The __pointer_type_info and __function_type_info vtables
 *
 * This is RTTI's own bookkeeping, and OXDK's builtins already answer most of it:
 * it defines the __class_type_info, __si_class_type_info, __vmi_class_type_info
 * and __enum_type_info vtables as empty arrays, deliberately, so that RTTI links
 * at all. Two more are named by the typeid that a std::function's type erasure
 * emits -- the pointer and function forms -- and those fall in the gap.
 *
 * The shape is the one builtins.c uses: a four-slot table of nulls, and a
 * one-element array whose address is the vtable, forced to the mangled name with
 * an asm label. Null slots are honest here -- with no hierarchy to walk,
 * dynamic_cast answers null and typeid comparisons do not match -- and that is
 * the same bargain the four in builtins.c make.
 *
 * Those three are named by asm labels rather than by anything C++ declares, so
 * <typeinfo> is not included: nothing here names std::type_info.
 */

#include <cstdio>
#include <string>

namespace std {
inline namespace __1 {

namespace {

/* A buffer on the stack rather than a static one: the answer is copied out
 * before the caller sees it, and the XDK's printf makes no promise about a
 * shared buffer. 64 is enough for every integer form at full width and for %f at
 * the default precision, with room to spare. */
constexpr size_t kBufferSize = 64;

template <typename Value>
std::string Format(const char *format, Value value) {
   char buffer[kBufferSize];
   const int written = sprintf(buffer, format, value);
   if (written <= 0)
      return std::string();
   const size_t length = (static_cast<size_t>(written) < kBufferSize)
                             ? static_cast<size_t>(written)
                             : kBufferSize - 1;
   return std::string(buffer, length);
}

} /* namespace */

std::string to_string(int value) { return Format("%d", value); }
std::string to_string(long value) { return Format("%ld", value); }
std::string to_string(long long value) { return Format("%lld", value); }
std::string to_string(unsigned value) { return Format("%u", value); }
std::string to_string(unsigned long value) { return Format("%lu", value); }
std::string to_string(unsigned long long value) { return Format("%llu", value); }

/* Floats go through double, which is what the C variadic promotions produce
 * anyway; %Lf takes the long double directly. The XDK CRT only links its
 * floating point formatter when something references _fltused, and oxdklink
 * forces that into every link, so these reach a real implementation. */
std::string to_string(float value) { return Format("%f", static_cast<double>(value)); }
std::string to_string(double value) { return Format("%f", value); }
std::string to_string(long double value) { return Format("%Lf", value); }

} /* namespace __1 */
} /* namespace std */

extern "C" void DbgPrint(const char *format, ...);
extern "C" void HalReturnToFirmware(unsigned int routine);

namespace {

[[noreturn]] void Unreachable(const char *what) {
   DbgPrint("httpclient: %s reached with no unwinder, stopping\n", what);
   HalReturnToFirmware(1);
   for (;;) {
   }
}

} /* namespace */

extern "C" void _Unwind_Resume(void * /*exception*/) { Unreachable("_Unwind_Resume"); }

extern "C" void __cxa_rethrow() { Unreachable("__cxa_rethrow"); }

/* The two vtables. extern "C" is what keeps the asm label doing the naming:
 * without it clang mangles the name, and the label would end up on something
 * that is not the symbol RTTI asks for.
 *
 * Two objects per vtable, as in builtins.c: the four slots an Itanium vtable
 * begins with, all null because there is no type hierarchy to walk, and a
 * one-element array holding the address of those slots, which is the vtable
 * itself. */
extern "C" {
void *httpclient360_pointer_slots[4]  = {nullptr, nullptr, nullptr, nullptr};
void *httpclient360_function_slots[4] = {nullptr, nullptr, nullptr, nullptr};

/* The asm label first, then the definition. In one declaration clang reads the
 * label as applying to a different entity and reports a redefinition; as a
 * preceding declaration it names the object the definition below provides. */
extern void *httpclient360_pointer_vtable[1] __asm__("_ZTVN10__cxxabiv119__pointer_type_infoE");
extern void *httpclient360_function_vtable[1] __asm__("_ZTVN10__cxxabiv120__function_type_infoE");

void *httpclient360_pointer_vtable[1]  = {httpclient360_pointer_slots};
void *httpclient360_function_vtable[1] = {httpclient360_function_slots};
}
