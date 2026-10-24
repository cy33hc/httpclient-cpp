# httpclient-cpp on the Xbox 360, with OXDK

httpclient-cpp is a C++ wrapper around libcurl: one `CHTTPClient` object that
owns a curl easy handle and turns it into `GetText`, `DownloadFile`,
`UploadForm`, the REST verbs, a headers map and a response body. Upstream builds
it with CMake against whatever libcurl the host has.

This is the same library as OXDK builds it for the Xbox 360, compiled against
the port's libcurl, into a static archive a title links in two lines.

```
Makefile.oxdk360                   the build
oxdk360/flags.mk                   asks OXDK for the Xbox 360 flags
oxdk360/include/httpclient360.h    the one thing the source needs forced in
oxdk360/libcxx-shim/               the C++ runtime pieces nothing else supplies
oxdk360/httpclient360.mk.in        the glue a title includes, once installed
oxdk360/test/                      a title that links and exercises the library
```

## Build

```sh
make -f Makefile.oxdk360
```

That writes `build-oxdk360/libhttpclient.a` and, if it is missing,
`build-oxdk360/libcxx/libcxx-xenon.a`. The second one is libc++'s compiled half
for this target and is not optional -- see [libc++](#libc) below. The compiler and
flags are not copied from anywhere: `oxdk360/flags.mk` asks OXDK what it would use
for the Xbox 360 and the answer is written to `build-oxdk360/toolchain.mk`, so
this archive and a title built by `xbox360/xbox360.mk` cannot disagree about the
Xenon ABI or the libc++ configuration. After an OXDK change:
`make -f Makefile.oxdk360 refresh-flags`.

**libcurl has to be installed first.** It is a separate port and a sibling of
this tree:

```sh
cd ../curl && make -f Makefile.oxdk360 install
```

Useful targets:

```sh
make -f Makefile.oxdk360 core                          # just this library's sources
make -f Makefile.oxdk360 libcxx                        # just libc++'s compiled half
make -f Makefile.oxdk360 probe PROBE=HTTP/HTTPClient.cpp   # syntax-check one file
make -f Makefile.oxdk360 install                       # into $(OXDK_DIR)/xbox360/third-party/httpclient
make -f Makefile.oxdk360 check-install                 # install privately, then build a title from the fragment
make -f Makefile.oxdk360 linkcheck                     # build that title against the real prefix
make -f Makefile.oxdk360 check                         # and run xexcheck.py on it
make -f Makefile.oxdk360 clean
```

Two variables change what is built. `DEBUG_CURL` is 1, as upstream has it; set it
to 0 and the trace machinery *and* every log line are compiled out (see [one switch
for everything the library
says](#one-switch-for-everything-the-library-says-debug_curl)). `BUILD` moves the
output directory. Neither is a prerequisite of the objects, so a change to one needs
`make -f Makefile.oxdk360 clean` first.

## Install and use it in a title

```sh
make -f Makefile.oxdk360 install
```

installs to `$(OXDK_DIR)/xbox360/third-party/httpclient`, the layout zlib,
bzip2, json-c, lexbor, libarchive, XboxTLS, libcurl and libHttpClient already
use. `PREFIX=` puts it somewhere else.

A title then needs one include:

```make
OXDK_DIR       := /path/to/OXDK
OXDK_TARGET    := xbox360
XENON_ABI      := 1
OXDK360_LIBCXX := 1
SRCS           := main.cpp
XEX_TITLE      := mytitle

include $(OXDK_DIR)/oxdk.mk
include $(OXDK_DIR)/xbox360/third-party/httpclient/oxdk360/httpclient360.mk

CXXFLAGS += $(HTTPCLIENT360_CFLAGS)
OBJS     += $(HTTPCLIENT360_OBJS)
```

and the source uses the upstream API unchanged:

```cpp
#include "HTTPClient.h"

CHTTPClient client([](const std::string &line) { DbgPrint("%s\n", line.c_str()); });

client.InitSession(false, CHTTPClient::ENABLE_LOG);

std::string body;
long code = 0;
client.GetText("http://example.com/", body, code);

client.CleanupSession();
```

`CXXFLAGS` and not `CFLAGS`, because `xbox360.mk`'s rule for a `.cpp` file is
`$(CLANG) $(OXDK360_CXXFLAGS) $(CXXFLAGS)` and its C rule is the one that reads
`CFLAGS`. `OXDK360_LIBCXX := 1` because this library is compiled against OXDK's
libc++ and links its compiled half; a title that takes the XDK's own C++ headers
instead has two spellings of `std::string` on one link line. The fragment's
header comment spells all of this out.

## Check the port

```sh
make -f Makefile.oxdk360 check-install    # install privately, build and link a title
make -f Makefile.oxdk360 check            # the same title against the real prefix, then xexcheck.py
XBDM_HOST=192.168.1.50 make -C oxdk360/test deploy
XBDM_HOST=192.168.1.50 make -C oxdk360/test watch
```

`oxdk360/test` is a title that uses the public API: it reports libcurl's version
and TLS backend, constructs a `CHTTPClient` with a log callback, opens a session,
performs an HTTP GET and then an HTTPS one, and cleans up. It is the link check
first -- it resolves every symbol the library reaches, from the archive, from
libc++'s compiled half, from libcurl, from BearSSL and from the XDK libraries the
curl fragment appends -- and a functional test second. Its output goes to
`DbgPrint`, which XBDM relays, so `make watch` shows it.

`check-install` is the path a real title takes and is a different one through the
flags: there the fragment supplies the include directories, the definitions, the
force-include and the archives, and OXDK's own libc++ runtime object has to
compile with them.

As built here the XEX passes OXDK's own `xexutil/xexcheck.py`: 20 pages, 148
imports. It is also built from the installed fragment alone, by
`make -f Makefile.oxdk360 check-install`, which is the path a title in another
directory takes.

## Installing

`make -f Makefile.oxdk360 install` writes into
`$(OXDK_DIR)/xbox360/third-party/httpclient` -- the same prefix zlib, bzip2,
json-c, lexbor, libarchive, XboxTLS, libcurl and libHttpClient install into --
and that path is outside this repository, so a sandboxed or read-only build may
not be allowed to write it. When it is not, either of these does the same job:

```sh
make -f Makefile.oxdk360 check-install              # private install, then a title that links it
make -f Makefile.oxdk360 install PREFIX=/some/where # or install anywhere, and point
                                                    # HTTPCLIENT360_MK at that copy
```

`check-install` is also the honest check: it builds the smoke test from the
installed fragment and nothing else, which is the path a title in another
directory takes. `make -f Makefile.oxdk360 linkcheck` and `check` do the same
through the real prefix, and are what to run after installing there.

## What this port is

The upstream source is compiled as it stands except for three small changes, each
described below and each behind a define: the throw in `CurlHandle`, the
`std::cout` fallback in `DebugCallback`, and `DEBUG_CURL` being defined only if
nothing else has. It is linked against the same libcurl a C title would use.
Nothing about the library's design changes: it still owns one `CURL*`, still
drives libcurl's easy interface, and still takes the same callbacks.

```
HTTP/HTTPClient.h       the API; DEBUG_CURL guarded so it can be turned off
HTTP/HTTPClient.cpp     the wrapper; DbgPrint where upstream wrote to std::cout
HTTP/CurlHandle.cpp     unchanged in effect; one #ifdef around upstream's throw
```

### libc++

Most of libc++ is headers, but `std::string`'s out-of-line members, the locale
and iostream machinery `std::stringstream` reaches, and the unordered-container
bucket sizing are compiled into `libc++.a` on a normal platform, and there is no
such library for this target. This port builds one from libc++'s own sources
through OXDK's makefile for it, with a source list and a flag set supplied here,
and carries it in the install so a title needs one include line rather than a
second library to find.

`HTTPClient.cpp` does reach compiled libc++: `StringFormat` builds a
`std::stringstream`, so `<locale>`, `<ios>`, `<ios.instantiations>`, `<iostream>`
and `<ostream>` are all in the link. That is also why the title has to be a
libc++ title.

Two pieces had to be written by hand rather than taken from libc++'s source
list. `oxdk360/libcxx-shim/console_runtime.cpp` holds them, and its header
comment explains each:

* the nine `std::to_string` overloads, because libc++'s `string.cpp` includes
  `<charconv>` and, in the release OXDK's headers come from, `<charconv>` reaches
  into private headers that are not shipped. `HTTPClient.cpp` names the
  `unsigned long long` overload from a byte count;

* `_Unwind_Resume`, `__cxa_rethrow` and the `__pointer_type_info` /
  `__function_type_info` vtables, which are the residues clang's codegen emits
  for this target and neither the XDK CRT nor OXDK's `builtins.c` answers. OXDK's
  builtins already defines the class, single-inheritance, virtual-inheritance and
  enum vtables as empty tables on purpose, so RTTI links without a hierarchy to
  walk; these two are the same kind of object.

### Exceptions

OXDK builds a title with `-fno-exceptions`, and documents why: clang emits an EH
personality the XDK CRT does not ship, so `throw` cannot be compiled and nothing
could catch it if it were. `xbox360.mk` puts `-fno-exceptions` in
`OXDK360_CXXFLAGS` itself.

Upstream's `CurlHandle` constructor throws `std::runtime_error` when
`curl_global_init` fails. This port compiles with `-DHTTPCLIENT360_NO_EXCEPTIONS`,
under which that path reports the failure on the debug channel and stops -- which
is what an uncaught throw amounts to on a console -- and the `#else` branch is
upstream's throw, untouched, for a host build of the same file.

Keeping the throw was tried and is not worth its cost. Making it link needs
`-fexceptions`, and with `-fexceptions` clang also emits landing pads for every
function that could throw, which pulls `_Unwind_Resume` and a
`__cxa_rethrow` that libc++abi would have to supply properly. On a target with no
unwinder that is a runtime nobody can use, bought for an error path that already
ends the process.

### One switch for everything the library says: `DEBUG_CURL`

`DEBUG_CURL` is the only port define that gates logging. It is on by default, as
upstream has it, and it covers:

* the curl trace -- `DebugCallback`, `StartCurlDebug`, `EndCurlDebug` and
  `SetCurlTraceLogDirectory`, plus the `CURLOPT_VERBOSE`/`CURLOPT_DEBUGFUNCTION`
  curl is given on every session;
* **every log line** the library would write through `ENABLE_LOG`. Those call
  sites test `ShouldLog()`, which is `#if DEBUG_CURL` inside, so `DEBUG_CURL=0`
  compiles the logging out too rather than leaving twenty-odd flag tests behind.

`ENABLE_LOG` itself stays a run-time flag, because a caller decides per session
whether it wants output. The two are tied like this:

```cpp
return (m_eSettingsFlags & ENABLE_LOG) && s_bTraceDirectorySet;
```

So there are two conditions, and both have to hold:

| | `ENABLE_LOG` set | folder set | a log line is written |
|---|---|---|---|
| `DEBUG_CURL=1` | yes | yes | **yes** |
| `DEBUG_CURL=1` | no | any | no |
| `DEBUG_CURL=1` | yes | **no** | **no** |
| `DEBUG_CURL=0` | any | any | no -- not compiled in |

**No folder, no logs.** A title that passes `ENABLE_LOG` but never calls
`SetCurlTraceLogDirectory()` gets silence: there is nowhere for the library to
report to, so it does not report. `IsTraceLogEnabled()` says which state it is in,
and `SetCurlTraceLogDirectory("")` turns it back off.

What makes the trace produce a *file* is the same call, and it has to come before
`InitSession`:

```cpp
CHTTPClient::SetCurlTraceLogDirectory("game:\\");   // before InitSession
```

`InitSession` is what calls `StartCurlDebug`, which is where the file name is built
-- `<directory>/TraceLog_<strftime "%Y%m%d_%H">.txt`, a new file each hour -- and the
stream opened. Set the directory after `InitSession` and the session that is already
open has no trace file; `SetCurlTraceLogDirectory` is static, so it applies to every
client made afterwards. `oxdk360/test/main.cpp` sets it, checks `IsTraceLogEnabled()`
before and after, and reads the file back.

Build it off with:

```sh
make -f Makefile.oxdk360 DEBUG_CURL=0
```

121 functions become 119 and the trace machinery is gone. This is why the guards in
`HTTPClient.h` and `HTTPClient.cpp` are `#if DEBUG_CURL` rather than `#ifdef`: with
`#ifdef`, `-DDEBUG_CURL=0` still counts as defined and there is no way to turn the
feature off short of editing the source.

`SetCurlTraceLogDirectory` and `IsTraceLogEnabled` stay declared when
`DEBUG_CURL=0` -- as inline no-ops returning false -- so a title written against
one build still compiles against the other instead of needing its own `#if`.

One thing had to change for it to link at all, and it is why there is no longer a
second define. Upstream's `DebugCallback`, for a debug event that arrives when no
trace file is open, writes to `std::cout`. There is no stdout on a console, and
libc++'s own `iostream` object cannot stand in for one on this target: the build
defines `_MSC_VER`, so libc++'s headers declare the standard stream objects with an
asm label in Microsoft's mangling (`?cout@__1@std@@…`) while clang goes on mangling
every reference the Itanium way (`_ZNSt3__14coutE`). The declaration and the
definition in libc++'s compiled half never meet, and the link stops on `std::cout`
-- with nothing in the message to say the two manglings are the same object. That
fallback now reports through `DbgPrint`, which is where a console title's output
goes anyway, and since it sits inside `#if DEBUG_CURL` there is no separate
`NO_IOSTREAM` define to carry. The trace file path is untouched.

### The one line the source cannot provide

`<curl/curl.h>` includes `<winsock2.h>` and `<windows.h>` on any Windows target,
and on this platform that order is a cycle:

```
curl's <winsock2.h> -> the XDK's <winsockx.h>
                    -> <windows.h> (the curl port's shim)
                    -> the XDK's <xtl.h>
                    -> <winsockx.h> again, still mid-body so its guard
                       short-circuits it
                    -> <xonline.h>, which wants XNKID, XNADDR and IN_ADDR,
                       declared further down that very body
```

`<xtl.h>` defines `_INC_WINDOWS` before it includes `<winsockx.h>`, so when the
same chain starts from `<windows.h>` instead, `<winsockx.h>` completes and
`<xonline.h>` finds everything. `oxdk360/include/httpclient360.h` is force-included
ahead of every translation unit to put that order in place once, and to map
`strcasecmp` on the CRT's `_stricmp` -- the header sorting in `HTTPClient.h` uses
the POSIX spelling, which the console CRT exports only underscored.

## What is exercised, and what is not

Compiled and linked, which is what the archive check and the title's link prove:

* the whole public API: `InitSession`, `CleanupSession`, `GetText`,
  `DownloadFile`, `UploadFile`, `UploadForm`, the REST verbs, `EncodeUrl` /
  `DecodeUrl`, and every callback the library registers with curl.

Exercised by the smoke test when it runs on a console:

* `curl_version_info`, and with it the assertion that this archive's TLS backend
  is BearSSL and not some other libcurl on the link line
* `CurlHandle::instance()` and with it `curl_global_init`
* `CHTTPClient`'s constructor, its `std::function` log callback and
  `InitSession`
* an HTTP GET to `http://example.com/`, which reaches libcurl's transfer path,
  the console's sockets, and the port's resolver over `XNetDnsLookup`
* an HTTPS GET to `https://example.com/`, which reaches BearSSL's handshake
* `SetCurlTraceLogDirectory` and the whole `DEBUG_CURL` path: the trace file is
  named by the library, written by `DebugCallback` through curl's
  `CURLOPT_DEBUGDATA` and a `std::ofstream`, closed by `EndCurlDebug`, and then
  read back by the title and reported with its size
* `CleanupSession`, and `curl_global_cleanup` through the handle's destructor

Not exercised anywhere here:

* a title on real hardware. Nothing in this tree has been run on a console; the
  link, the XEX and the checks above are what has been verified.
* a successful HTTPS transfer. There is no trust store on a console and this
  port does not install one, so the handshake is expected to fail verification
  and `SetCertificateFile` is how a title would point at a bundle it shipped.
* `DownloadFile`, `UploadFile` and `UploadForm` at run time. They are in the
  archive and their call paths link; the smoke test does not drive them, because
  each needs a server that accepts what it sends.
* `DEBUG_CURL=0`. Both states build here -- 121 functions with the trace, 119
  without -- but only the default has been made into a title.

## Where this came from

The upstream project is
[Mohamed Amine Mzoughi's HTTP client for C++](https://github.com/embeddedmz/httpclient-cpp),
MIT licensed, see [LICENSE](LICENSE). This port adds the build glue, the two
shim files, the smoke test and the documentation; the library itself is theirs.
