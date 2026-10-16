# Link check and smoke test for httpclient-cpp on the Xbox 360.
#
#   make                                   -> default.xex
#   make check                             -> xexcheck.py on it
#   XBDM_HOST=192.168.1.50 make run        -> copy it to the console and run it
#   XBDM_HOST=192.168.1.50 make watch      -> the debug channel
#   make clean
#
# This deliberately goes through the *installed* library, not the built one: the
# headers, the archive, libc++'s compiled half and the fragment under the OXDK
# third-party prefix, which is what a title in another directory would get. So
# install first:
#
#   cd .. && make -f Makefile.oxdk360 install
#
# `make -f Makefile.oxdk360 check-install` in the source directory does the same
# build against a private install, which is the way to check a change without
# touching the prefix.

OXDK_DIR    ?= $(HOME)/x360projects/OXDK
OXDK_TARGET := xbox360
XENON_ABI   := 1

# libc++, not the XDK's own C++ library. httpclient-cpp's archive was built with
# OXDK's libc++ headers and its compiled half, so the title's <string>,
# <unordered_map> and <functional> have to be the same ones. With this unset the
# title takes the XDK's C++ headers and -fms-compatibility-version=14, and the
# two halves mangle the same types differently.
OXDK360_LIBCXX := 1

XEX_TITLE   := httpclient_smoketest

# Where the installed library is. The default is the OXDK third-party prefix a
# real `make -f Makefile.oxdk360 install` writes; check-install points it at a
# private install instead, so that the fragment is exercised before it is
# installed for real.
#
# The root is derived from the fragment itself rather than the other way
# around, because the fragment defaults HTTPCLIENT360_ROOT to the prefix it was
# generated with and `?=` would then keep the wrong one: an installed library is
# always <root>/oxdk360/httpclient360.mk, and <root> is what the archive and the
# headers hang off.
HTTPCLIENT360_ROOT ?= $(OXDK_DIR)/xbox360/third-party/httpclient
HTTPCLIENT360_MK   ?= $(HTTPCLIENT360_ROOT)/oxdk360/httpclient360.mk

ifeq ($(wildcard $(HTTPCLIENT360_MK)),)
$(error httpclient-cpp for the Xbox 360 is not installed. Run \
`make -f Makefile.oxdk360 install` in the source directory, then try again)
endif

HTTPCLIENT360_ROOT := $(patsubst %/oxdk360/httpclient360.mk,%,$(HTTPCLIENT360_MK))

SRCS := main.cpp

include $(OXDK_DIR)/oxdk.mk
include $(HTTPCLIENT360_MK)

# The library's flags first: the include directories, the two ABI defines and the
# force-include that puts <windows.h> before <curl/curl.h>. Then the archive and
# libcurl, through OBJS, so that oxdk.mk's link rule sees them.
#
# CXXFLAGS and not CFLAGS: xbox360.mk's rule for a .cpp file is
# `$(CLANG) $(OXDK360_CXXFLAGS) $(CXXFLAGS)`, so a project's additions for C++
# have to go in the C++ variable. Its C rule reads CFLAGS.
#
# No -fexceptions, and none is needed: httpclient-cpp is built with exceptions
# off, the way OXDK builds a title, and its one throw site is behind a define
# that turns it into a report and a stop. What is inside the archive is what a
# title links, so the title's headers and the archive agree.
CXXFLAGS += $(HTTPCLIENT360_CFLAGS)
OBJS     += $(HTTPCLIENT360_OBJS)

# The XDK's own headers, the same suppressions the library build carries. Without
# them this compiles with two thousand warnings and not one of them is about this
# source.
OXDK_WARN_OFF := -Wno-varargs -Wno-ignored-attributes -Wno-pragma-pack \
                 -Wno-microsoft-anon-tag -Wno-ignored-qualifiers \
                 -Wno-deprecated-declarations -Wno-ignored-pragma-intrinsic
CXXFLAGS += $(OXDK_WARN_OFF)

# xexcheck.py is OXDK's pre-flight for the loader: every rule in it was read out
# of the kernel or established on hardware, and running it is much cheaper than a
# boot. `make check` is `make` and then this.
XEXCHECK ?= $(OXDK_DIR)/xbox360/tools/xexutil/xexcheck.py

check: $(XEX)
	python3 $(XEXCHECK) $(XEX)

.PHONY: check
