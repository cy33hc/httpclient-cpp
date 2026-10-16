# Ask OXDK what compiler and flags it would use for the Xbox 360, and print
# them as makefile assignments.
#
#   make -s -f oxdk360/flags.mk flags OXDK_DIR=/path/to/OXDK
#
# Makefile.oxdk360 generates build-oxdk360/toolchain.mk from this and includes
# it, so the compiler, the include order and the Xenon ABI in this port are the
# same ones xbox360/xbox360.mk hands a title. After an OXDK change:
# `make -f Makefile.oxdk360 refresh-flags`.

OXDK_DIR    ?= $(HOME)/x360projects/OXDK
OXDK_ROOT   := $(OXDK_DIR)
OXDK360_DIR := $(OXDK_ROOT)/xbox360
OXDK_TARGET := xbox360

# httpclient-cpp is C++ and cannot link against Microsoft's libcpMT: clang
# mangles Itanium where the XDK library mangles MSVC, so the two never meet.
# Everything the library names that is not inline -- std::string's out-of-line
# members, the locale and iostream machinery std::stringstream pulls in -- has
# to come from a libc++ built for this target, and the headers have to be the
# same release as that build.
OXDK360_LIBCXX := 1

# And it is a Xenon build. OXDK's own XDK libraries and the kernel are compiled
# with the Xenon calling convention, not PowerPC SysV, and clang emits it only
# behind this feature. Without it every call into XDK or kernel code needs a
# hand-written shim and va_list is the wrong type for the XDK's CRT.
XENON_ABI := 1

include $(OXDK_ROOT)/common/toolchain.mk
include $(OXDK_ROOT)/xbox360/xbox360.mk

# Only the variables this build actually consumes are printed. OXDK also hands
# out XDK_DIR and OXDK360_INC, the XDK's own include directories; nothing here
# needs either, because OXDK's own CXXFLAGS carry them, and a title that wants
# them can read them from OXDK itself.
flags:
	@echo "CLANG := $(CLANG)"
	@echo "CLANGXX := $(CLANGXX)"
	@echo "LLVM_AR := $(LLVM_AR)"
	@echo "LLVM_NM := $(LLVM_NM)"
	@echo "OBJCOPY := $(OBJCOPY)"
	@echo "OXDK360_CFLAGS := $(OXDK360_CFLAGS)"
	@echo "OXDK360_CXXFLAGS := $(OXDK360_CXXFLAGS)"
	@echo "OXDK360_LIBCXX_DIR := $(OXDK360_LIBCXX_DIR)"
