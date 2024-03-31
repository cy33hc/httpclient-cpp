#---------------------------------------------------------------------------------
# Clear the implicit built in rules
#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

ifeq ($(strip $(PSL1GHT)),)
$(error "Please set PSL1GHT in your environment. export PSL1GHT=<path>")
endif

include	$(PSL1GHT)/ppu_rules



#---------------------------------------------------------------------------------
ifeq ($(strip $(PLATFORM)),)
#---------------------------------------------------------------------------------
export BASEDIR		:= $(CURDIR)
export DEPS			:= $(BASEDIR)/deps
export LIBS			:=	$(BASEDIR)/lib

#---------------------------------------------------------------------------------
else
#---------------------------------------------------------------------------------

export LIBDIR		:= $(LIBS)/$(PLATFORM)
export DEPSDIR		:=	$(DEPS)/$(PLATFORM)

#---------------------------------------------------------------------------------
endif
#---------------------------------------------------------------------------------

TARGET		:=	libhttpclient
BUILD		:=	build
SOURCE		:=	HTTP
INCLUDE		:=	HTTP
DATA		:=	data
LIBS		:=	

MACHDEP		:= -DPS3_PPU_PLATFORM -DHAVE_STDINT_H -DHAVE_STRING_H \
				-DHAVE_STDLIB_H -DHAVE_SYS_TYPES_H -DHAVE_UNISTD_H -D_U_=/**/

CFLAGS		+= -O2 -Wall -mcpu=cell $(MACHDEP) -fno-strict-aliasing $(INCLUDES)
CXXFLAGS	=  $(CFLAGS)

LD			:=	ppu-ld

ifneq ($(BUILD),$(notdir $(CURDIR)))

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export VPATH	:=	$(foreach dir,$(SOURCE),$(CURDIR)/$(dir)) \
					$(foreach dir,$(DATA),$(CURDIR)/$(dir))
export BUILDDIR	:=	$(CURDIR)/$(BUILD)
export DEPSDIR	:=	$(BUILDDIR)

CFILES		:= $(foreach dir,$(SOURCE),$(notdir $(wildcard $(dir)/*.c)))
CXXFILES	:= $(foreach dir,$(SOURCE),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES		:= $(foreach dir,$(SOURCE),$(notdir $(wildcard $(dir)/*.S)))
BINFILES	:= $(foreach dir,$(DATA),$(notdir $(wildcard $(dir)/*.bin)))


export OFILES	:=	$(CFILES:.c=.o) \
					$(CXXFILES:.cpp=.o) \
					$(SFILES:.S=.o) \
					$(BINFILES:.bin=.bin.o)

export BINFILES	:=	$(BINFILES:.bin=.bin.h)

export INCLUDES	=	$(foreach dir,$(INCLUDE),-I$(CURDIR)/$(dir)) \
					-I$(CURDIR)/$(BUILD) -I$(PSL1GHT)/ppu/include -I$(PORTLIBS)/include

.PHONY: $(BUILD) install clean shader

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@make --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

install: $(BUILD)
ifeq ($(PORTLIBS),)
	@echo "$PORTLIBS is not set. Can not install libhttpclient."
	@exit 1
endif
	@echo Copying...
	@mkdir -p $(PORTLIBS)/include/httpclient
	@cp -frv HTTP/*.h $(PORTLIBS)/include/httpclient
	@cp -frv *.a $(PORTLIBS)/lib
	@echo Done!

clean:
	@echo Clean...
	@rm -rf $(BUILD) $(OUTPUT).elf $(OUTPUT).self $(OUTPUT).a

else

DEPENDS	:= $(OFILES:.o=.d)

$(OUTPUT).a: $(OFILES)
$(OFILES): $(BINFILES) $(VCGFILES) $(VSAFILES)

-include $(DEPENDS)

endif
