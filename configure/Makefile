TOP=..

# step 1.  Use -I... to test event-config.h
#          produce configure/O.$(T_A)/TOOLCHAIN
# step 2 in setup/Makefile
_PVXS_BOOTSTRAP = YES

include $(TOP)/configure/CONFIG

# use custom libevent2 install prefix by:
#   setting LIBEVENT only for single arch build
#   setting LIBEVENT_$(T_A) for each arch
#   leave unset to use implicit system search path
# NOTE: only needed if not present in default search paths
LIBEVENT ?= $(LIBEVENT_$(T_A))
LIBEVENT_$(T_A) ?= $(wildcard $(abspath $(INSTALL_LOCATION)/bundle/usr/$(T_A)))

INCLUDES += $(if $(LIBEVENT),-I$(LIBEVENT)/include)

TARGETS = $(CONFIG_TARGETS)
CONFIGS += $(subst ../,,$(wildcard $(CONFIG_INSTALLS)))

CFG += CONFIG_PVXS_VERSION

_LIBEVENT_BUNDLE_LIBS += event_core

ifeq (WIN32,$(OS_CLASS))
_LIBEVENT_SYS_LIBS += bcrypt iphlpapi netapi32 ws2_32
else
_LIBEVENT_BUNDLE_LIBS += event_pthreads
endif

# at this point we have included the generated O.$(T_A)/TOOLCHAIN
# and use this to generated CONFIG_PVXS_MODULE

ifdef T_A
CFG += TOOLCHAIN_PVXS.$(T_A)
endif

include $(TOP)/configure/RULES

ifdef T_A
install: TOOLCHAIN

TOOLCHAIN: toolchain.c
	$(CPP) $(CPPFLAGS) $(INCLUDES) ../toolchain.c > $@.tmp
	$(MV) $@.tmp $@

EXPAND_ARGS = -a $(T_A) -t "$(INSTALL_LOCATION)"
EXPAND_ARGS += "-DLIBEVENT=$(LIBEVENT)"
EXPAND_ARGS += "-DLIBEVENT_BUNDLE_LIBS=$(_LIBEVENT_BUNDLE_LIBS)"
EXPAND_ARGS += "-DLIBEVENT_SYS_LIBS=$(_LIBEVENT_SYS_LIBS)"

TOOLCHAIN_PVXS.$(T_A): ../TOOLCHAIN_PVXS.target@ TOOLCHAIN
	$(EXPAND_TOOL) $(EXPAND_ARGS) $< $@

endif
