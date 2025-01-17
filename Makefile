SRCPATH = /tmp/usr/src/kernels/linux-5.14
BINPREFIX = /usr/local/bin
LIBPREFIX = /usr/local/lib64
RUNPREFIX = /var/run/xdp
GDBDB = -g
TESTING = -DDEBUG
TRUNK_PORT=''
#http://nuclear.mutantstargoat.com/articles/make/
#Makefile:CXXDEPMODE = depmode=gcc3
#Makefile:TPROGS_CXXFLAGS = -g -O2 -m64 -ggdb -O2 -I/usr/include/libxml2 -std=c++11 -L/usr/local/lib -Wl,-rpath=/usr/local/lib
#ifdef OBSD # make OBSD=9
#endif

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make M=samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= /usr/bin/llc
CLANG ?= /usr/bin/clang
OPT ?= /usr/bin/opt
LLVM_DIS ?= /usr/bin/llvm-dis
LLVM_OBJCOPY ?= /usr/bin/llvm-objcopy
BTF_PAHOLE = pahole
PS = /usr/bin/ps
SED = /usr/bin/sed
MKDIR = /usr/bin/mkdir
INSTALL = /usr/bin/install
UNAME = /usr/bin/uname
SYSTEMCTL = /usr/bin/systemctl
LN = /usr/bin/ln
UNLINK = /usr/bin/unlink
RM = /bin/rm
RMFLAGS = -vf
AR = /usr/bin/ar
ARFLAGS = rcsv
RANLIB = /usr/bin/ranlib
RANLIBFLAGS = -t
PROG = mienro
lib_LIBRARIES = lib$(PROG).a

objtree := ..
srctree := ..
LIBDIR = ./lib
KERNDIR = ./kern
PROGDIR = ./src
TESTDIR = ./tests
SYSDDIR = ./systemd-scripts
MANPDIR = ./docs/man
BPF_SAMPLES_PATH ?= $(abspath $(srctree)/$(src))
TOOLS_PATH := $(BPF_SAMPLES_PATH)/tools

UIDNAME = $(shell /usr/bin/id -un)
KERNEL_VERSION = $(./kernel_ver.sh)
VALIDUID = root

# Target XDP Kernel Object
TOBJS_FLAGS = -I$(srctree)/arch/x86/include
TOBJS_FLAGS += -I$(srctree)/arch/x86/include/generated
TOBJS_FLAGS += -I$(srctree)/include
TOBJS_FLAGS += -I$(srctree)/arch/x86/include/uapi
TOBJS_FLAGS += -I$(srctree)/arch/x86/include/generated/uapi
TOBJS_FLAGS += -I$(srctree)/include/uapi
TOBJS_FLAGS += -I$(srctree)/include/generated/uapi
TOBJS_FLAGS += -I$(srctree)/tools/lib
TOBJS_FLAGS += -I$(srctree)/tools/lib/bpf
TOBJS_FLAGS += -I$(srctree)/tools/testing/selftests/bpf
TOBJS_FLAGS += -I$(LIBDIR)

ifeq ($(ARCH), arm)
# Strip all except -D__LINUX_ARM_ARCH__ option needed to handle linux
# headers when arm instruction set identification is requested.
ARM_ARCH_SELECTOR := $(filter -D__LINUX_ARM_ARCH__%, $(KBUILD_CFLAGS))
BPF_EXTRA_CFLAGS := $(ARM_ARCH_SELECTOR)
TPROGS_CFLAGS += $(ARM_ARCH_SELECTOR)
endif

TPROGS_FLAGS = -I./include
TPROGS_FLAGS += -I$(objtree)/usr/include
TPROGS_FLAGS += -I$(srctree)/tools/testing/selftests/bpf/
TPROGS_FLAGS += -I$(srctree)/tools/lib/
TPROGS_FLAGS += -I$(srctree)/tools/include
TPROGS_FLAGS += -I$(srctree)/tools/perf
TPROGS_FLAGS += -DHAVE_ATTR_TEST=0

TPROGS_CFLAGS += -Wall -O2
TPROGS_CFLAGS += -Wmissing-prototypes
TPROGS_CFLAGS += -Wstrict-prototypes
TPROGS_CFLAGS += $(TPROGS_FLAGS)

TPROGS_CXXFLAGS += -Wall -O2 -m64 -std=c++23 -fstack-protector-all
TPROGS_CXXFLAGS += $(TPROGS_FLAGS)
ifeq ($(shell $(PS) --no-headers -o comm 1), systemd)
TPROGS_CXXFLAGS += -DSYSTEMD_ACTIVE
endif
ifdef TRUNK_PORT
TPROGS_CXXFLAGS += -DTRUNK_PORT
endif
TPROGS_CXXFLAGS += -I$(LIBDIR)

ifdef GDBDB
ifeq ($(GDBDB), -g)
	TPROGS_CXXFLAGS += -ggdb
ifdef TESTING
ifeq ($(TESTING), -DDEBUG)
	TPROGS_CXXFLAGS += -DDEBUG
endif
endif
endif
endif

ifdef SYSROOT
TPROGS_CFLAGS += --sysroot=$(SYSROOT)
TPROGS_LDFLAGS := -L$(SYSROOT)/usr/lib
endif

# Libbpf dependencies
LIBBPF = $(TOOLS_PATH)/lib/bpf/libbpf.a

LDFLAGS += $(LIBBPF) -lpthread -lelf -lz
TPROGS_CXXOBJS = mcommon.o Setup.o Mienro.o
TPROGS_CXXPRGSUFFIXS = load # unload mon4 mon6 monnet
TPROGS_CXXTSTSUFFIXS = test
TSCRPS_SYSTEMD_SERVS = mienro.service
TSCRPS_MANPAGE_DOCUS = mienro.8

# Detect that we're cross compiling and use the cross compiler
ifdef CROSS_COMPILE
CLANG_ARCH_ARGS = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif

# Check systemd is active (pidof -s systemd to find the pid number)
ifeq ($(shell $(PS) --no-headers -o comm 1), systemd)
#define SYSTEMD_ACTIVE
endif

# Don't evaluate probes and warnings if we need to run make recursively
HDR_PROBE := $(shell printf "\#include <linux/types.h>\n struct list_head { int a; }; int main() { return 0; }" | \
	$(CC) $(TPROGS_CFLAGS) $(TPROGS_LDFLAGS) -x c - \
	-o /dev/null 2>/dev/null && echo okay)
ifeq ($(HDR_PROBE),)
$(warning WARNING: Detected possible issues with include path.)
$(warning WARNING: Please install kernel headers locally (make headers_install).)
endif

BTF_LLC_PROBE := $(shell $(LLC) -march=bpf -mattr=help 2>&1 | grep dwarfris)
BTF_PAHOLE_PROBE := $(shell $(BTF_PAHOLE) --help 2>&1 | grep BTF)
BTF_OBJCOPY_PROBE := $(shell $(LLVM_OBJCOPY) --help 2>&1 | grep -i 'usage.*llvm')
BTF_LLVM_PROBE := $(shell echo "int main() { return 0; }" | \
			  $(CLANG) -target bpf -O2 -g -c -x c - -o ./llvm_btf_verify.o; \
			  readelf -S ./llvm_btf_verify.o | grep BTF; \
			  /bin/rm -f ./llvm_btf_verify.o)

BPF_EXTRA_CFLAGS += -fno-stack-protector
ifneq ($(BTF_LLVM_PROBE),)
	BPF_EXTRA_CFLAGS += -g
else
ifneq ($(and $(BTF_LLC_PROBE),$(BTF_PAHOLE_PROBE),$(BTF_OBJCOPY_PROBE)),)
	BPF_EXTRA_CFLAGS += -g
	LLC_FLAGS += -mattr=dwarfris
	DWARF2BTF = y
endif
endif

PROG: clean welcome $(PROG)_kern_objects $(lib_LIBRARIES)
	@for a in $(TPROGS_CXXPRGSUFFIXS); do \
		if [ -e $(PROGDIR)/$$a'.'cc ]; then \
			echo $(CXX) $(TPROGS_CXXFLAGS) -L$(LIBDIR) -o $(PROGDIR)/$(PROG)''$$a $(PROGDIR)/$$a'.'cc $(LIBDIR)/$(lib_LIBRARIES) $(LDFLAGS); \
			$(CXX) $(TPROGS_CXXFLAGS) -L$(LIBDIR) -o $(PROGDIR)/$(PROG)''$$a $(PROGDIR)/$$a'.'cc $(LIBDIR)/$(lib_LIBRARIES) $(LDFLAGS); \
		fi; \
	done;

	@if [ -e /usr/local/lib64/libCatch2Main.a -a -e /usr/local/lib64/libCatch2.a ]; then \
		echo "Compiling tests ..."; \
		for a in $(TPROGS_CXXTSTSUFFIXS); do \
			if [ -e $(TESTDIR)/$$a'.'cc ]; then \
				echo $(CXX) $(TPROGS_CXXFLAGS) -I/usr/local/include -L/usr/local/lib64 -L$(LIBDIR) -o $(TESTDIR)/$(PROG)''$$a $(TESTDIR)/$$a'.'cc $(LIBDIR)/$(lib_LIBRARIES) /usr/local/lib64/libCatch2Main.a /usr/local/lib64/libCatch2.a $(LDFLAGS); \
				$(CXX) $(TPROGS_CXXFLAGS) -I/usr/local/include -L/usr/local/lib64 -L$(LIBDIR) -o $(TESTDIR)/$(PROG)''$$a $(TESTDIR)/$$a'.'cc $(LIBDIR)/$(lib_LIBRARIES) /usr/local/lib64/libCatch2Main.a /usr/local/lib64/libCatch2.a $(LDFLAGS); \
			fi; \
		done; \
	else \
		echo ""; \
		echo "Missing Catch2 Libraries inside /usr/local/lib64 directory. I cannot running tests!"; \
		echo "Hint:"; \
		echo "\$$ wget https://github.com/catchorg/Catch2/archive/refs/tags/v2.13.6.zip"; \
		echo "\$$ unzip v2.13.6.zip"; \
		echo "\$$ cd Catch2-2.13.6\n\$ cmake -Bbuild -H. -DBUILD_TESTING=OFF\n"; \
		echo "\$$ cmake -Bbuild -H. -DBUILD_TESTING=OFF"; \
		echo "\$$ sudo cmake --build build/ --target install"; \
	fi;

# All objects in lib directory must be already compiled (needed for multithread compilation)
$(lib_LIBRARIES): $(TPROGS_CXXOBJS)
	@for a in $(TPROGS_CXXOBJS); do \
		if [ -e $(LIBDIR)/$$a ]; then \
			$(AR) $(ARFLAGS) $(LIBDIR)/$(lib_LIBRARIES) $(LIBDIR)/$$a; \
		fi; \
	done;
	$(RANLIB) $(RANLIBFLAGS) $(LIBDIR)/$(lib_LIBRARIES)

$(PROG)_kern_objects:
	@for a in "wanif" "ctrif" "lanif"; do \
		echo "  CLANG-bpf "$(KERNDIR)/$(PROG)"_"$$a"_kern.o"; \
		$(CLANG) -nostdinc -isystem $(shell $(CC) -print-file-name=include) $(TOBJS_FLAGS) -include ../include/linux/kconfig.h $(BPF_EXTRA_CFLAGS) \
		-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option  \
		-include ./include/asm_goto_workaround.h \
		-O2 -emit-llvm -Xclang -disable-llvm-passes -c $(KERNDIR)/$$a"_kern.c" -o - | \
		$(OPT) -O2 -mtriple=bpf-pc-linux | \
		$(LLVM_DIS) | \
		$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $(KERNDIR)/$(PROG)"_"$$a"_kern.o"; \
	done;

ifeq ($(DWARF2BTF),y)
	$(BTF_PAHOLE) -J $@
endif

Mienro.o:
	$(CXX) -Wp,-MD,$(LIBDIR)/.$@.d $(TPROGS_CXXFLAGS) -I$(LIBDIR) -c -o $(LIBDIR)/$@ $(LIBDIR)/Mienro.cc

Setup.o:
	$(CXX) -Wp,-MD,$(LIBDIR)/.$@.d $(TPROGS_CXXFLAGS) -I$(LIBDIR) -c -o $(LIBDIR)/$@ $(LIBDIR)/Setup.cc

mcommon.o:
	$(CXX) -Wp,-MD,$(LIBDIR)/.$@.d $(TPROGS_CXXFLAGS) -I$(LIBDIR) -c -o $(LIBDIR)/$@ $(LIBDIR)/mcommon.cc

install:
ifeq ($(UIDNAME), $(VALIDUID))
	@for a in $(TPROGS_CXXPRGSUFFIXS); do \
		if [ -e $(PROGDIR)/$$a'.'cc ]; then \
			$(CXX) $(TPROGS_CXXFLAGS) -DMIENRO_KOBJPATH='"$(LIBPREFIX)"' -DMIENRO_PROGPATH='"$(BINPREFIX)"' -L$(LIBDIR) -o $(PROGDIR)/.$(PROG)''$$a $(PROGDIR)/$$a'.'cc $(LIBDIR)/$(lib_LIBRARIES) $(LDFLAGS); \
		fi; \
	done;

	@for a in "wanif" "ctrif" "lanif"; do \
		if [ -e $(LIBDIR)/$(PROG)"_"$$a"_kern.o" ]; then \
			if [ -d $(LIBPREFIX) ]; then \
				$(RM) -f $(LIBPREFIX)/$(PROG)"_"$$a"_kern.o"; \
			else \
				echo "Missing Target directory $(LIBPREFIX)"; \
				exit -1; \
			fi; \
		fi; \
		$(INSTALL) -m 500 $(KERNDIR)/$(PROG)"_"$$a"_kern.o" $(LIBPREFIX); \
		echo "Kernel module $(LIBPREFIX)/$(PROG)"_"$$a"_kern.o" ready!"; \
	done

	@for a in $(TPROGS_CXXPRGSUFFIXS); do \
		if [ -e $(PROGDIR)/.$(PROG)''$$a ]; then \
			if [ -d $(BINPREFIX) ]; then \
				$(RM) -f $(BINPREFIX)/$(PROG)''$$a; \
			else \
				echo "Missing Target directory $(BINPREFIX)"; \
				exit -1; \
			fi; \
			$(INSTALL) -m 755 $(PROGDIR)/.$(PROG)''$$a $(BINPREFIX)/$(PROG)''$$a; \
			echo Program $(BINPREFIX)/$(PROG)''$$a ready!; \
		fi; \
	done;

#ifdef SYSTEMD_ACTIVE
	@for a in $(TSCRPS_SYSTEMD_SERVS); do \
		if [ -e $(SYSDDIR)/$$a ]; then \
			if [ -d /usr/lib/systemd/system ]; then \
				$(RM) -f /usr/lib/systemd/system/$$a; \
			else \
				echo "Missing Target directory /usr/lib/systemd/system"; \
				exit -1; \
			fi; \
			$(SED) -e "s|MIENRO_BINPREFIX|$(BINPREFIX)|" -e "s|MIENRO_RUNPREFIX|$(RUNPREFIX)|" $(SYSDDIR)/$$a > /tmp/.$$a; \
			$(INSTALL) -m 644 /tmp/.$$a /usr/lib/systemd/system/$$a; \
			$(UNLINK) /tmp/.$$a; \
			echo Systemd service script /usr/lib/systemd/system/$$a installed!; \
			$(SYSTEMCTL) enable $$a; \
			echo Systemd service script /usr/lib/systemd/system/$$a enabled!; \
		fi; \
	done;

	$(SYSTEMCTL) daemon-reload;
#endif

	@for a in $(TSCRPS_MANPAGE_DOCUS); do \
		if [ -e $(MANPDIR)/$$a ]; then \
			if [ -d /usr/share/man/man8 ]; then \
				$(RM) -f /usr/share/man/man8/$$a; \
			else \
				echo "Missing Target directory /usr/share/man/man8"; \
				exit -1; \
			fi; \
			$(INSTALL) -m 644 $(MANPDIR)/$$a /usr/share/man/man8/$$a; \
		fi; \
	done;
else
	@echo "You are not $(VALIDUID) and I cannot install programs."
endif

unistall:
ifeq ($(UIDNAME), $(VALIDUID))
	@for a in "wanif" "ctrif" "lanif"; do \
		if [ -e $(LIBPREFIX)/$(PROG)"_"$$a"_kern.o" ]; then \
			$(RM) -f $(LIBPREFIX)/$(PROG)"_"$$a"_kern.o"; \
			echo "Kernel module $(LIBPREFIX)/$(PROG)"_"$$a"_kern.o" deleted!"; \
		fi; \
	done

	@for a in $(TPROGS_CXXPRGSUFFIXS); do \
		if [ -e $(BINPREFIX)/$(PROG)''$$a ]; then \
			$(RM) -f $(BINPREFIX)/$(PROG)''$$a; \
			echo Program $(BINPREFIX)/$(PROG)''$$a deleted!; \
		fi; \
	done

#ifdef SYSTEMD_ACTIVE
	@for a in $(TSCRPS_SYSTEMD_SERVS); do \
		if [ -e $(SYSDDIR)/$$a ]; then \
			if [ -d /etc/systemd/system/multi-user.target.wants ]; then \
				if [ -e /etc/systemd/system/multi-user.target.wants/$$a ]; then \
					$(SYSTEMCTL) disable $$a; \
					echo Systemd service script /usr/lib/systemd/system/$$a disabled!; \
				fi; \
			else \
				echo "Missing Target directory /etc/systemd/system/multi-user.target.wants"; \
				exit -1; \
			fi; \
			if [ -d /usr/lib/systemd/system ]; then \
				$(RM) -f /usr/lib/systemd/system/$$a; \
				echo Systemd service script /usr/lib/systemd/system/$$a deleted!; \
			else \
				echo "Missing Target directory /usr/lib/systemd/system"; \
				exit -1; \
			fi; \
		fi; \
	done;

	$(SYSTEMCTL) daemon-reload;
#endif

	@for a in $(TSCRPS_MANPAGE_DOCUS); do \
		if [ -e $(MANPDIR)/$$a ]; then \
			if [ -d /usr/share/man/man8 ]; then \
				$(RM) -f /usr/share/man/man8/$$a; \
				echo Manpage deleted /usr/share/man/man8/$$a deleted!; \
			else \
				echo "Missing Target directory /usr/share/man/man8"; \
				exit -1; \
			fi; \
		fi; \
	done;
else
	@echo "You are not $(VALIDUID) and I cannot install $(PROG) programs."
endif

test:
	@if [ -e /usr/local/lib64/libCatch2Main.a -a -e /usr/local/lib64/libCatch2.a ]; then \
		echo "Running tests ..."; \
		for a in $(TPROGS_CXXTSTSUFFIXS); do \
				echo "Running $(TESTDIR)/$(PROG)$$a ..."; \
				$(TESTDIR)/$(PROG)''$$a; \
		done; \
	else \
		echo ""; \
		echo "Missing Catch2 Libraries inside /usr/local/lib64 directory. I cannot running tests!"; \
		echo "Hint:"; \
		echo "\$$ wget https://github.com/catchorg/Catch2/archive/refs/tags/v2.13.6.zip"; \
		echo "\$$ unzip v2.13.6.zip"; \
		echo "\$$ cd Catch2-2.13.6\n\$ cmake -Bbuild -H. -DBUILD_TESTING=OFF\n"; \
		echo "\$$ cmake -Bbuild -H. -DBUILD_TESTING=OFF"; \
		echo "\$$ sudo cmake --build build/ --target install"; \
	fi;

welcome:
	@echo "Compiling libraries ..."
	$(MAKE) -C $(SRCPATH)/tools/lib/bpf

clean:
	@echo "Cleaning up ..."
	@for a in $(TPROGS_CXXPRGSUFFIXS); do \
		$(RM) $(RMFLAGS) $(PROGDIR)/$(PROG)$$a; \
	done

	@for a in $(TPROGS_CXXTSTSUFFIXS); do \
		$(RM) $(RMFLAGS) $(TESTDIR)/$(PROG)$$a; \
	done

	$(RM) $(RMFLAGS) $(LIBDIR)/$(lib_LIBRARIES)

	@for a in $(TPROGS_CXXOBJS); do \
		if [ -e $(KERNDIR)/$$a ]; then \
			$(RM) $(RMFLAGS) $(KERNDIR)/$$a; \
		elif [ -e $(LIBDIR)/$$a ]; then \
			$(RM) $(RMFLAGS) $(LIBDIR)/$$a; \
			if [ -e $(LIBDIR)/.$$a.d ]; then \
				$(RM) $(RMFLAGS) $(LIBDIR)/.$$a.d; \
			fi; \
		fi; \
    	done;
	@for a in "wanif" "ctrif" "lanif"; do \
		$(RM) $(RMFLAGS) $(KERNDIR)/$(PROG)"_"$$a"_kern.o"; \
	done;
	$(RM) $(RMFLAGS) Module.symvers .Module.symvers.cmd modules.order .modules.order.cmd

#	@echo "$(MAKE) -C ../../ M=$(CURDIR) clean"
ifeq ($(UIDNAME), $(VALIDUID))
	@for a in $(TPROGS_CXXPRGSUFFIXS); do \
		if [ -e $(PROGDIR)/$(PROG)$$a ]; then \
			$(RM) $(RMFLAGS) $(BINPREFIX)/$(PROG)$$a; \
		fi \
	done
else
	@for a in $(TPROGS_CXXPRGSUFFIXS); do \
		if [ -e $(PROGDIR)/$(PROG)$$a ]; then \
			echo "Sorry: You are not $(VALIDUID) and I cannot remove $(BINPREFIX)/$(PROG)$$a"; \
		fi \
	done
endif
	@echo done

.SILENT: clean

.PHONY: verify_cmds verify_target_bpf $(PROG)_kern_objects clean welcome install unistall

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi
