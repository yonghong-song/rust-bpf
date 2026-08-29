# SPDX-License-Identifier: GPL-2.0
#
# Build standalone Rust BPF programs (no kernel crate dependency)
#
# Usage: make

BLDDIR := $(CURDIR)/bld
TARGET := $(CURDIR)/bpfel-unknown-none-v4.json
# Persistent across `rm -rf bld` — libcore/liballoc rebuilds dominate clean
# builds (~22s), and these only depend on rustc/RUST_SRC, not on user code.
DEPDIR := $(CURDIR)/bld_deps

# Host triple for proc-macro and bpf-postproc builds (default to current).
HOST_TRIPLE ?= x86_64-unknown-linux-gnu

# LLVM toolchain. LLVM_DIR is the ONLY knob: the command-line tools, the
# llvm-sys prefix and the bpf-postproc feature are all derived from it below,
# with `:=`, so there is no second variable that can drift out of sync and
# point half the build at a different LLVM.
#
# LLVM_DIR must match the LLVM that RUSTC was built against (`rustc -vV`
# prints it): rustc emits bitcode in its own LLVM's format, and an older
# llvm-link rejects it outright with "error: Invalid record". The
# check-toolchain rule below enforces that rather than letting it fail deep
# in the pipeline.
LLVM_DIR ?= /home/yhs/work/llvm-project/llvm/build.23
LLVM_BIN := $(LLVM_DIR)/bin
LLVM_CONFIG := $(LLVM_BIN)/llvm-config
LLC := $(LLVM_BIN)/llc
OPT := $(LLVM_BIN)/opt
LLVM_LINK := $(LLVM_BIN)/llvm-link
LLVM_AS := $(LLVM_BIN)/llvm-as
LLVM_DIS := $(LLVM_BIN)/llvm-dis
LLVM_OBJCOPY := $(LLVM_BIN)/llvm-objcopy

# "23.1.0" -> LLVM_MAJOR 23, LLVM_MINOR 1. Trailing junk in development
# versions ("24.0.0git") is harmless: only the first two fields are used.
LLVM_VERSION := $(shell $(LLVM_CONFIG) --version 2>/dev/null)
LLVM_MAJOR := $(word 1,$(subst ., ,$(LLVM_VERSION)))
LLVM_MINOR := $(word 2,$(subst ., ,$(LLVM_VERSION)))
# llvm-sys only honours LLVM_SYS_<crate major>_PREFIX for its OWN crate major
# version, and that major is <LLVM major><LLVM minor> (LLVM 23.1 -> llvm-sys
# 231.x -> LLVM_SYS_231_PREFIX). Any other name is ignored and llvm-sys
# silently falls back to whatever llvm-config is on $PATH, linking
# bpf-postproc against a foreign LLVM that then emits unreadable bitcode.
LLVM_SYS_PREFIX_VAR := LLVM_SYS_$(LLVM_MAJOR)$(LLVM_MINOR)_PREFIX
# Picks the matching optional llvm-sys dep in bpf-postproc/Cargo.toml.
POSTPROC_FEATURE := llvm-$(LLVM_MAJOR)
LLVM_STAMP := $(BLDDIR)/.llvm-dir

# RUSTC and RUST_SRC must come from the SAME rustc version: libcore/liballoc
# use lang items and built-in macros that only the exactly-matching compiler
# knows about, so pairing a released toolchain with an unrelated rust checkout
# fails outright (hundreds of errors in core). The nightly rustup toolchain
# plus its own rust-src component is a matched pair by construction:
#   rustup toolchain install nightly && rustup component add rust-src --toolchain nightly
# To build against a rust git checkout instead, bootstrap it there
# (`./configure && ./x.py build --stage 1 library`, there is no Makefile in
# that tree) and override both:
#   make RUSTC=<tree>/build/$(HOST_TRIPLE)/stage1/bin/rustc RUST_SRC=<tree>/library
RUST_TOOLCHAIN ?= $(HOME)/.rustup/toolchains/nightly-$(HOST_TRIPLE)
RUSTC ?= $(RUST_TOOLCHAIN)/bin/rustc
RUST_SRC ?= $(RUST_TOOLCHAIN)/lib/rustlib/src/rust/library
CARGO ?= cargo

# The LLVM rustc was built with. A nightly bump can move this (22 -> 23 in
# Aug 2026), at which point LLVM_DIR has to move with it.
RUSTC_LLVM_VERSION := $(shell $(RUSTC) -vV 2>/dev/null | sed -n 's/^LLVM version: //p')
RUSTC_LLVM_MAJOR := $(word 1,$(subst ., ,$(RUSTC_LLVM_VERSION)))

# Fail fast, with something actionable, instead of surfacing as "Invalid
# record" out of llvm-link or a compile_error! out of llvm-sys. Skipped for
# the clean targets so they still work without a toolchain present.
ifeq ($(filter clean distclean,$(MAKECMDGOALS)),)
ifeq ($(LLVM_VERSION),)
$(error no llvm-config at $(LLVM_CONFIG); set LLVM_DIR=<llvm build or install dir>)
endif
ifeq ($(RUSTC_LLVM_VERSION),)
$(error cannot run $(RUSTC); set RUSTC=<path> or RUST_TOOLCHAIN=<dir>)
endif
ifneq ($(LLVM_MAJOR),$(RUSTC_LLVM_MAJOR))
$(error LLVM mismatch: $(RUSTC) uses LLVM $(RUSTC_LLVM_VERSION) but LLVM_DIR=$(LLVM_DIR) is LLVM $(LLVM_VERSION). Point LLVM_DIR at an LLVM $(RUSTC_LLVM_MAJOR) build)
endif
endif

RUSTFLAGS_ENV := RUSTC_BOOTSTRAP=1
RUSTC_COMMON := --target $(TARGET) -C opt-level=3 -C panic=unwind -C debuginfo=2 -Z unstable-options -Z threads=64

PROGS := scx_simple scx_cosmos

# Programs that let a bpf_throw() unwind through Rust Drop impls. These need
# the .bpf_cleanup section, which only exists in LLVM >= 23 (9d51c891b719
# "[BPF] Add exception handling support with .bpf_cleanup section"), so they
# are only built when $(LLVM_DIR) is new enough -- which, given the
# LLVM_MAJOR == RUSTC_LLVM_MAJOR check above, means only on a rustc whose own
# LLVM is >= 23. On anything older `make` still builds PROGS and says what it
# skipped, rather than failing.
EH_PROGS := exc
ifeq ($(shell test "$(LLVM_MAJOR)" -ge 23 2>/dev/null && echo yes),yes)
EH_BUILD := $(EH_PROGS)
else
EH_BUILD :=
ifeq ($(filter clean distclean,$(MAKECMDGOALS)),)
$(warning skipping $(EH_PROGS): .bpf_cleanup needs LLVM >= 23, LLVM_DIR is LLVM $(LLVM_VERSION))
endif
endif

all: $(addprefix $(BLDDIR)/,$(addsuffix .o,$(PROGS) $(EH_BUILD)))

# --- core ---
$(DEPDIR)/libcore.rlib: $(RUST_SRC)/core/src/lib.rs
	@mkdir -p $(DEPDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null \
		--cfg 'no_fp_fmt_parse' \
		--crate-name core \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/libcore.rmeta \
		$<

# --- compiler_builtins (stub) ---
$(DEPDIR)/libcompiler_builtins.rlib: $(DEPDIR)/libcore.rlib
	@mkdir -p $(DEPDIR)
	echo '#![no_std]' '#![feature(compiler_builtins,rustc_attrs)]' '#![compiler_builtins]' '#![allow(internal_features)]' '#[rustc_std_internal_symbol] fn __rust_no_alloc_shim_is_unstable_v2() {}' | \
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name compiler_builtins \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/libcompiler_builtins.rmeta \
		-

# --- alloc ---
$(DEPDIR)/liballoc.rlib: $(RUST_SRC)/alloc/src/lib.rs $(DEPDIR)/libcompiler_builtins.rlib
	@mkdir -p $(DEPDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name alloc \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/liballoc.rmeta \
		$<

# --- multi3 intrinsic ---
$(DEPDIR)/multi3.bc: $(CURDIR)/multi3.ll
	@mkdir -p $(DEPDIR)
	$(LLVM_AS) $< -o $@

# --- btf runtime crate (no_std, BPF target) ---
$(DEPDIR)/libbtf.rlib: $(CURDIR)/btf/src/lib.rs $(DEPDIR)/libcore.rlib
	@mkdir -p $(DEPDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name btf \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/libbtf.rmeta \
		$<

# --- btf-macros proc-macro crate (host) ---
# Built via cargo because it depends on syn/quote/proc-macro2. Proc-macro
# crates are always host-targeted; rustc loads the resulting .so when
# expanding `#[btf]` in BPF-target builds.
$(BLDDIR)/libbtf_macros.so: $(wildcard $(CURDIR)/btf-macros/src/*.rs) $(CURDIR)/btf-macros/Cargo.toml
	cd $(CURDIR)/btf-macros && RUSTC=$(RUSTC) $(CARGO) build --release
	@mkdir -p $(BLDDIR)
	cp $(CURDIR)/btf-macros/target/release/libbtf_macros.so $@

# --- bpf-postproc tool (host) ---
# Lowers __btf_field_byte_offset / __btf_field_exists polyfills into
# llvm.preserve.struct.access.index chains + llvm.bpf.preserve.field.info
# calls so the BPF backend emits CO-RE relocations.
#
# $(LLVM_STAMP) forces a relink when LLVM_DIR changes: cargo would rebuild,
# but make on its own would see the copy in $(BLDDIR) as up to date and keep
# a bpf-postproc bound to the previous LLVM.
$(BLDDIR)/bpf-postproc: $(wildcard $(CURDIR)/bpf-postproc/src/*.rs) $(CURDIR)/bpf-postproc/Cargo.toml $(LLVM_STAMP)
	cd $(CURDIR)/bpf-postproc && \
		$(LLVM_SYS_PREFIX_VAR)=$(LLVM_DIR) \
		$(CARGO) build --release --no-default-features --features $(POSTPROC_FEATURE)
	@mkdir -p $(BLDDIR)
	cp $(CURDIR)/bpf-postproc/target/release/bpf-postproc $@

# Records LLVM_DIR, and is only touched when the recorded value actually
# changes, so it does not force a rebuild on every invocation.
.PHONY: force
force:
$(LLVM_STAMP): force
	@mkdir -p $(BLDDIR)
	@echo '$(LLVM_DIR)' | cmp -s - $@ 2>/dev/null || echo '$(LLVM_DIR)' > $@

# --- Build BPF program bitcode ---
$(BLDDIR)/%.bc: %.rs $(DEPDIR)/liballoc.rlib $(DEPDIR)/libbtf.rlib $(BLDDIR)/libbtf_macros.so
	@mkdir -p $(BLDDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--extern btf=$(DEPDIR)/libbtf.rlib \
		--extern btf_macros=$(BLDDIR)/libbtf_macros.so \
		-Zcrate-attr='feature(alloc_error_handler)' \
		--crate-name $(basename $(notdir $<)) \
		--emit=llvm-bc -o $@ $<

# --- Extract .rlib contents for linking ---
$(DEPDIR)/extracted: $(DEPDIR)/libcore.rlib $(DEPDIR)/libcompiler_builtins.rlib $(DEPDIR)/liballoc.rlib
	@mkdir -p $(DEPDIR)/extracted
	@for lib in $^; do \
		name=$$(basename $$lib .rlib | sed 's/^lib//'); \
		mkdir -p $(DEPDIR)/extracted/$$name; \
		cd $(DEPDIR)/extracted/$$name && ar x $$lib; \
	done
	@touch $@

# --- Link all bitcode ---
$(BLDDIR)/%-linked.bc: $(BLDDIR)/%.bc $(DEPDIR)/extracted $(DEPDIR)/multi3.bc
	@cp $< $@
	@for i in 1 2 3 4 5; do \
		$(LLVM_LINK) --only-needed $@ \
			$$(find $(DEPDIR)/extracted -name '*.rcgu.o') \
			-o $@.tmp && mv $@.tmp $@; \
	done
	@$(LLVM_LINK) $@ $(DEPDIR)/multi3.bc -o $@.tmp && mv $@.tmp $@

# --- Lower btf polyfills to CO-RE relocations ---
$(BLDDIR)/%-reloc.bc: $(BLDDIR)/%-linked.bc $(BLDDIR)/bpf-postproc
	$(BLDDIR)/bpf-postproc $< $@

# --- Optimize after linking (inlines trivial functions, DCE) ---
# Internalize everything except struct_ops entry points and license,
# then optimize. This lets opt remove dead global symbols.
KEEP_SYMS := simple_ops \
             simple_select_cpu simple_enqueue simple_dispatch \
             simple_running simple_stopping simple_enable \
             simple_init simple_exit \
             cosmos_ops \
             cosmos_select_cpu cosmos_tick cosmos_enqueue cosmos_dispatch \
             cosmos_runnable cosmos_running cosmos_stopping \
             cosmos_enable cosmos_init_task cosmos_exit_task \
             cosmos_init cosmos_exit \
             _LICENSE
INTERNALIZE := $(foreach s,$(KEEP_SYMS),--internalize-public-api-list=$(s))
$(BLDDIR)/%-opt.bc: $(BLDDIR)/%-reloc.bc
	$(OPT) $(INTERNALIZE) --force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce,default<O2>' $< -o $@

# --- Add .ksyms, lower invoke→call, unreachable→ret for BPF ---
# add_ksyms.py converts invoke→call, making landing pad blocks dead.
# simplifycfg removes those dead blocks. add_ksyms.py then fixes any
# remaining unreachable (e.g. switch defaults).
$(BLDDIR)/%-ksyms.bc: $(BLDDIR)/%-opt.bc
	$(LLVM_DIS) $< -o $@.ll
	python3 $(CURDIR)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@.tmp.bc
	$(OPT) -passes=simplifycfg $@.tmp.bc -o $@.tmp2.bc
	$(LLVM_DIS) $@.tmp2.bc -o $@.ll
	python3 $(CURDIR)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll $@.tmp.bc $@.tmp2.bc

# --- Final BPF object ---
$(BLDDIR)/%.o: $(BLDDIR)/%-ksyms.bc
	$(LLC) -march=bpfel -mcpu=v4 -filetype=obj -o $@.tmp $<
	$(LLVM_OBJCOPY) \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality $@.tmp $@
	@rm -f $@.tmp

# --- BPF exception-handling programs ---
#
# Same tools and the same bc -> linked -> opt -> ksyms -> o shape as the
# pipeline above, with three differences:
#
#  * bpf-postproc is skipped, so -linked.bc feeds -opt.bc directly. All it
#    does is lower #[btf] CO-RE polyfills, and these programs are built
#    without --extern btf, so there is nothing for it to do.
#  * add_ksyms.py runs with KERNEL_BTF=1, which makes the BTF loadable: the
#    .ksyms prototypes mirror the real kfunc signatures (libbpf compares them
#    against the kernel's and rejects the void(void) placeholders otherwise
#    emitted), and Rust type names are reduced to C identifiers.
#  * add_ksyms.py runs with KEEP_INVOKE=1, so the invoke/landingpad pairs
#    survive into codegen and the backend can emit the (begin, end,
#    landing_pad) triples. Everything else the script does is still needed,
#    in particular unreachable->ret (a Rust panic path otherwise ends without
#    an exit insn) and the .ksyms tagging that puts bpf_throw, the cleanup
#    kfuncs and _Unwind_Resume into BTF.
#
# The rules are generated per program because the ksyms step needs those two
# environment variables and the pattern rule above does not set them.
EH_KEEP_SYMS := entry _LICENSE
EH_INTERNALIZE := $(foreach s,$(EH_KEEP_SYMS),--internalize-public-api-list=$(s))

define EH_PROG_RULES
$$(BLDDIR)/$(1).bc: $(1).rs $$(DEPDIR)/liballoc.rlib
	@mkdir -p $$(BLDDIR)
	$$(RUSTFLAGS_ENV) $$(RUSTC) --edition 2024 --crate-type rlib $$(RUSTC_COMMON) \
		--sysroot=/dev/null -L$$(DEPDIR) \
		--crate-name $(1) \
		--emit=llvm-bc -o $$@ $$<

$$(BLDDIR)/$(1)-opt.bc: $$(BLDDIR)/$(1)-linked.bc
	$$(OPT) $$(EH_INTERNALIZE) --force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce,default<O2>' $$< -o $$@

$$(BLDDIR)/$(1)-ksyms.bc: $$(BLDDIR)/$(1)-opt.bc
	$$(LLVM_DIS) $$< -o $$@.ll
	KEEP_INVOKE=1 KERNEL_BTF=1 python3 $$(CURDIR)/add_ksyms.py $$@.ll $$@.ll
	$$(LLVM_AS) $$@.ll -o $$@.tmp.bc
	$$(OPT) -passes=simplifycfg $$@.tmp.bc -o $$@.tmp2.bc
	$$(LLVM_DIS) $$@.tmp2.bc -o $$@.ll
	KEEP_INVOKE=1 KERNEL_BTF=1 python3 $$(CURDIR)/add_ksyms.py $$@.ll $$@.ll
	$$(LLVM_AS) $$@.ll -o $$@
	@rm -f $$@.ll $$@.tmp.bc $$@.tmp2.bc

.PRECIOUS: $$(BLDDIR)/$(1).bc $$(BLDDIR)/$(1)-linked.bc \
           $$(BLDDIR)/$(1)-opt.bc $$(BLDDIR)/$(1)-ksyms.bc
endef

$(foreach p,$(EH_PROGS),$(eval $(call EH_PROG_RULES,$(p))))

clean:
	rm -rf $(BLDDIR)

# Also drops the cargo target/ trees for the two host tools; they are
# gitignored but account for ~250M, far more than BLDDIR/DEPDIR combined.
distclean: clean
	rm -rf $(DEPDIR)
	rm -rf $(CURDIR)/bpf-postproc/target $(CURDIR)/btf-macros/target

.PRECIOUS: $(BLDDIR)/%.bc $(BLDDIR)/%-linked.bc $(BLDDIR)/%-reloc.bc $(BLDDIR)/%-opt.bc $(BLDDIR)/%-ksyms.bc

.PHONY: all clean distclean
