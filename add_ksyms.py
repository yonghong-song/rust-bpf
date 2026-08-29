#!/usr/bin/env python3
# Add section ".ksyms" and BTF-enabling debug metadata to extern function
# declarations in LLVM IR so that LLC generates proper BTF FUNC entries.
# Usage: add_ksyms.py input.ll output.ll

import os, re, sys

text = open(sys.argv[1]).read()

# The kernel only accepts BTF type names that are C identifiers, so a
# monomorphised Rust name like "NonNull<u8>" makes the whole .BTF section
# unloadable and takes func_info/line_info down with it.  Rewrite the offending
# characters in the debug info the BTF is derived from.  Only type names are
# touched; file names and linkage names do not reach BTF.
if os.environ.get('KERNEL_BTF'):
    def sanitize_name(m):
        head, name = m.group(1), m.group(2)
        fixed = re.sub(r'[^0-9A-Za-z_]', '_', name)
        if fixed and fixed[0].isdigit():
            fixed = '_' + fixed
        return f'{head}"{fixed}"'

    text = re.sub(
        r'(!(?:DICompositeType|DIBasicType|DIDerivedType|DIEnumerator|'
        r'DISubprogram)\([^)]*?\bname:\s*)"([^"]*)"',
        sanitize_name,
        text,
    )

# Find the highest existing metadata ID so we can append new ones.
max_id = max((int(m[1:]) for m in re.findall(r'!\d+', text)), default=0)

# Find the DIFile used by existing DISubprograms (reuse it for kfuncs).
di_file_match = re.search(r'(!\d+) = !DIFile\(', text)
di_file = di_file_match.group(1) if di_file_match else None

# Collect non-intrinsic declare lines and add section + debug metadata.
new_metadata = []
next_id = max_id + 1

# With KERNEL_BTF set, the DISubroutineType of each kfunc mirrors the LLVM
# declaration instead of being an empty void(void).  libbpf checks the BTF
# prototype of every kfunc extern against the kernel's with
# bpf_core_types_are_compat(), which compares the argument count first, so a
# void(void) prototype makes any kfunc that takes arguments unloadable.
#
# Only void and integer arguments are reconstructed exactly.  A pointer
# becomes a pointer to void, which is compatible with the kernel only when the
# kfunc's own argument is void * -- reconstructing "struct task_struct *" and
# friends would mean pulling the real types out of the kernel's BTF.
#
# Off by default so the LLVM 22 scx_* objects stay byte for byte what they
# were.
kernel_btf = bool(os.environ.get('KERNEL_BTF'))
emit_protos = kernel_btf

# Shared DI type nodes, keyed by LLVM type name.
di_types = {}

def di_type_for(llvm_ty):
    """Metadata reference for an LLVM type, or None for void/unsupported."""
    global next_id

    if llvm_ty == 'void':
        return None
    if llvm_ty in di_types:
        return di_types[llvm_ty]

    m = re.fullmatch(r'i(\d+)', llvm_ty)
    if m:
        bits = int(m.group(1))
        # BTF INT compatibility only looks at the bit offset, so an unsigned
        # integer of the right width matches any kernel integer of that width.
        node = f'!{next_id}'
        new_metadata.append(
            f'{node} = !DIBasicType(name: "__u{bits}", size: {bits}, '
            f'encoding: DW_ATE_unsigned)')
        next_id += 1
    elif llvm_ty == 'ptr':
        node = f'!{next_id}'
        new_metadata.append(
            f'{node} = !DIDerivedType(tag: DW_TAG_pointer_type, size: 64)')
        next_id += 1
    else:
        return None

    di_types[llvm_ty] = node
    return node

def split_args(args):
    """Split a declare's argument list on top-level commas."""
    out, depth, cur = [], 0, ''
    for ch in args:
        if ch in '([{<':
            depth += 1
        elif ch in ')]}>':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [a.strip() for a in out]

def subroutine_types(line):
    """'types:' list mirroring a declare's signature, or '!{null}'."""
    m = re.match(r'declare\s+(?:!\S+\s+\S+\s+)*(.*?)\s*@[\w.$]+\((.*)\)', line)
    if not m:
        return '!{null}'

    # The return type is the last word before the function name; anything
    # before it is a parameter attribute (noundef, zeroext, ...).
    ret_ty = m.group(1).split()[-1] if m.group(1).split() else 'void'
    nodes = [di_type_for(ret_ty) or 'null']

    for arg in split_args(m.group(2)):
        words = arg.split()
        if not words or words[0] == '...':
            continue
        node = di_type_for(words[0])
        if not node:
            # An argument we cannot describe would produce a prototype that is
            # wrong rather than merely incomplete; leave the whole function
            # undescribed instead.
            return '!{null}'
        nodes.append(node)

    return '!{' + ', '.join(nodes) + '}'

def add_ksyms(m):
    global next_id
    line = m.group(0)

    # Extract function name.
    name_match = re.search(r'@(\w+)\(', line)
    name = name_match.group(1) if name_match else "unknown"

    types = subroutine_types(line) if emit_protos else '!{null}'

    # Allocate metadata IDs: one for DISubprogram, one for DISubroutineType.
    dbg_id = next_id
    subrt_id = next_id + 1
    next_id += 2

    file_ref = di_file if di_file else '!0'
    new_metadata.append(
        f'!{dbg_id} = !DISubprogram(name: "{name}", scope: {file_ref}, '
        f'file: {file_ref}, type: !{subrt_id}, '
        f'flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)')
    new_metadata.append(
        f'!{subrt_id} = !DISubroutineType(types: {types})')

    # Insert !dbg right after 'declare' and append section at the end.
    # declare !dbg !N <rest> #M section ".ksyms"
    line = line.replace('declare ', f'declare !dbg !{dbg_id} ', 1)
    return f'{line} section ".ksyms"'

# Skip LLVM intrinsics (@llvm.*) and rust_eh_personality.
text = re.sub(
    r'^declare\s(?!.*@llvm\.)(?!.*@rust_eh_personality\b).*#\d+\s*$',
    add_ksyms,
    text,
    flags=re.MULTILINE,
)

# LLC lowers llvm.memcpy/memmove/memset intrinsics and the memcmp libcall
# to plain extern symbols (@memcpy, @memcmp, ...). The kernel doesn't expose
# those names as kfuncs, so rename them to the arena-aware bpf_arena_* kfuncs:
#
#   llvm.memcpy.p0.p0.i64(dst, src, len, isvolatile) -> bpf_arena_memcpy(dst, src, len)
#   llvm.memmove.p0.p0.i64(dst, src, len, isvolatile) -> bpf_arena_memcpy(dst, src, len)
#   (both overlapping and non-overlapping copies go through bpf_arena_memcpy
#    for now; memmove semantics can be added as a separate kfunc later)
#   call ... @memcmp(...) -> call ... @bpf_arena_memcmp(...)
#   call ... @memcpy(...) -> call ... @bpf_arena_memcpy(...)
mem_intrinsics = {
    'bpf_arena_memcpy': (r'call void @llvm\.(?:memcpy|memmove)\.p0\.p0\.i64\('
                         r'(ptr[^,]*),\s*(ptr[^,]*),\s*(i64[^,]*),\s*i1[^)]*\)'),
}

# Find an attribute group number used by other extern decls.
attr_match = re.search(r'^declare\s.*#(\d+)\s+section', text, re.MULTILINE)
attr_num = attr_match.group(1) if attr_match else '1'

extra_decls = []
for name, pattern in mem_intrinsics.items():
    if re.search(pattern, text):
        text = re.sub(
            pattern,
            rf'call void @{name}(\1, \2, \3)',
            text,
        )
        dbg_id = next_id
        subrt_id = next_id + 1
        next_id += 2
        file_ref = di_file if di_file else '!0'
        new_metadata.append(
            f'!{dbg_id} = !DISubprogram(name: "{name}", scope: {file_ref}, '
            f'file: {file_ref}, type: !{subrt_id}, '
            f'flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)')
        new_metadata.append(
            f'!{subrt_id} = !DISubroutineType(types: !{{null}})')
        extra_decls.append(
            f'declare !dbg !{dbg_id} void @{name}(ptr, ptr, i64) '
            f'#{attr_num} section ".ksyms"')

# Rename memcmp/memcpy libcalls (produced by LLVM's lowering of slice
# comparisons / copies) to the arena-aware bpf_arena_* kfuncs. This covers
# both the `declare` lines add_ksyms() already tagged and every call site.
# We also rename the matching DISubprogram debug-info name, because LLC
# derives the BTF FUNC name from that rather than from the LLVM symbol —
# if we only renamed the symbol, libbpf would see `bpf_arena_memcmp` in the
# ELF symbol table but `memcmp` in BTF and fail the kfunc resolve.
libcall_renames = {
    'memcmp': 'bpf_arena_memcmp',
    'memcpy': 'bpf_arena_memcpy',
}
for old, new in libcall_renames.items():
    text = re.sub(r'(?<![A-Za-z0-9_.])@' + re.escape(old) + r'\b',
                  '@' + new, text)
    text = re.sub(r'(!DISubprogram\(name:\s*")' + re.escape(old) + r'"',
                  r'\g<1>' + new + '"', text)

# LLC lowers 'resume' instructions to calls to _Unwind_Resume.
# Replace resume with a direct call so BTF/.ksyms picks it up.
if re.search(r'^\s+resume\s', text, re.MULTILINE):
    # resume { ptr, i32 } %val -> extract ptr, call _Unwind_Resume, unreachable
    def replace_resume(m):
        indent = m.group(1)
        val = m.group(2)
        meta = m.group(3) or ''
        # Use a unique tmp name based on position to avoid SSA conflicts.
        tmp = f'%_unwind_ptr.{m.start()}'
        return (f'{indent}{tmp} = extractvalue {{ ptr, i32 }} {val}, 0{meta}\n'
                f'{indent}call void @_Unwind_Resume(ptr {tmp}){meta}\n'
                f'{indent}unreachable')
    text = re.sub(
        r'^(\s+)resume \{ ptr, i32 \} (\S+)(,\s*!dbg\s+!\d+)?$',
        replace_resume,
        text,
        flags=re.MULTILINE,
    )
    dbg_id = next_id
    subrt_id = next_id + 1
    next_id += 2
    file_ref = di_file if di_file else '!0'
    new_metadata.append(
        f'!{dbg_id} = !DISubprogram(name: "_Unwind_Resume", scope: {file_ref}, '
        f'file: {file_ref}, type: !{subrt_id}, '
        f'flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)')
    # Deliberately void(void) even though the call passes the exception
    # object: the kernel's _Unwind_Resume kfunc takes no arguments, and the
    # verifier rewrites the call into a return before ever type checking it.
    new_metadata.append(
        f'!{subrt_id} = !DISubroutineType(types: !{{null}})')
    extra_decls.append(
        f'declare !dbg !{dbg_id} void @_Unwind_Resume(ptr) '
        f'#{attr_num} section ".ksyms"')

# Fix BTF linkage: Rust emits DISPFlagDefinition | DISPFlagOptimized for all
# functions, even internal ones. Without DISPFlagLocalToUnit, LLC generates
# BTF FUNC with linkage=global. The verifier then treats internal subprogs as
# global, validating caller args against the BTF signature independently.
# This fails when the optimizer drops dead args (e.g. #[track_caller]'s
# implicit &Location). Add DISPFlagLocalToUnit to every DISubprogram attached
# to a `define internal` function so LLC emits linkage=static in BTF.
internal_dbg_ids = set()
for m in re.finditer(r'^define\s+internal\s.*!dbg\s+(!\d+)', text, re.MULTILINE):
    internal_dbg_ids.add(m.group(1))

for dbg_id in internal_dbg_ids:
    text = re.sub(
        r'(' + re.escape(dbg_id) + r'\s*=\s*distinct\s+!DISubprogram\([^)]*'
        r'spFlags:\s*)(DISPFlagDefinition)',
        r'\1DISPFlagLocalToUnit | DISPFlagDefinition',
        text,
    )

# Strip 'noreturn' so LLVM doesn't DCE code after noreturn calls.
text = re.sub(r'\bnoreturn\b', '', text)
text = re.sub(r'^attributes (#\d+) = \{\s*\}$',
              r'attributes \1 = { noinline }', text, flags=re.MULTILINE)

# Convert 'invoke' to 'call' + 'br', dropping the unwind path.
#
# LLVM < 23 has no BPF exception handling, so the unwind edge has nowhere to
# go and the landing pads are dead weight. With KEEP_INVOKE=1 the invokes are
# left alone instead: LLVM >= 23 lowers them itself and records every invoke
# region in .bpf_cleanup (9d51c891b719 "[BPF] Add exception handling support
# with .bpf_cleanup section"), which is what lets bpf_throw() find the Drop
# cleanup code at run time.
def lower_invoke(m):
    indent = m.group(1)
    ret_assign = m.group(2) or ''
    tail = m.group(3)
    normal = m.group(4)
    meta = m.group(5) or ''
    call_meta = re.sub(r',\s*!noalias\s+!\d+', '', meta)
    return (f'{indent}{ret_assign}call {tail.rstrip()}{call_meta}\n'
            f'{indent}br label %{normal}{call_meta}')

if not os.environ.get('KEEP_INVOKE'):
    text = re.sub(
        r'^(\s+)((?:%\S+\s*=\s*)?)'
        r'invoke\s+'
        r'(.*?)'
        r'\s+to\s+label\s+%(\S+)'
        r'\s+unwind\s+label\s+%\S+'
        r'((?:,\s*!\w+\s+!\d+)*)$',
        lower_invoke,
        text,
        flags=re.MULTILINE,
    )

# Replace 'unreachable' with 'ret'. 'ret' compiles to a BPF exit insn.
# BPF verifier requires every subprogram to end with exit or jmp.
def fix_unreachable(text):
    lines = text.split('\n')
    out = []
    ret_type = 'void'
    for line in lines:
        m = re.match(r'define\s.*?\s+(@\S+)\(', line)
        if m:
            rt = re.search(r'define\s+(?:internal\s+)?(?:fastcc\s+)?(?:noundef\s+)?(?:zeroext\s+)?(\S+)\s+@', line)
            if rt:
                ret_type = rt.group(1)
        if re.match(r'  +unreachable', line):
            indent = re.match(r'(  +)', line).group(1)
            meta = ''
            mm = re.search(r'(,\s*!dbg\s+!\d+)', line)
            if mm:
                meta = mm.group(1)
            if ret_type == 'void':
                out.append(f'{indent}ret void{meta}')
            elif ret_type in ('i1', 'i8', 'i16', 'i32', 'i64'):
                out.append(f'{indent}ret {ret_type} 0{meta}')
            else:
                out.append(f'{indent}ret {ret_type} zeroinitializer{meta}')
            continue
        out.append(line)
    return '\n'.join(out)

text = fix_unreachable(text)

# Insert extra declares before the first 'attributes' line.
if extra_decls:
    text = re.sub(
        r'^(attributes\s)',
        '\n'.join(extra_decls) + '\n\n\\1',
        text,
        count=1,
        flags=re.MULTILINE,
    )

# Append new metadata at the end.
if new_metadata:
    text = text.rstrip() + '\n' + '\n'.join(new_metadata) + '\n'

open(sys.argv[2], 'w').write(text)
