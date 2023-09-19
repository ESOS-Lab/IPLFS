/* SPDX-License-Identifier: GPL-2.0 */
/* CONFIG_CC_VERSION_TEXT (Do not delete this comment. See help in Kconfig) */
/*
 *
 * Automatically generated file; DO NOT EDIT.
 * Linux/x86 5.11.0 Kernel Configuration
 *
 */
/*
 * The use of "&&" / "||" is limited in certain expressions.
 * The following enable to calculate "and" / "or" with macro expansion only.
 */
/*
 * Helper macros to use CONFIG_ options in C/CPP expressions. Note that
 * these only work with boolean and tristate options.
 */
/*
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky.  Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0).  Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
/*
 * IS_BUILTIN(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise. For boolean options, this is equivalent to
 * IS_ENABLED(CONFIG_FOO).
 */
/*
 * IS_MODULE(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'm', 0
 * otherwise.
 */
/*
 * IS_REACHABLE(CONFIG_FOO) evaluates to 1 if the currently compiled
 * code can call a function defined in code compiled based on CONFIG_FOO.
 * This is similar to IS_ENABLED(), but returns false when invoked from
 * built-in code when CONFIG_FOO is set to 'm'.
 */
/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Linker script for x32 vDSO.
 * We #include the file to define the layout details.
 *
 * This file defines the version script giving the user-exported symbols in
 * the DSO.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* const.h: Macros for dealing with constants.  */
/* Some constant macros are used in both assembler and
 * C code.  Therefore we cannot annotate them always with
 * 'UL' and other type specifiers unilaterally.  We
 * use the following macros to deal with this.
 *
 * Similarly, _AT() will cast an expression with a type in C, but
 * leave it unchanged in asm.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * int-ll64 is used everywhere now.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * asm-generic/int-ll64.h
 *
 * Integer declarations for architectures which use "long long"
 * for 64-bit types.
 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * asm-generic/int-ll64.h
 *
 * Integer declarations for architectures which use "long long"
 * for 64-bit types.
 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * There seems to be no way of detecting this automatically from user
 * space, so 64 bit architectures should override this in their
 * bitsperlong.h. In particular, an architecture that supports
 * both 32 and 64 bit user space must not rely on CONFIG_64BIT
 * to decide it, but rather check a compiler provided macro.
 */
/*
 * FIXME: The check currently breaks x86-64 build, so it's
 * temporarily disabled. Please fix x86-64 and reenable
 */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2016 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */
/* PAGE_SHIFT determines the page size */
/* Cast *PAGE_MASK to a signed type so that it is sign-extended if
   virtual addresses are 32-bits but physical addresses are larger
   (ie, 32-bit PAE). */
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The index for the tss.ist[] array. The hardware limit is 7 entries.
 */
/*
 * Set __PAGE_OFFSET to the most negative possible address +
 * PGDIR_SIZE*17 (pgd slot 273).
 *
 * The gap is to allow a space for LDT remap for PTI (1 pgd slot) and space for
 * a hypervisor (16 slots). Choosing 16 slots for a hypervisor is arbitrary,
 * but it's what Xen requires.
 */
/* See Documentation/x86/x86_64/mm.rst for a description of the memory map. */
/*
 * User space process size.  This is the first address outside the user range.
 * There are a few constraints that determine this:
 *
 * On Intel CPUs, if a SYSCALL instruction is at the highest canonical
 * address, then that syscall will enter the kernel with a
 * non-canonical return address, and SYSRET will explode dangerously.
 * We avoid this particular problem by preventing anything executable
 * from being mapped at the maximum canonical address.
 *
 * On AMD CPUs in the Ryzen family, there's a nasty bug in which the
 * CPUs malfunction if they execute code from the highest canonical page.
 * They'll speculate right off the end of the canonical space, and
 * bad things happen.  This is worked around in the same way as the
 * Intel problem.
 *
 * With page table isolation enabled, we map the LDT in ... [stay tuned]
 */
/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
/*
 * In spite of the name, KERNEL_IMAGE_SIZE is a limit on the maximum virtual
 * address for the kernel image, rather than the limit on the size itself.
 * This can be at most 1 GiB, due to the fixmap living in the next 1 GiB (see
 * level2_kernel_pgt in arch/x86/kernel/head_64.S).
 *
 * On KASLR use 1 GiB by default, leaving 1 GiB for modules once the
 * page tables are fully set up.
 *
 * If KASLR is disabled we can shrink it to 0.5 GiB and increase the size
 * of the modules area to 1.5 GiB.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The below symbols may be defined for one or more, but not ALL, of the above
 * compilers. We don't consider that to be an error, so set them to nothing.
 * For example, some of them are for compiler specific plugins.
 */
/* Are two types/vars the same type (ignoring qualifiers)? */
/*
 * __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
 *			       non-scalar types unchanged.
 */
/*
 * Prefer C11 _Generic for better compile-times and simpler code. Note: 'char'
 * is not type-compatible with 'signed char', and we define a separate case.
 */
/* Is this type a native word size -- useful for atomic operations */
/* Compile time object size, -1 for unknown */
/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
/* Helpers for emitting diagnostics in pragmas. */
/* Indirect stringification.  Doing two levels allows the parameter to be a
 * macro itself.  For example, compile with -DFOO=bar, __stringify(FOO)
 * converts to "bar".
 */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Export symbols from the kernel to modules.  Forked from module.h
 * to reduce the amount of pointless cruft we feed to gcc when only
 * exporting a simple symbol or two.
 *
 * Try not to add #includes here.  It slows compilation and makes kernel
 * hackers place grumpy comments in header files.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/* Some toolchains use other characters (e.g. '`') to mark new line in macro */
/*
 * For assembly routines.
 *
 * Note when using these that you must specify the appropriate
 * alignment directives yourself
 */
/*
 * This is used by architectures to keep arguments on the stack
 * untouched by the compiler by keeping them live until the end.
 * The argument stack may be owned by the assembly-language
 * caller, not the callee, and gcc doesn't always understand
 * that.
 *
 * We have the return value, and a maximum of six arguments.
 *
 * This should always be followed by a "return ret" for the
 * protection to work (ie no more work that the compiler might
 * end up needing stack temporaries for).
 */
/* Assembly files may be compiled with -traditional .. */
/* SYM_T_FUNC -- type used by assembler to mark functions */
/* SYM_T_OBJECT -- type used by assembler to mark data */
/* SYM_T_NONE -- type used by assembler to mark entries of unknown type */
/* SYM_A_* -- align the symbol? */
/* SYM_L_* -- linkage of symbols */
/* === generic annotations === */
/* SYM_ENTRY -- use only if you have to for non-paired symbols */
/* SYM_START -- use only if you have to */
/* SYM_END -- use only if you have to */
/* === code annotations === */
/*
 * FUNC -- C-like functions (proper stack frame etc.)
 * CODE -- non-C code (e.g. irq handlers with different, special stack etc.)
 *
 * Objtool validates stack for FUNC, but not for CODE.
 * Objtool generates debug info for both FUNC & CODE, but needs special
 * annotations for each CODE's start (to describe the actual stack frame).
 *
 * Objtool requires that all code must be contained in an ELF symbol. Symbol
 * names that have a  .L prefix do not emit symbol table entries. .L
 * prefixed symbols can be used within a code region, but should be avoided for
 * denoting a range of code via ``SYM_*_START/END`` annotations.
 *
 * ALIAS -- does not generate debug info -- the aliased function will
 */
/* SYM_INNER_LABEL_ALIGN -- only for labels in the middle of code */
/* SYM_INNER_LABEL -- only for labels in the middle of code */
/*
 * SYM_FUNC_START_LOCAL_ALIAS -- use where there are two local names for one
 * function
 */
/*
 * SYM_FUNC_START_ALIAS -- use where there are two global names for one
 * function
 */
/* SYM_FUNC_START -- use for global functions */
/*
 * The same as SYM_FUNC_START_ALIAS, but we will need to distinguish these two
 * later.
 */
/* SYM_FUNC_START_NOALIGN -- use for global functions, w/o alignment */
/* SYM_FUNC_START_LOCAL -- use for local functions */
/* the same as SYM_FUNC_START_LOCAL_ALIAS, see comment near SYM_FUNC_START */
/* SYM_FUNC_START_LOCAL_NOALIGN -- use for local functions, w/o alignment */
/* SYM_FUNC_START_WEAK -- use for weak functions */
/* SYM_FUNC_START_WEAK_NOALIGN -- use for weak functions, w/o alignment */
/* SYM_FUNC_END_ALIAS -- the end of LOCAL_ALIASed or ALIASed function */
/*
 * SYM_FUNC_END -- the end of SYM_FUNC_START_LOCAL, SYM_FUNC_START,
 * SYM_FUNC_START_WEAK, ...
 */
/* the same as SYM_FUNC_END_ALIAS, see comment near SYM_FUNC_START */
/* SYM_CODE_START -- use for non-C (special) functions */
/* SYM_CODE_START_NOALIGN -- use for non-C (special) functions, w/o alignment */
/* SYM_CODE_START_LOCAL -- use for local non-C (special) functions */
/*
 * SYM_CODE_START_LOCAL_NOALIGN -- use for local non-C (special) functions,
 * w/o alignment
 */
/* SYM_CODE_END -- the end of SYM_CODE_START_LOCAL, SYM_CODE_START, ... */
/* === data annotations === */
/* SYM_DATA_START -- global data symbol */
/* SYM_DATA_START -- local data symbol */
/* SYM_DATA_END -- the end of SYM_DATA_START symbol */
/* SYM_DATA_END_LABEL -- the labeled end of SYM_DATA_START symbol */
/* SYM_DATA -- start+end wrapper around simple global data */
/* SYM_DATA_LOCAL -- start+end wrapper around simple local data */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* &a[0] degrades to a pointer: a different type from an array */
/*
 * This is needed in functions which generate the stack canary, see
 * arch/x86/kernel/smpboot.c::start_secondary() for an example.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Prevent the compiler from merging or refetching reads or writes. The
 * compiler is also forbidden from reordering successive instances of
 * READ_ONCE and WRITE_ONCE, but only when the compiler is aware of some
 * particular ordering. One way to make the compiler aware of ordering is to
 * put the two invocations of READ_ONCE or WRITE_ONCE in different C
 * statements.
 *
 * These two macros will also work on aggregate data types like structs or
 * unions.
 *
 * Their two major use cases are: (1) Mediating communication between
 * process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/* Built-in __init functions needn't be compiled with retpoline */
/* These macros are used to mark some functions or 
 * initialized data (doesn't apply to uninitialized data)
 * as `initialization' functions. The kernel can take this
 * as hint that the function is used only during the initialization
 * phase and free up used memory resources after
 *
 * Usage:
 * For functions:
 * 
 * You should add __init immediately before the function name, like:
 *
 * static void __init initme(int x, int y)
 * {
 *    extern int z; z = x * y;
 * }
 *
 * If the function has a prototype somewhere, you can also add
 * __init between closing brace of the prototype and semicolon:
 *
 * extern int initialize_foobar_device(int, int, int) __init;
 *
 * For initialized data:
 * You should insert __initdata or __initconst between the variable name
 * and equal sign followed by value, e.g.:
 *
 * static int init_variable __initdata = 0;
 * static const char linux_logo[] __initconst = { 0x32, 0x36, ... };
 *
 * Don't forget to initialize data not at file scope, i.e. within a function,
 * as gcc otherwise puts the data into the bss section and not into the init
 * section.
 */
/* These are for everybody (although not all archs will actually
   discard it in modules) */
/*
 * modpost check for section mismatches during the kernel build.
 * A section mismatch happens when there are references from a
 * code or data section to an init section (both code or data).
 * The init sections are (for most archs) discarded by the kernel
 * when early init has completed so all such references are potential bugs.
 * For exit sections the same issue exists.
 *
 * The following markers are used for the cases where the reference to
 * the *init / *exit section (code or data) is valid and will teach
 * modpost not to issue a warning.  Intended semantics is that a code or
 * data tagged __ref* can reference code or data from init section without
 * producing a warning (of course, no warning does not mean code is
 * correct, so optimally document why the __ref is needed and why it's OK).
 *
 * The markers follow same syntax rules as __init / __initdata.
 */
/* Used for MEMORY_HOTPLUG */
/* For assembly routines */
/* silence warnings when references are OK */
/* Data marked not to be saved by software suspend */
/*
 * Linker script for vDSO.  This is an ELF shared object prelinked to
 * its virtual address, and with only one read-only segment.
 * This script controls its layout.
 */
SECTIONS
{
 /*
	 * User/kernel shared data is before the vDSO.  This may be a little
	 * uglier than putting it after the vDSO, but it avoids issues with
	 * non-allocatable things that dangle past the end of the PT_LOAD
	 * segment.
	 */
 vvar_start = . - 4 * (1 << 12);
 vvar_page = vvar_start;
 /* Place all vvars at the offsets in asm/vvar.h. */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vvar.h: Shared vDSO/kernel variable declarations
 * Copyright (c) 2011 Andy Lutomirski
 *
 * A handful of variables are accessible (read-only) from userspace
 * code in the vsyscall page and the vdso.  They are declared here.
 * Some other file must define them with DEFINE_VVAR.
 *
 * In normal kernel code, they are used like any other variable.
 * In user code, they are accessed through the VVAR macro.
 *
 * These variables live in a page of kernel data that has an extra RO
 * mapping for userspace.  Each variable needs a unique offset within
 * that page; specify that offset with the DECLARE_VVAR macro.  (If
 * you mess up, the linker will catch it.)
 */
/*
 * EMIT_VVAR() is used by the kernel linker script to put vvars in the
 * right place. Also, it's used by kernel code to import offsets values.
 */
/* DECLARE_VVAR(offset, type, name) */
vvar__vdso_data = vvar_page + 128;
 pvclock_page = vvar_start + (1 << 12);
 hvclock_page = vvar_start + 2 * (1 << 12);
 timens_page = vvar_start + 3 * (1 << 12);
 /* Place all vvars in timens too at the offsets in asm/vvar.h. */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vvar.h: Shared vDSO/kernel variable declarations
 * Copyright (c) 2011 Andy Lutomirski
 *
 * A handful of variables are accessible (read-only) from userspace
 * code in the vsyscall page and the vdso.  They are declared here.
 * Some other file must define them with DEFINE_VVAR.
 *
 * In normal kernel code, they are used like any other variable.
 * In user code, they are accessed through the VVAR macro.
 *
 * These variables live in a page of kernel data that has an extra RO
 * mapping for userspace.  Each variable needs a unique offset within
 * that page; specify that offset with the DECLARE_VVAR macro.  (If
 * you mess up, the linker will catch it.)
 */
/*
 * EMIT_VVAR() is used by the kernel linker script to put vvars in the
 * right place. Also, it's used by kernel code to import offsets values.
 */
/* DECLARE_VVAR(offset, type, name) */
timens__vdso_data = timens_page + 128;
 . = SIZEOF_HEADERS;
 .hash : { *(.hash) } :text
 .gnu.hash : { *(.gnu.hash) }
 .dynsym : { *(.dynsym) }
 .dynstr : { *(.dynstr) }
 .gnu.version : { *(.gnu.version) }
 .gnu.version_d : { *(.gnu.version_d) }
 .gnu.version_r : { *(.gnu.version_r) }
 .dynamic : { *(.dynamic) } :text :dynamic
 .rodata : {
  *(.rodata*)
  *(.data*)
  *(.sdata*)
  *(.got.plt) *(.got)
  *(.gnu.linkonce.d.*)
  *(.bss*)
  *(.dynbss*)
  *(.gnu.linkonce.b.*)
 } :text
 /*
	 * Discard .note.gnu.property sections which are unused and have
	 * different alignment requirement from vDSO note sections.
	 */
 /DISCARD/ : {
  *(.note.gnu.property)
 }
 .note : { *(.note.*) } :text :note
 .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
 .eh_frame : { KEEP (*(.eh_frame)) } :text
 /*
	 * Text is well-separated from actual data: there's plenty of
	 * stuff that isn't used at runtime in between.
	 */
 .text : {
  *(.text*)
  *(.fixup)
 } :text =0x90909090,
 .altinstructions : { *(.altinstructions) } :text
 .altinstr_replacement : { *(.altinstr_replacement) } :text
 __ex_table : { *(__ex_table) } :text
 /DISCARD/ : {
  *(.discard)
  *(.discard.*)
  *(__bug_table)
 }
}
/*
 * Very old versions of ld do not recognize this name token; use the constant.
 */
/*
 * We must supply the ELF program headers explicitly to get just one
 * PT_LOAD segment, and set the flags explicitly to make segments read-only.
 */
PHDRS
{
 text PT_LOAD FLAGS(5) FILEHDR PHDRS; /* PF_R|PF_X */
 dynamic PT_DYNAMIC FLAGS(4); /* PF_R */
 note PT_NOTE FLAGS(4); /* PF_R */
 eh_frame_hdr 0x6474e550;
}
/*
 * This controls what userland symbols we export from the vDSO.
 */
VERSION {
 LINUX_2.6 {
 global:
  __vdso_clock_gettime;
  __vdso_gettimeofday;
  __vdso_getcpu;
  __vdso_time;
  __vdso_clock_getres;
 local: *;
 };
}
