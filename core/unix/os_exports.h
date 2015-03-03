/* **********************************************************
 * Copyright (c) 2011-2015 Google, Inc.  All rights reserved.
 * Copyright (c) 2000-2010 VMware, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Copyright (c) 2003-2007 Determina Corp. */
/* Copyright (c) 2001-2003 Massachusetts Institute of Technology */
/* Copyright (c) 2000-2001 Hewlett-Packard Company */

/*
 * os_exports.h - Linux specific exported declarations
 */

#ifndef _OS_EXPORTS_H_
#define _OS_EXPORTS_H_ 1

#include <stdarg.h>
#include "../os_shared.h"
#ifdef MACOS
#  define _XOPEN_SOURCE 700 /* required to get POSIX, etc. defines out of ucontext.h */
#  define __need_struct_ucontext64 /* seems to be missing from Mac headers */
#  include <ucontext.h>
#endif

#ifndef NOT_DYNAMORIO_CORE_PROPER
# define getpid getpid_forbidden_use_get_process_id
#endif

#ifdef MACOS
/* We end up de-referencing the symlink so we rely on a prefix match */
# define DYNAMORIO_LIBRARY_NAME "libdynamorio."
# define DYNAMORIO_PRELOAD_NAME "libdrpreload.dylib"
#else
# define DYNAMORIO_LIBRARY_NAME "libdynamorio.so"
# define DYNAMORIO_PRELOAD_NAME "libdrpreload.so"
#endif

/* The smallest granularity the OS supports */
#define OS_ALLOC_GRANULARITY     (4*1024)
#define MAP_FILE_VIEW_ALIGNMENT  (4*1024)

/* We steal a segment register, and so use fs for x86 (where pthreads
 * uses gs) and gs for x64 (where pthreads uses fs) (presumably to
 * avoid conflicts w/ wine).
 * Keep this consistent w/ the TLS_SEG_OPCODE define in arch/instr.h
 * and TLS_SEG in arch/asm_defines.asm
 *
 * PR 205276 covers transparently stealing our segment selector.
 */
#ifdef X86
# ifdef X64
#  define SEG_TLS SEG_GS
#  define ASM_SEG "%gs"
#  define LIB_SEG_TLS SEG_FS /* libc+loader tls */
#  define LIB_ASM_SEG "%fs"
# else
#  define SEG_TLS SEG_FS
#  define ASM_SEG "%fs"
#  define LIB_SEG_TLS SEG_GS /* libc+loader tls */
#  define LIB_ASM_SEG "%gs"
# endif
#elif defined(ARM)
# ifdef X64
#  define SEG_TLS      DR_REG_TPIDRRO_EL0 /* DR_REG_TPIDRURO */
#  define LIB_SEG_TLS  DR_REG_TPIDR_EL0   /* DR_REG_TPIDRURW, libc+loader tls */
# else
#  define SEG_TLS      DR_REG_TPIDRURW
#  define LIB_SEG_TLS  DR_REG_TPIDRURO /* libc+loader tls */
# endif /* 64/32-bit */
#endif /* X86/ARM */

#define TLS_REG_LIB  LIB_SEG_TLS  /* TLS reg commonly used by libraries in Linux */
#define TLS_REG_ALT  SEG_TLS      /* spare TLS reg, used by DR in X86 Linux */

#define DR_REG_SYSNUM IF_X86_ELSE(REG_EAX/* not XAX */, DR_REG_R7)

#ifdef ARM
# ifdef X64
#  error NYI on AArch64
# endif
/* The TLS slot for DR's TLS base.
 * On ARM, we use the 'private' field of the tcbhead_t to store DR TLS base.
 * typedef struct
 * {
 *   dtv_t *dtv;
 *   void *private;
 * } tcbhead_t;
 * When using private loader, we control all the TLS allocation and
 * should be able to avoid using that field.
 * This is also used in asm code, so we use literal instead of sizeof.
 */
# define DR_TLS_BASE_OFFSET   IF_X64_ELSE(8, 4) /* skip dtv */
/* opcode for reading usr mode TLS base (user-read-only-thread-ID-register)
 * mrc p15, 0, reg_app, c13, c0, 3
 */
# define USR_TLS_REG_OPCODE 3
# define USR_TLS_COPROC_15 15
#endif

void *get_tls(ushort tls_offs);
void set_tls(ushort tls_offs, void *value);

/* in os.c */
void os_file_init(void);
void os_fork_init(dcontext_t *dcontext);
void os_thread_stack_store(dcontext_t *dcontext);
app_pc get_dynamorio_dll_end(void);
thread_id_t get_tls_thread_id(void);
thread_id_t get_sys_thread_id(void);
bool is_thread_terminated(dcontext_t *dcontext);
void os_wait_thread_terminated(dcontext_t *dcontext);
void os_tls_pre_init(int gdt_index);
/* XXX: reg_id_t is not defined here, use ushort instead */
ushort os_get_app_tls_base_offset(ushort/*reg_id_t*/ seg);
ushort os_get_app_tls_reg_offset(ushort/*reg_id_t*/ seg);
void *os_get_app_tls_base(dcontext_t *dcontext, ushort/*reg_id_t*/ seg);

#ifdef DEBUG
void os_enter_dynamorio(void);
#endif

/* We do NOT want our libc routines wrapped by pthreads, so we use
 * our own syscall wrappers.
 */
int open_syscall(const char *file, int flags, int mode);
int close_syscall(int fd);
int dup_syscall(int fd);
ssize_t read_syscall(int fd, void *buf, size_t nbytes);
ssize_t write_syscall(int fd, const void *buf, size_t nbytes);
void exit_process_syscall(long status);
void exit_thread_syscall(long status);
process_id_t get_parent_id(void);

/* i#238/PR 499179: our __errno_location isn't affecting libc so until
 * we have libc independence or our own private isolated libc we need
 * to preserve the app's libc's errno
 */
int get_libc_errno(void);
void set_libc_errno(int val);

/* i#46: Our env manipulation routines. */
extern char **our_environ;
void dynamorio_set_envp(char **envp);
#if !defined(NOT_DYNAMORIO_CORE_PROPER) && !defined(NOT_DYNAMORIO_CORE)
/* drinjectlib wants the libc version while the core wants the private version */
# define getenv our_getenv
#endif
char *our_getenv(const char *name);

/* to avoid unsetenv problems we have our own unsetenv */
#define unsetenv our_unsetenv
int our_unsetenv(const char *name);

/* new segment support
 * name is a string
 * wx should contain one of the strings "w", "wx", "x", or ""
 */
/* FIXME: also want control over where in rw region or ro region this
 * section goes -- for cl, order linked seems to do it, but for linux
 * will need a linker script (see unix/os.c for the nspdata problem)
 */
#ifdef MACOS
/* XXX: currently assuming all custom sections are writable and non-executable! */
# define DECLARE_DATA_SECTION(name, wx) \
     asm(".section __DATA,"name); \
     asm(".align 12"); /* 2^12 */
#else
# ifdef X86
#  define DECLARE_DATA_SECTION(name, wx) \
     asm(".section "name", \"a"wx"\", @progbits"); \
     asm(".align 0x1000");
# elif defined(ARM)
#  define DECLARE_DATA_SECTION(name, wx) \
     asm(".section "name", \"a"wx"\""); \
     asm(".align 12"); /* 2^12 */
# endif /* X86/ARM */
#endif /* MACOS/UNIX */

/* XXX i#465: It's unclear what section we should switch to after our section
 * declarations.  gcc 4.3 seems to switch back to text at the start of every
 * function, while gcc >= 4.6 seems to emit all code together without extra
 * section switches.  Since earlier versions of gcc do their own switching and
 * the latest versions expect .text, we choose to switch to the text section.
 */
#ifdef MACOS
# define END_DATA_SECTION_DECLARATIONS() \
     asm(".section __DATA,.data"); \
     asm(".align 12"); \
     asm(".text");
#else
# ifdef X86
#  define END_DATA_SECTION_DECLARATIONS() \
     asm(".section .data"); \
     asm(".align 0x1000"); \
     asm(".text");
# elif defined(ARM)
#  define END_DATA_SECTION_DECLARATIONS() \
     asm(".section .data"); \
     asm(".align 12"); \
     asm(".text");
# endif /* X86/ARM */
#endif

/* the VAR_IN_SECTION macro change where each var goes */
#define START_DATA_SECTION(name, wx) /* nothing */
#define END_DATA_SECTION() /* nothing */

/* Any assignment, even to 0, puts vars in current .data and not .bss for cl,
 * but for gcc we need to explicitly declare which section.  We still need
 * the .section asm above to give section attributes and alignment.
 */
#ifdef MACOS
# define VAR_IN_SECTION(name) __attribute__ ((section ("__DATA,"name)))
#else
# define VAR_IN_SECTION(name) __attribute__ ((section (name)))
#endif

/* Location of vsyscall "vdso" page.  Even when vdso is 2 pages we assume the
 * vsyscall is on the 1st page (i#1583).
 */
extern app_pc vsyscall_page_start;
/* pc of the end of the syscall instr itself */
extern app_pc vsyscall_syscall_end_pc;
/* pc where kernel returns control after sysenter vsyscall */
extern app_pc vsyscall_sysenter_return_pc;
#define VSYSCALL_PAGE_MAPS_NAME "[vdso]"

bool is_thread_create_syscall(dcontext_t *dcontext);
bool was_thread_create_syscall(dcontext_t *dcontext);
bool is_sigreturn_syscall(dcontext_t *dcontext);
bool was_sigreturn_syscall(dcontext_t *dcontext);
bool ignorable_system_call(int num, instr_t *gateway, dcontext_t *dcontext_live);

bool kernel_is_64bit(void);

void
os_handle_mov_seg(dcontext_t *dcontext, byte *pc);

/* in arch.c */
bool unhook_vsyscall(void);

/***************************************************************************/
/* in signal.c */

/* defines and typedefs exported for dr_jmp_buf_t */

#define NUM_NONRT   32 /* includes 0 */
#define OFFS_RT     32
#ifdef LINUX
#  define NUM_RT    33 /* RT signals are [32..64] inclusive, hence 33. */
#else
#  define NUM_RT     0 /* no RT signals */
#endif
/* MAX_SIGNUM is the highest valid signum. */
#define MAX_SIGNUM  ((OFFS_RT) + (NUM_RT) - 1)
/* i#336: MAX_SIGNUM is a valid signal, so we must allocate space for it.
 */
#define SIGARRAY_SIZE (MAX_SIGNUM + 1)

/* size of long */
#ifdef X64
# define _NSIG_BPW 64
#else
# define _NSIG_BPW 32
#endif

#ifdef LINUX
# define _NSIG_WORDS (MAX_SIGNUM / _NSIG_BPW)
#else
# define _NSIG_WORDS 1 /* avoid 0 */
#endif

/* kernel's sigset_t packs info into bits, while glibc's uses a short for
 * each (-> 8 bytes vs. 128 bytes)
 */
typedef struct _kernel_sigset_t {
#ifdef LINUX
    unsigned long sig[_NSIG_WORDS];
#elif defined(MACOS)
    unsigned int sig[_NSIG_WORDS];
#endif
} kernel_sigset_t;

void receive_pending_signal(dcontext_t *dcontext);
bool is_signal_restorer_code(byte *pc, size_t *len);
bool is_currently_on_sigaltstack(dcontext_t *dcontext);

#ifdef MACOS
/* mcontext_t is a pointer and we want the real thing */
/* We need room for avx.  If we end up with !YMM_ENABLED() we'll just end
 * up wasting some space in synched thread allocations.
 */
#  ifdef X64
typedef _STRUCT_MCONTEXT_AVX64 sigcontext_t; /* == __darwin_mcontext_avx64 */
#  else
typedef _STRUCT_MCONTEXT_AVX32 sigcontext_t; /* == __darwin_mcontext_avx32 */
#  endif
#else
typedef struct sigcontext sigcontext_t;
#endif
#define CONTEXT_HEAP_SIZE(sc) (sizeof(sc))
#define CONTEXT_HEAP_SIZE_OPAQUE (CONTEXT_HEAP_SIZE(sigcontext_t))

/* cross-platform sigcontext_t field access */
#ifdef MACOS
/* We're using _XOPEN_SOURCE >= 600 so we have __DARWIN_UNIX03 and thus leading __: */
# define SC_FIELD(name) __ss.__##name
#else
# define SC_FIELD(name) name
#endif
#ifdef X86
# ifdef X64
#  define SC_XIP SC_FIELD(rip)
#  define SC_XAX SC_FIELD(rax)
#  define SC_XCX SC_FIELD(rcx)
#  define SC_XDX SC_FIELD(rdx)
#  define SC_XBX SC_FIELD(rbx)
#  define SC_XSP SC_FIELD(rsp)
#  define SC_XBP SC_FIELD(rbp)
#  define SC_XSI SC_FIELD(rsi)
#  define SC_XDI SC_FIELD(rdi)
#  ifdef MACOS
#   define SC_XFLAGS SC_FIELD(rflags)
#  else
#   define SC_XFLAGS SC_FIELD(eflags)
#  endif
# else /* 32-bit */
#  define SC_XIP SC_FIELD(eip)
#  define SC_XAX SC_FIELD(eax)
#  define SC_XCX SC_FIELD(ecx)
#  define SC_XDX SC_FIELD(edx)
#  define SC_XBX SC_FIELD(ebx)
#  define SC_XSP SC_FIELD(esp)
#  define SC_XBP SC_FIELD(ebp)
#  define SC_XSI SC_FIELD(esi)
#  define SC_XDI SC_FIELD(edi)
#  define SC_XFLAGS SC_FIELD(eflags)
# endif /* 64/32-bit */
# define SC_FP SC_XBP
# define SC_SYSNUM_REG SC_XAX
#elif defined(ARM)
# ifdef X64
   /* FIXME i#1569: NYI */
#  error 64-bit ARM is not supported
# else
#  define SC_XIP SC_FIELD(arm_pc)
#  define SC_FP  SC_FIELD(arm_fp)
#  define SC_R0  SC_FIELD(arm_r0)
#  define SC_R1  SC_FIELD(arm_r1)
#  define SC_R2  SC_FIELD(arm_r2)
#  define SC_R3  SC_FIELD(arm_r3)
#  define SC_R4  SC_FIELD(arm_r4)
#  define SC_R5  SC_FIELD(arm_r5)
#  define SC_R6  SC_FIELD(arm_r6)
#  define SC_R7  SC_FIELD(arm_r7)
#  define SC_R8  SC_FIELD(arm_r8)
#  define SC_R9  SC_FIELD(arm_r9)
#  define SC_R10 SC_FIELD(arm_r10)
#  define SC_R11 SC_FIELD(arm_fp)
#  define SC_R12 SC_FIELD(arm_ip)
#  define SC_XSP SC_FIELD(arm_sp)
#  define SC_LR  SC_FIELD(arm_lr)
#  define SC_XFLAGS SC_FIELD(arm_cpsr)
#  define SC_SYSNUM_REG SC_R7
# endif /* 64/32-bit */
#endif /* X86/ARM */
void *
#ifdef MACOS
create_clone_record(dcontext_t *dcontext, reg_t *app_xsp,
                    app_pc thread_func, void *func_arg);
#else
create_clone_record(dcontext_t *dcontext, reg_t *app_xsp);
#endif

#ifdef MACOS
void *
get_clone_record_thread_arg(void *record);
#endif

void *
get_clone_record(reg_t xsp);
reg_t
get_clone_record_app_xsp(void *record);
byte *
get_clone_record_dstack(void *record);

#ifdef ARM
reg_t
get_clone_record_stolen_value(void *record);

uint /* dr_isa_mode_t but we have a header ordering problem */
get_clone_record_isa_mode(void *record);
#endif

app_pc
signal_thread_inherit(dcontext_t *dcontext, void *clone_record);
void
signal_fork_init(dcontext_t *dcontext);

bool
set_itimer_callback(dcontext_t *dcontext, int which, uint millisec,
                    void (*func)(dcontext_t *, priv_mcontext_t *),
                    void (*func_api)(dcontext_t *, dr_mcontext_t *));

uint
get_itimer_frequency(dcontext_t *dcontext, int which);

bool
sysnum_is_not_restartable(int sysnum);

/***************************************************************************/

/* in pcprofile.c */
void pcprofile_fragment_deleted(dcontext_t *dcontext, fragment_t *f);
void pcprofile_thread_exit(dcontext_t *dcontext);

/* in stackdump.c */
/* fork, dump core, and use gdb for complete stack trace */
void stackdump(void);
/* use backtrace feature of glibc for quick but sometimes incomplete trace */
void glibc_stackdump(int fd);

/* nudgesig.c */
bool
send_nudge_signal(process_id_t pid, uint action_mask,
                  client_id_t client_id, uint64 client_arg);

/* module.c */
/* source_fragment is the start pc of the fragment to be run under DR */
bool
at_dl_runtime_resolve_ret(dcontext_t *dcontext, app_pc source_fragment, int *ret_imm);
#endif /* _OS_EXPORTS_H_ */
