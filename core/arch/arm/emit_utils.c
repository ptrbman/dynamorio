/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
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

/* file "emit_utils.c"
 * The ARM processors does not maintain cache consistency in hardware,
 * so we need be careful about getting stale cache entries.
 */

#include "../globals.h"
#include "arch.h"
#include "instr.h"
#include "instr_create.h"
#include "instrlist.h"
#include "instrument.h" /* for dr_insert_call() */

#define APP  instrlist_meta_append

/***************************************************************************/
/*                               EXIT STUB                                 */
/***************************************************************************/

byte *
insert_relative_target(byte *pc, cache_pc target, bool hot_patch)
{
    /* FIXME i#1551: NYI on ARM.
     * We may want to refactor the calling code to remove this and only
     * use patch_branch().
     */
    ASSERT_NOT_IMPLEMENTED(false);
    return NULL;
}

byte *
insert_relative_jump(byte *pc, cache_pc target, bool hot_patch)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return NULL;
}

/* inserts any nop padding needed to ensure patchable branch offsets don't
 * cross cache line boundaries.  If emitting sets the offset field of all
 * instructions, else sets the translation for the added nops (for
 * recreating). If emitting and -pad_jmps_shift_{bb,trace} returns the number
 * of bytes to shift the start_pc by (this avoids putting a nop before the
 * first exit cti) else returns 0.
 */
uint
nop_pad_ilist(dcontext_t *dcontext, fragment_t *f, instrlist_t *ilist, bool emitting)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return 0;
}

/* Emit code for the exit stub at stub_pc.  Return the size of the
 * emitted code in bytes.  This routine assumes that the caller will
 * take care of any cache synchronization necessary (though none is
 * necessary on the Pentium).
 * The stub is unlinked initially, except coarse grain indirect exits,
 * which are always linked.
 */
int
insert_exit_stub_other_flags(dcontext_t *dcontext, fragment_t *f,
                             linkstub_t *l, cache_pc stub_pc, ushort l_flags)
{
    byte *pc = (byte *) stub_pc;
    if (LINKSTUB_DIRECT(l_flags)) {
        /* FIXME i#1575: coarse-grain NYI on ARM */
        ASSERT_NOT_IMPLEMENTED(!TEST(FRAG_COARSE_GRAIN, f->flags));

        if (FRAG_IS_THUMB(f->flags)) {
            /* FIXME i#1551: add Thumb support */
            ASSERT_NOT_IMPLEMENTED(false);
        } else {
            ptr_int_t ls = (ptr_int_t) l;
            /* XXX: should we use our IR and encoder instead?  Then we could
             * share code with emit_do_syscall(), though at a perf cost.
             */
            /* XXX: we can shrink from 16 bytes to 12 if we keep &linkstub as
             * data at the end of the stub and use a pc-rel load instead of the 2
             * mov-immed instrs (followed by the same ldr into pc):
             *    ldr r0 [pc]
             *    ldr pc, [r10, #fcache-return-offs]
             *    <&linkstub>
             * However, that may incur dcache misses w/ separate icache.
             * Another idea is to spill lr instead of r0 and use "bl fcache_return"
             * (again with &linkstub as data), though it has reachability problems.
             */
            /* str r0, [r10, #r0-slot] */
            *(uint *)pc =
                0xe5800000 | ((dr_reg_stolen - DR_REG_R0) << 16) | TLS_REG0_SLOT;
            pc += ARM_INSTR_SIZE;
            /* movw r0, #bottom-half-&linkstub */
            *(uint*)pc =
                0xe3000000 | ((ls & 0xf000) << 4) | (ls & 0xfff);
            pc += ARM_INSTR_SIZE;
            /* movt r0, #top-half-&linkstub */
            *(uint *)pc =
                0xe3400000 | ((ls & 0xf0000000) >> 12) | ((ls & 0x0fff0000) >> 16);
            pc += ARM_INSTR_SIZE;
            /* ldr pc, [r10, #fcache-return-offs] */
            *(uint*)pc =
                0xe590f000 | ((dr_reg_stolen - DR_REG_R0) << 16) |
                get_direct_exit_tls_offs(dcontext, f->flags);
            pc += ARM_INSTR_SIZE;
        }
        return (int) (pc - stub_pc);
    } else {
        /* FIXME i#1551: ibl NYI on ARM */
        ASSERT_NOT_IMPLEMENTED(false);
        return 0;
    }
}

void
patch_branch(cache_pc branch_pc, cache_pc target_pc, bool hot_patch)
{
    /* FIXME i#1551: support Thumb */
    if (((*(branch_pc + 3)) & 0xf) == 0xa) {
        /* OP_b with 3-byte immed that's stored as >>2 */
        uint val = *(uint *)branch_pc;
        int disp = (target_pc - branch_pc + ARM_CUR_PC_OFFS);
        ASSERT(ALIGNED(disp, ARM_INSTR_SIZE));
        ASSERT(disp < 0x3000000 || disp > -64*1024*1024); /* 26-bit max */
        val |= ((disp >> 2) & 0xffffff);
        *(uint *)branch_pc = val;
    } else {
        /* FIXME i#1551: support patching OP_ldr into pc using TLS-stored offset.
         * We'll need to add the unlinked ibl addresses to TLS?
         */
        ASSERT_NOT_IMPLEMENTED(false);
    }
}

cache_pc
exit_cti_disp_pc(cache_pc branch_pc)
{
    /* FIXME i#1551: NYI on ARM.
     * We may want to refactor the calling code to remove this and only
     * use patch_branch().
     */
    ASSERT_NOT_IMPLEMENTED(false);
    return NULL;
}

void
link_indirect_exit_arch(dcontext_t *dcontext, fragment_t *f,
                        linkstub_t *l, bool hot_patch,
                        app_pc target_tag)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}

cache_pc
indirect_linkstub_stub_pc(dcontext_t *dcontext, fragment_t *f, linkstub_t *l)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return NULL;
}

cache_pc
cbr_fallthrough_exit_cti(cache_pc prev_cti_pc)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return NULL;
}

/* This is an atomic operation with respect to a thread executing in the
 * cache (barring ifdef NATIVE_RETURN, which is now removed), for
 * inlined indirect exits the
 * unlinked path of the ibl routine detects the race condition between the
 * two patching writes and handles it appropriately unless using the
 * atomic_inlined_linking option in which case there is only one patching
 * write (since tail is duplicated)
 */
void
unlink_indirect_exit(dcontext_t *dcontext, fragment_t *f, linkstub_t *l)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}


/*******************************************************************************
 * COARSE-GRAIN FRAGMENT SUPPORT
 */

cache_pc
entrance_stub_jmp(cache_pc stub)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return NULL;
}

/* Returns whether stub is an entrance stub as opposed to a fragment
 * or a coarse indirect stub.  FIXME: if we separate coarse indirect
 * stubs from bodies we'll need to put them somewhere else, or fix up
 * decode_fragment() to be able to distinguish them in some other way
 * like first instruction tls slot.
 */
bool
coarse_is_entrance_stub(cache_pc stub)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return false;
}

/*###########################################################################
 *
 * fragment_t Prefixes
 *
 * Two types: indirect branch target, which restores eflags and xcx, and
 * normal prefix, which just restores xcx
 */

void
insert_fragment_prefix(dcontext_t *dcontext, fragment_t *f)
{
    ASSERT(f->prefix_size == 0);
    if (use_ibt_prefix(f->flags)) {
        /* FIXME i#1551: NYI on ARM */
        ASSERT_NOT_IMPLEMENTED(false);
    }
    /* make sure emitted size matches size we requested */
    ASSERT(f->prefix_size == fragment_prefix_size(f->flags));
}

/***************************************************************************/
/*             THREAD-PRIVATE/SHARED ROUTINE GENERATION                    */
/***************************************************************************/
#ifdef X64
# error NYI on AArch64
#endif

/* helper functions for emit_fcache_enter_common */

#define OPND_ARG1    opnd_create_reg(DR_REG_R0)

/* Load app's TLS base to reg_base and then APP_TLS_SWAP_SLOT value to reg_slot.
 * This should be only used on emitting fcache enter/return code.
 */
static void
append_load_app_tls_slot(dcontext_t *dcontext, instrlist_t *ilist,
                         reg_id_t reg_base, reg_id_t reg_slot)
{
    /* load app's TLS base from user-read-only-thread-ID register
     * mrc p15, 0, reg_base, c13, c0, 3
     */
    APP(ilist, INSTR_CREATE_mrc(dcontext,
                                opnd_create_reg(reg_base),
                                OPND_CREATE_INT(15),
                                OPND_CREATE_INT(0),
                                opnd_create_reg(DR_REG_CR13),
                                opnd_create_reg(DR_REG_CR0),
                                OPND_CREATE_INT(APP_TLS_REG_OPCODE)));
    /* ldr reg_slot, [reg, APP_TLS_SLOT_SWAP] */
    APP(ilist, XINST_CREATE_load(dcontext,
                                 opnd_create_reg(reg_slot),
                                 OPND_CREATE_MEMPTR(reg_base,
                                                    APP_TLS_SWAP_SLOT)));
}

/* Having only one thread register (TPIDRURO) shared between app and DR,
 * we steal a register for DR's TLS base in the code cache,
 * and steal an app's TLS slot for DR's TLS base in the C code.
 * On entering the code cache (fcache_enter):
 * - grab gen routine's parameter dcontext and put it into REG_DCXT
 * - load app's TLS base from TPIDRURO to r0
 * - load DR's TLS base from app's TLS slot we steal ([r0, APP_TLS_SWAP_SLOT])
 * - restore the app original value (stored in os_tls->app_tls_swap)
 *   back to app's TLS slot ([r0, APP_TLS_SWAP_SLOT])
 */
void
append_fcache_enter_prologue(dcontext_t *dcontext, instrlist_t *ilist, bool absolute)
{
    ASSERT_NOT_IMPLEMENTED(!absolute &&
                           !TEST(SELFPROT_DCONTEXT, dynamo_options.protect_mask));
    /* grab gen routine's parameter dcontext and put it into REG_DCXT */
    APP(ilist, XINST_CREATE_move(dcontext,
                                 opnd_create_reg(REG_DCXT),
                                 OPND_ARG1/*r0*/));
    /* load app's TLS base into r0 and DR's TLS base into dr_reg_stolen */
    append_load_app_tls_slot(dcontext, ilist, SCRATCH_REG0, dr_reg_stolen);
    /* load app original value from os_tls->app_tls_swap */
    APP(ilist, RESTORE_FROM_TLS(dcontext, SCRATCH_REG1, os_get_app_tls_swap_offset()));
    /* store app value back to app's TLS swap slot ([r0, APP_TLS_SWAP_SLOT]) */
    APP(ilist, XINST_CREATE_store(dcontext,
                                  OPND_CREATE_MEMPTR(SCRATCH_REG0,
                                                     APP_TLS_SWAP_SLOT),
                                  opnd_create_reg(SCRATCH_REG1)));
}

void
append_call_exit_dr_hook(dcontext_t *dcontext, instrlist_t *ilist,
                         bool absolute, bool shared)
{
    /* i#1551: DR_HOOK is not supported on ARM */
    ASSERT_NOT_IMPLEMENTED(EXIT_DR_HOOK == NULL);
}

void
append_restore_xflags(dcontext_t *dcontext, instrlist_t *ilist, bool absolute)
{
    APP(ilist, RESTORE_FROM_DC(dcontext, SCRATCH_REG0, XFLAGS_OFFSET));
    APP(ilist, INSTR_CREATE_msr(dcontext,
                                opnd_create_reg(DR_REG_CPSR),
                                OPND_CREATE_INT_MSR_NZCVQG(),
                                opnd_create_reg(SCRATCH_REG0)));
}

void
append_restore_simd_reg(dcontext_t *dcontext, instrlist_t *ilist, bool absolute)
{
    /* s16–s31 (d8–d15, q4–q7) are callee save */
    /* FIXME i#1551: NYI on ARM */
}

#ifdef X64
# define DR_GPR_LIST_LENGTH 32
# define DR_REG_LIST_TAIL                                      \
    opnd_create_reg(DR_REG_X14), opnd_create_reg(DR_REG_X15),  \
    opnd_create_reg(DR_REG_X16), opnd_create_reg(DR_REG_X17),  \
    opnd_create_reg(DR_REG_X18), opnd_create_reg(DR_REG_X19),  \
    opnd_create_reg(DR_REG_X20), opnd_create_reg(DR_REG_X21),  \
    opnd_create_reg(DR_REG_X22), opnd_create_reg(DR_REG_X23),  \
    opnd_create_reg(DR_REG_X24), opnd_create_reg(DR_REG_X25),  \
    opnd_create_reg(DR_REG_X26), opnd_create_reg(DR_REG_X27),  \
    opnd_create_reg(DR_REG_X28), opnd_create_reg(DR_REG_X29),  \
    opnd_create_reg(DR_REG_X30), opnd_create_reg(DR_REG_X31)
#else
# define DR_REG_LIST_LENGTH 15 /* no R15 (pc) */
# define DR_REG_LIST_TAIL opnd_create_reg(DR_REG_R14)
#endif

#define DR_REG_LIST                                           \
    opnd_create_reg(DR_REG_R0),  opnd_create_reg(DR_REG_R1),  \
    opnd_create_reg(DR_REG_R2),  opnd_create_reg(DR_REG_R3),  \
    opnd_create_reg(DR_REG_R4),  opnd_create_reg(DR_REG_R5),  \
    opnd_create_reg(DR_REG_R6),  opnd_create_reg(DR_REG_R7),  \
    opnd_create_reg(DR_REG_R8),  opnd_create_reg(DR_REG_R9),  \
    opnd_create_reg(DR_REG_R10), opnd_create_reg(DR_REG_R11), \
    opnd_create_reg(DR_REG_R12), opnd_create_reg(DR_REG_R13), \
    DR_REG_LIST_TAIL

/* Append instructions to restore gpr on fcache enter, to be executed
 * right before jump to fcache target.
 * - dcontext is in REG_DCXT
 * - DR's tls base is in dr_reg_stolen
 * - all other registers can be used as scratch, and we are using R0.
 */
void
append_restore_gpr(dcontext_t *dcontext, instrlist_t *ilist, bool absolute)
{
    /* FIXME i#1573: NYI on ARM with SELFPROT_DCONTEXT */
    ASSERT_NOT_IMPLEMENTED(!TEST(SELFPROT_DCONTEXT, dynamo_options.protect_mask));
    ASSERT(dr_reg_stolen != SCRATCH_REG0);
    /* store stolen reg value into TLS slot */
    APP(ilist, RESTORE_FROM_DC(dcontext, SCRATCH_REG0, REG_OFFSET(dr_reg_stolen)));
    APP(ilist, SAVE_TO_TLS(dcontext, SCRATCH_REG0, TLS_REG_STOLEN_SLOT));

    /* Save DR's tls base into mcontext for the ldm later.
     * XXX: we just want to remove the stolen reg from the reg list,
     * so instead of having this extra store, we should provide a help
     * function to create the reg list.
     */
    APP(ilist, SAVE_TO_DC(dcontext, dr_reg_stolen, REG_OFFSET(dr_reg_stolen)));
    /* prepare for ldm */
    APP(ilist, INSTR_CREATE_add(dcontext,
                                opnd_create_reg(REG_DCXT),
                                opnd_create_reg(REG_DCXT),
                                OPND_CREATE_INT(R0_OFFSET)));
    /* load all regs from mcontext */
    APP(ilist, INSTR_CREATE_ldm(dcontext,
                                OPND_CREATE_MEMLIST(REG_DCXT),
                                DR_REG_LIST_LENGTH,
                                DR_REG_LIST));
}

/* helper functions for append_fcache_return_common */

/* Append instructions to save gpr on fcache return, called after
 * append_fcache_return_prologue.
 * Assuming the execution comes from an exit stub,
 * and dcontext base is held in REG_DCXT.
 * - store all registers into dcontext's mcontext
 * - restore REG_DCXT app value from TLS slot to mcontext
 * - restore dr_reg_stolen app value from TLS slot to mcontext
 */
void
append_save_gpr(dcontext_t *dcontext, instrlist_t *ilist, bool ibl_end, bool absolute,
                generated_code_t *code, linkstub_t *linkstub, bool coarse_info)
{
    ASSERT_NOT_IMPLEMENTED(!absolute &&
                           !TEST(SELFPROT_DCONTEXT, dynamo_options.protect_mask));
    APP(ilist, INSTR_CREATE_add(dcontext,
                                opnd_create_reg(REG_DCXT),
                                opnd_create_reg(REG_DCXT),
                                OPND_CREATE_INT(R0_OFFSET)));
    /* save current register state to dcontext's mcontext, some are in TLS */
    APP(ilist, INSTR_CREATE_stm(dcontext,
                                OPND_CREATE_MEMLIST(REG_DCXT),
                                DR_REG_LIST_LENGTH,
                                DR_REG_LIST));

    /* app's r0 was spilled to DIRECT_STUB_SPILL_SLOT by exit stub */
    APP(ilist, RESTORE_FROM_TLS(dcontext, SCRATCH_REG1, DIRECT_STUB_SPILL_SLOT));
    if (linkstub != NULL) {
        /* FIXME i#1551: NYI for coarse-grain stub */
        ASSERT_NOT_IMPLEMENTED(false);
    } else {
        APP(ilist, SAVE_TO_DC(dcontext, SCRATCH_REG1, R0_OFFSET));
    }
    /* REG_DCXT's app value is stored in DCONTEXT_BASE_SPILL_SLOT by
     * append_prepare_fcache_return, copy it to mcontext.
     */
    APP(ilist, RESTORE_FROM_TLS(dcontext, SCRATCH_REG1, DCONTEXT_BASE_SPILL_SLOT));
    APP(ilist, SAVE_TO_DC(dcontext, SCRATCH_REG1, REG_DCXT_OFFS));
    /* dr_reg_stolen's app value is always stored in the TLS spill slot,
     * and we restore its value back to mcontext on fcache return.
     */
    APP(ilist, RESTORE_FROM_TLS(dcontext, SCRATCH_REG1, TLS_REG_STOLEN_SLOT));
    APP(ilist, SAVE_TO_DC(dcontext, SCRATCH_REG1, REG_OFFSET(dr_reg_stolen)));
    /* steal app's TLS slot for DR's TLS base */
    /* load app's TLS base into r1 and app's tls slot value into r2 */
    append_load_app_tls_slot(dcontext, ilist, SCRATCH_REG1, SCRATCH_REG2);
    /* save r2 into os_tls->app_tls_swap */
    APP(ilist, SAVE_TO_TLS(dcontext, SCRATCH_REG2, os_get_app_tls_swap_offset()));
    /* save dr_reg_stolen into app's tls slot */
    APP(ilist, XINST_CREATE_store(dcontext,
                                  OPND_CREATE_MEMPTR(SCRATCH_REG1,
                                                     APP_TLS_SWAP_SLOT),
                                  opnd_create_reg(dr_reg_stolen)));
    /* FIXME i#1551: how should we handle register pc? */
}

void
append_save_simd_reg(dcontext_t *dcontext, instrlist_t *ilist, bool absolute)
{
    /* s16–s31 (d8–d15, q4–q7) are callee save */
    /* FIXME i#1551: NYI on ARM */
}

void
append_save_clear_xflags(dcontext_t *dcontext, instrlist_t *ilist, bool absolute)
{
    APP(ilist, INSTR_CREATE_mrs(dcontext,
                                opnd_create_reg(SCRATCH_REG0),
                                opnd_create_reg(DR_REG_CPSR)));
    APP(ilist, SAVE_TO_DC(dcontext, SCRATCH_REG0, XFLAGS_OFFSET));
    /* There is no DF on ARM, so we do not need clear xflags. */
}

bool
append_call_enter_dr_hook(dcontext_t *dcontext, instrlist_t *ilist,
                          bool ibl_end, bool absolute)
{
    /* i#1551: DR_HOOK is not supported on ARM */
    ASSERT_NOT_IMPLEMENTED(EXIT_DR_HOOK == NULL);
    return false;
}

void
insert_save_eflags(dcontext_t *dcontext, instrlist_t *ilist, instr_t *where,
                   uint flags, bool tls, bool absolute _IF_X64(bool x86_to_x64_ibl_opt))
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}

void
insert_restore_eflags(dcontext_t *dcontext, instrlist_t *ilist, instr_t *where,
                      uint flags, bool tls, bool absolute
                      _IF_X64(bool x86_to_x64_ibl_opt))
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}


/* create the inlined ibl exit stub template */
byte *
emit_inline_ibl_stub(dcontext_t *dcontext, byte *pc,
                     ibl_code_t *ibl_code, bool target_trace_table)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return NULL;
}

byte *
emit_indirect_branch_lookup(dcontext_t *dcontext, generated_code_t *code, byte *pc,
                            byte *fcache_return_pc,
                            bool target_trace_table,
                            bool inline_ibl_head,
                            ibl_code_t *ibl_code /* IN/OUT */)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return NULL;
}

bool
is_jmp_rel32(byte *code_buf, app_pc app_loc, app_pc *jmp_target /* OUT */)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return false;
}


bool
is_jmp_rel8(byte *code_buf, app_pc app_loc, app_pc *jmp_target /* OUT */)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return false;
}
