/* ******************************************************************************
 * Copyright (c) 2014-2015 Google, Inc.  All rights reserved.
 * ******************************************************************************/

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
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Google, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* file "mangle.c" */

#include "../globals.h"
#include "arch.h"
#include "instr_create.h"
#include "instrument.h" /* instrlist_meta_preinsert */

/* Make code more readable by shortening long lines.
 * We mark everything we add as non-app instr.
 */
#define POST instrlist_meta_postinsert
#define PRE  instrlist_meta_preinsert

/* For ARM, we always use TLS and never use hardcoded dcontext
 * (xref USE_SHARED_GENCODE_ALWAYS() and -private_ib_in_tls).
 * Thus we use instr_create_{save_to,restore_from}_tls() directly.
 */

byte *
remangle_short_rewrite(dcontext_t *dcontext,
                       instr_t *instr, byte *pc, app_pc target)
{
    /* FIXME i#1551: refactor the caller and make this routine x86-only. */
    ASSERT_NOT_REACHED();
    return NULL;
}

void
convert_to_near_rel(dcontext_t *dcontext, instr_t *instr)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}
/***************************************************************************/
#if !defined(STANDALONE_DECODER)

void
insert_clear_eflags(dcontext_t *dcontext, clean_call_info_t *cci,
                    instrlist_t *ilist, instr_t *instr)
{
    /* clear eflags for callee's usage */
    if (cci == NULL || !cci->skip_clear_eflags) {
        if (!dynamo_options.cleancall_ignore_eflags) {
            /* FIXME i#1551: NYI on ARM */
            ASSERT_NOT_IMPLEMENTED(false);
        }
    }
}

/* Pushes not only the GPRs but also simd regs, xip, and xflags, in
 * priv_mcontext_t order.
 * The current stack pointer alignment should be passed.  Use 1 if
 * unknown (NOT 0).
 * Returns the amount of data pushed.  Does NOT fix up the xsp value pushed
 * to be the value prior to any pushes for x64 as no caller needs that
 * currently (they all build a priv_mcontext_t and have to do further xsp
 * fixups anyway).
 */
uint
insert_push_all_registers(dcontext_t *dcontext, clean_call_info_t *cci,
                          instrlist_t *ilist, instr_t *instr,
                          uint alignment, instr_t *push_pc)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return 0;
}

/* User should pass the alignment from insert_push_all_registers: i.e., the
 * alignment at the end of all the popping, not the alignment prior to
 * the popping.
 */
void
insert_pop_all_registers(dcontext_t *dcontext, clean_call_info_t *cci,
                         instrlist_t *ilist, instr_t *instr,
                         uint alignment)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}

reg_id_t
shrink_reg_for_param(reg_id_t regular, opnd_t arg)
{
#ifdef X64
    /* FIXME i#1551: NYI on AArch64 */
    ASSERT_NOT_IMPLEMENTED(false);
#endif
    return regular;
}

uint
insert_parameter_preparation(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                             bool clean_call, uint num_args, opnd_t *args)
{
    uint i;
    instr_t *mark = INSTR_CREATE_label(dcontext);
    PRE(ilist, instr, mark);

    ASSERT(num_args == 0 || args != NULL);
    /* FIXME i#1551: we only support limited number of args for now. */
    ASSERT_NOT_IMPLEMENTED(num_args <= NUM_REGPARM);
    for (i = 0; i < num_args; i++) {
        /* FIXME i#1551: we only implement naive parameter preparation,
         * where args are all regs and do not conflict with param regs.
         */
        ASSERT_NOT_IMPLEMENTED(opnd_is_reg(args[i]) &&
                               opnd_get_size(args[i]) == OPSZ_PTR);
        DODEBUG({
            uint j;
            /* assume no reg used by arg conflicts with regparms */
            for (j = 0; j < i; j++)
                ASSERT_NOT_IMPLEMENTED(!opnd_uses_reg(args[j], regparms[i]));
        });
        if (regparms[i] != opnd_get_reg(args[i])) {
            POST(ilist, mark, XINST_CREATE_move(dcontext,
                                                opnd_create_reg(regparms[i]),
                                                args[i]));
        }
    }
    return 0;
}

bool
insert_reachable_cti(dcontext_t *dcontext, instrlist_t *ilist, instr_t *where,
                     byte *encode_pc, byte *target, bool jmp, bool precise,
                     reg_id_t scratch, instr_t **inlined_tgt_instr)
{
    /* load target into scratch register */
    insert_mov_immed_ptrsz(dcontext, (ptr_int_t)target,
                           opnd_create_reg(scratch), ilist, where, NULL, NULL);
    /* mov target from scratch register to pc */
    PRE(ilist, where, INSTR_CREATE_mov(dcontext,
                                       opnd_create_reg(DR_REG_PC),
                                       opnd_create_reg(scratch)));
    return true /* an ind branch */;
}

/*###########################################################################
 *###########################################################################
 *
 *   M A N G L I N G   R O U T I N E S
 */

void
insert_mov_immed_arch(dcontext_t *dcontext, instr_t *src_inst, byte *encode_estimate,
                      ptr_int_t val, opnd_t dst,
                      instrlist_t *ilist, instr_t *instr,
                      instr_t **first, instr_t **second)
{
    instr_t *mov1, *mov2;
    ASSERT(opnd_is_reg(dst));
    /* FIXME i#1551: we may handle Thumb and ARM mode differently.
     * Now we assume ARM mode only.
     */
    /* MVN writes the bitwise inverse of an immediate value to the dst register */
    if (~val >= 0 && ~val <= 0xfff) {
        mov1 = INSTR_CREATE_mvn(dcontext, dst, OPND_CREATE_INT(~val));
        PRE(ilist, instr, mov1);
        mov2 = NULL;
    } else {
        /* To use INT16 here and pass the size checks in opnd_create_immed_int
         * we'd have to add UINT16 (or sign-extend the bottom half again):
         * simpler to use INT, and our general ARM philosophy is to use INT and
         * ignore immed sizes at instr creation time (only at encode time do we
         * check them).
         */
        mov1 = INSTR_CREATE_movw(dcontext, dst, OPND_CREATE_INT(val & 0xffff));
        PRE(ilist, instr, mov1);
        val = (val >> 16) & 0xffff;
        if (val == 0) {
            /* movw zero-extends so we're done */
            mov2 = NULL;
        } else {
            /* XXX: movw expects reg size to be OPSZ_PTR but
             * movt expects reg size to be OPSZ_PTR_HALF.
             */
            opnd_set_size(&dst, OPSZ_PTR_HALF);
            mov2 = INSTR_CREATE_movt(dcontext, dst, OPND_CREATE_INT(val));
            PRE(ilist, instr, mov2);
        }
    }
    if (first != NULL)
        *first = mov1;
    if (second != NULL)
        *second = mov2;
}

void
insert_push_immed_arch(dcontext_t *dcontext, instr_t *src_inst, byte *encode_estimate,
                       ptr_int_t val, instrlist_t *ilist, instr_t *instr,
                       instr_t **first, instr_t **second)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}

void
mangle_syscall_arch(dcontext_t *dcontext, instrlist_t *ilist, uint flags,
                    instr_t *instr, instr_t *next_instr)
{
    /* Shared routine already checked method, handled INSTR_NI_SYSCALL*,
     * and inserted the signal barrier and non-auto-restart nop.
     * If we get here, we're dealing with an ignorable syscall.
     */

    /* We assume we do not have to restore the stolen reg value, as it's
     * r8+ and so there will be no syscall arg or number stored in it.
     * We assume the kernel won't read it.
     */
    ASSERT(DR_REG_STOLEN_MIN > DR_REG_SYSNUM);

    /* We do need to save the stolen reg if it is caller-saved.
     * For now we assume that the kernel honors the calling convention
     * and won't clobber callee-saved regs.
     */
    if (dr_reg_stolen != DR_REG_R10 && dr_reg_stolen != DR_REG_R11) {
        PRE(ilist, instr,
            instr_create_save_to_tls(dcontext, DR_REG_R10, TLS_REG0_SLOT));
        PRE(ilist, instr,
            XINST_CREATE_move(dcontext, opnd_create_reg(DR_REG_R10),
                              opnd_create_reg(dr_reg_stolen)));
        /* Post-syscall: */
        PRE(ilist, next_instr,
            XINST_CREATE_move(dcontext, opnd_create_reg(dr_reg_stolen),
                              opnd_create_reg(DR_REG_R10)));
        PRE(ilist, next_instr,
            instr_create_restore_from_tls(dcontext, DR_REG_R10, TLS_REG0_SLOT));
    }
}

#ifdef UNIX
void
mangle_clone_code(dcontext_t *dcontext, byte *pc, bool skip)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}

bool
mangle_syscall_code(dcontext_t *dcontext, fragment_t *f, byte *pc, bool skip)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return false;
}

void
mangle_insert_clone_code(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                         bool skip _IF_X64(gencode_mode_t mode))
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}
#endif /* UNIX */

void
mangle_interrupt(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                 instr_t *next_instr)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
}

instr_t *
mangle_direct_call(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                   instr_t *next_instr, bool mangle_calls, uint flags)
{
    /* Strategy: replace OP_bl with 2-step mov immed into lr + OP_b */
    /* FIXME i#1551: handle predication where instr is skipped */
    ptr_uint_t retaddr;
    uint opc = instr_get_opcode(instr);
    ASSERT(opc == OP_bl || opc == OP_blx);
    retaddr = get_call_return_address(dcontext, ilist, instr);
    insert_mov_immed_ptrsz(dcontext, (ptr_int_t)retaddr, opnd_create_reg(DR_REG_LR),
                           ilist, instr, NULL, NULL);
    if (opc == OP_bl) {
        /* remove OP_bl (final added jmp already targets the callee) */
        instrlist_remove(ilist, instr);
        instr_destroy(dcontext, instr);
    } else {
        /* Unfortunately while there is OP_blx with an immed, OP_bx requires
         * indirection through a register.  We thus need to swap modes separately,
         * but our ISA doesn't support mixing modes in one fragment, making
         * a local "blx next_instr" not easy.
         */
        /* FIXME i#1551: handling OP_blx NYI on ARM */
        ASSERT_NOT_IMPLEMENTED(false);
    }
    return next_instr;
}

void
mangle_indirect_call(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                     instr_t *next_instr, bool mangle_calls, uint flags)
{
    ptr_uint_t retaddr;
    PRE(ilist, instr,
        instr_create_save_to_tls(dcontext, DR_REG_R2, TLS_REG2_SLOT));
    if (!opnd_same(instr_get_target(instr), opnd_create_reg(DR_REG_R2))) {
        PRE(ilist, instr,
            XINST_CREATE_move(dcontext, opnd_create_reg(DR_REG_R2),
                              instr_get_target(instr)));
    }
    retaddr = get_call_return_address(dcontext, ilist, instr);
    insert_mov_immed_ptrsz(dcontext, (ptr_int_t)retaddr, opnd_create_reg(DR_REG_LR),
                           ilist, instr, NULL, NULL);
    /* remove OP_blx_ind (final added jmp already targets the callee) */
    instrlist_remove(ilist, instr);
    instr_destroy(dcontext, instr);
    /* FIXME i#1551: handle mode switch */
    /* FIXME i#1551: handle predication where instr is skipped */
}

void
mangle_return(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
              instr_t *next_instr, uint flags)
{
    /* The mangling is identical */
    mangle_indirect_jump(dcontext, ilist, instr, next_instr, flags);
}

void
mangle_indirect_jump(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                     instr_t *next_instr, uint flags)
{
    int opc = instr_get_opcode(instr);
    PRE(ilist, instr,
        instr_create_save_to_tls(dcontext, DR_REG_R2, TLS_REG2_SLOT));
    if (instr_writes_gpr_list(instr)) {
        /* The load into pc will always be last (r15) so we remove it and add
         * a single-load instr into r2, with the same inc/dec and writeback.
         */
        uint i;
        bool found_pc;
        opnd_t memop = instr_get_src(instr, 0);
        instr_t *single;
        ASSERT(opnd_is_base_disp(memop));
        opnd_set_size(&memop, OPSZ_VAR_REGLIST);
        instr_set_src(instr, 0, memop);
        single = instr_clone(dcontext, instr);
        for (i = 0; i < instr_num_dsts(instr); i++) {
            ASSERT(opnd_is_reg(instr_get_dst(instr, i)));
            if (opnd_get_reg(instr_get_dst(instr, i)) == DR_REG_PC) {
                found_pc = true;
                instr_remove_dsts(dcontext, instr, i, i+1);
                break;
            }
        }
        ASSERT(found_pc);
        instr_remove_dsts(dcontext, single, 0, i); /* leave pc => r2 */
        instr_set_dst(single, 0, opnd_create_reg(DR_REG_R2));
        PRE(ilist, next_instr, single);
    } else if (opc == OP_bx || opc ==  OP_bxj) {
        PRE(ilist, instr,
            XINST_CREATE_move(dcontext, opnd_create_reg(DR_REG_R2),
                              instr_get_target(instr)));
        /* remove the bx */
        instrlist_remove(ilist, instr);
        instr_destroy(dcontext, instr);
    } else if (opc == OP_rfe || opc == OP_rfedb || opc == OP_rfeda || opc == OP_rfeib ||
               opc == OP_eret || opc == OP_tbb || opc == OP_tbh) {
        /* FIXME i#1551: NYI on ARM */
        ASSERT_NOT_IMPLEMENTED(false);
        /* FIXME i#1551: we should add add dr_insert_get_mbr_branch_target() for
         * use internally and by clients, as OP_tb{b,h} break our assumptions
         * of the target simply being stored as an absolute address at
         * the memory operand location.  Instead, these are pc-relative:
         * pc += memval*2.
         */
    } else {
        /* Explicitly writes just the pc */
        uint i;
        bool found_pc;
        /* XXX: can anything (non-OP_ldm) have r2 as an additional dst? */
        ASSERT_NOT_IMPLEMENTED(!instr_writes_to_reg(instr, DR_REG_R2,
                                                    DR_QUERY_INCLUDE_ALL));
        for (i = 0; i < instr_num_dsts(instr); i++) {
            if (opnd_is_reg(instr_get_dst(instr, i)) &&
                opnd_get_reg(instr_get_dst(instr, i)) == DR_REG_PC) {
                found_pc = true;
                instr_set_dst(instr, i, opnd_create_reg(DR_REG_R2));
                break;
            }
        }
        ASSERT(found_pc);
    }
    /* FIXME i#1551: handle mode switch */
    /* FIXME i#1551: handle predication where instr is skipped
     * For ind branch: need to add cbr -- will emit do right thing?
     * For pc read or rip-rel: b/c post-app-instr restore can't
     * rely on pred flags (app instr could change them), just
     * have all the mangling be non-pred?  No hurt, right?
     * Though may as well have the mov-immed for mangle_rel_addr
     * be predicated.
     */
}

/* Local single-instr-window scratch reg picker */
static reg_id_t
pick_scratch_reg(instr_t *instr, ushort *scratch_slot OUT, bool *should_restore OUT)
{
    reg_id_t reg;
    ushort slot;
    *should_restore = true;
    for (reg  = SCRATCH_REG0, slot = TLS_REG0_SLOT;
         reg <= SCRATCH_REG5; reg++, slot++) {
        if (!instr_uses_reg(instr, reg))
            break;
    }
    if (reg > SCRATCH_REG5) {
        /* Likely OP_ldm.  We'll have to pick a dead reg (non-ideal b/c a fault
         * could come in: i#400).
         */
        for (reg  = SCRATCH_REG0, slot = TLS_REG0_SLOT;
             reg <= SCRATCH_REG5; reg++, slot++) {
            if (!instr_reads_from_reg(instr, reg, DR_QUERY_INCLUDE_ALL))
                break;
        }
        *should_restore = false;
    }
    ASSERT(reg <= SCRATCH_REG5); /* No instr reads and writes all regs */
    if (scratch_slot != NULL)
        *scratch_slot = slot;
    return reg;
}

bool
mangle_rel_addr(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                instr_t *next_instr)
{
    uint opc = instr_get_opcode(instr);
    /* Compute the value of r15==pc for orig app instr */
    ptr_int_t r15 = (ptr_int_t)instr_get_raw_bits(instr) +
        decode_cur_pc_offs(dr_get_isa_mode(dcontext));
    opnd_t reg_op, mem_op;
    ASSERT(instr_has_rel_addr_reference(instr));

    if (opc == OP_ldr || opc == OP_str) {
        ushort slot;
        bool should_restore;
        reg_id_t reg = pick_scratch_reg(instr, &slot, &should_restore);
        if (opc == OP_ldr) {
            reg_op = instr_get_dst(instr, 0);
            mem_op = instr_get_src(instr, 0);
        } else {
            reg_op = instr_get_src(instr, 0);
            mem_op = instr_get_dst(instr, 0);
        }
        ASSERT(opnd_is_reg(reg_op) && opnd_is_base_disp(mem_op));
        ASSERT_NOT_IMPLEMENTED(!instr_is_cti(instr));
        PRE(ilist, instr, instr_create_save_to_tls(dcontext, reg, slot));
        insert_mov_immed_ptrsz(dcontext, r15, opnd_create_reg(reg),
                               ilist, instr, NULL, NULL);
        if (opc == OP_ldr) {
            instr_set_src(instr, 0,
                          opnd_create_base_disp(reg, REG_NULL, 0,
                                                opnd_get_disp(mem_op),
                                                opnd_get_size(mem_op)));
        } else {
            instr_set_dst(instr, 0,
                          opnd_create_base_disp(reg, REG_NULL, 0,
                                                opnd_get_disp(mem_op),
                                                opnd_get_size(mem_op)));
        }
        if (should_restore)
            PRE(ilist, next_instr, instr_create_restore_from_tls(dcontext, reg, slot));
    } else {
        /* FIXME i#1551: NYI on ARM */
        ASSERT_NOT_IMPLEMENTED(false);
    }
    return false;
}

void
mangle_pc_read(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                instr_t *next_instr)
{
    ushort slot;
    bool should_restore;
    reg_id_t reg = pick_scratch_reg(instr, &slot, &should_restore);
    ptr_int_t app_r15 = (ptr_int_t)instr_get_raw_bits(instr) +
        decode_cur_pc_offs(dr_get_isa_mode(dcontext));
    int i;
    PRE(ilist, instr, instr_create_save_to_tls(dcontext, reg, slot));
    insert_mov_immed_ptrsz(dcontext, app_r15, opnd_create_reg(reg),
                           ilist, instr, NULL, NULL);
    for (i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_uses_reg(instr_get_src(instr, i), DR_REG_PC)) {
            /* A memref should have been mangled already in mangle_rel_addr */
            ASSERT(opnd_is_reg(instr_get_src(instr, i)));
            instr_set_src(instr, i, opnd_create_reg(reg));
        }
    }
    if (should_restore)
        PRE(ilist, next_instr, instr_create_restore_from_tls(dcontext, reg, slot));
}

void
float_pc_update(dcontext_t *dcontext)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_REACHED();
}

/* END OF CONTROL-FLOW MANGLING ROUTINES
 *###########################################################################
 *###########################################################################
 */

#endif /* !STANDALONE_DECODER */
/***************************************************************************/
