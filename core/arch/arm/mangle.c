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
#include "disassemble.h"

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
    uint mangled_sz = CTI_SHORT_REWRITE_LENGTH;
    uint raw_jmp;
    ASSERT(instr_is_cti_short_rewrite(instr, pc));
    if (target == NULL)
        target = decode_raw_jmp_target(dcontext, pc + CTI_SHORT_REWRITE_B_OFFS);
    instr_set_target(instr, opnd_create_pc(target));
    instr_allocate_raw_bits(dcontext, instr, mangled_sz);
    instr_set_raw_bytes(instr, pc, mangled_sz);
    encode_raw_jmp(dr_get_isa_mode(dcontext), target, (byte *)&raw_jmp,
                   pc + CTI_SHORT_REWRITE_B_OFFS);
    instr_set_raw_word(instr, CTI_SHORT_REWRITE_B_OFFS, raw_jmp);
    instr_set_operands_valid(instr, true);
    return (pc+mangled_sz);
}

instr_t *
convert_to_near_rel_arch(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr)
{
    int opcode = instr_get_opcode(instr);
    if (opcode == OP_b_short) {
        instr_set_opcode(instr, OP_b);
        return instr;
    } else if (opcode == OP_cbz || opcode == OP_cbnz) {
        /* While for non-trace-mode we could get by w/o converting,
         * as we use local stubs with a far-away link-through-stub
         * soln needed even for regular branches and thus these would
         * reach the stub, they won't reach for traces.
         * Thus we mirror what x86 does for jecxz:
         *       cbz foo
         *  =>
         *       cbnz fall
         *       jmp foo
         *  fall:
         *
         * The fact that we invert the cbr ends up requiring extra logic
         * in linkstub_cbr_disambiguate().
        */
        app_pc target = NULL;
        uint mangled_sz, offs, raw_jmp;
        reg_id_t src_reg;

        if (ilist != NULL) {
            /* PR 266292: for meta instrs, insert separate instrs */
            opnd_t tgt = instr_get_target(instr);
            instr_t *fall = INSTR_CREATE_label(dcontext);
            instr_t *jmp = INSTR_CREATE_b(dcontext, tgt);
            ASSERT(instr_is_meta(instr));
            /* reverse order */
            instrlist_meta_postinsert(ilist, instr, fall);
            instrlist_meta_postinsert(ilist, instr, jmp);
            instrlist_meta_postinsert(ilist, instr, instr);
            instr_set_target(instr, opnd_create_instr(fall));
            instr_invert_cbr(instr);
            return jmp; /* API specifies we return the long-reach cti */
        }

        if (opnd_is_near_pc(instr_get_target(instr)))
            target = opnd_get_pc(instr_get_target(instr));
        else if (opnd_is_near_instr(instr_get_target(instr))) {
            instr_t *tgt = opnd_get_instr(instr_get_target(instr));
            /* assumption: target's translation or raw bits are set properly */
            target = instr_get_translation(tgt);
            if (target == NULL && instr_raw_bits_valid(tgt))
                target = instr_get_raw_bits(tgt);
            ASSERT(target != NULL);
        } else
            ASSERT_NOT_REACHED();

        /* PR 251646: cti_short_rewrite: target is in src0, so operands are
         * valid, but raw bits must also be valid, since they hide the multiple
         * instrs.  For x64, it is marked for re-relativization, but it's
         * special since the target must be obtained from src0 and not
         * from the raw bits (since that might not reach).
         */
        /* query IR before we set raw bits */
        ASSERT(opnd_is_reg(instr_get_src(instr, 1)));
        src_reg = opnd_get_reg(instr_get_src(instr, 1));
        /* need 6 bytes */
        mangled_sz = CTI_SHORT_REWRITE_LENGTH;
        instr_allocate_raw_bits(dcontext, instr, mangled_sz);
        offs = 0;
        /* first 2 bytes: cbz or cbnz to "cur pc" + 2 which means immed is 1 */
        instr_set_raw_byte(instr, offs, 0x08 | (src_reg - DR_REG_R0));
        offs++;
        instr_set_raw_byte(instr, offs, (opcode == OP_cbz) ? CBNZ_BYTE_A : CBZ_BYTE_A);
        offs++;
        /* next 4 bytes: b to target */
        ASSERT(offs == CTI_SHORT_REWRITE_B_OFFS);
        encode_raw_jmp(dr_get_isa_mode(dcontext), target, (byte *)&raw_jmp,
                       instr->bytes + offs);
        instr_set_raw_word(instr, offs, raw_jmp);
        offs += sizeof(int);
        ASSERT(offs == mangled_sz);
        LOG(THREAD, LOG_INTERP, 2, "convert_to_near_rel: cbz/cbnz opcode\n");
        /* original target operand is still valid */
        instr_set_operands_valid(instr, true);
        return instr;
    }
    ASSERT_NOT_REACHED();
    return instr;
}

/***************************************************************************/
#if !defined(STANDALONE_DECODER)

void
insert_clear_eflags(dcontext_t *dcontext, clean_call_info_t *cci,
                    instrlist_t *ilist, instr_t *instr)
{
    /* There is no DF on ARM, so we do not need clear xflags. */
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
                          uint alignment, opnd_t push_pc)
{
    uint dstack_offs = 0;
    if (cci == NULL)
        cci = &default_clean_call_info;
    if (cci->preserve_mcontext || cci->num_xmms_skip != NUM_XMM_REGS) {
        /* FIXME i#1551: once we add skipping of regs, need to keep shape here */
    }
    /* FIXME i#1551: once we have cci->num_xmms_skip, skip this if possible */
    /* vstmdb always does writeback */
    PRE(ilist, instr, INSTR_CREATE_vstmdb(dcontext, OPND_CREATE_MEMLIST(DR_REG_SP),
                                          SIMD_REG_LIST_LEN, SIMD_REG_LIST_16_31));
    PRE(ilist, instr, INSTR_CREATE_vstmdb(dcontext, OPND_CREATE_MEMLIST(DR_REG_SP),
                                          SIMD_REG_LIST_LEN, SIMD_REG_LIST_0_15));
    dstack_offs += NUM_SIMD_SLOTS*sizeof(dr_simd_t);
    /* pc and aflags */
    if (!cci->skip_save_aflags) {
        reg_id_t scratch = DR_REG_R0;
        uint slot = TLS_REG0_SLOT;
        if (opnd_is_reg(push_pc) && opnd_get_reg(push_pc) == scratch) {
            scratch = DR_REG_R1;
            slot = TLS_REG1_SLOT;
        }
        /* XXX: actually, r0 was just used as scratch for swapping stack
         * via dcontext, so an optimization opportunity exists to avoid
         * that restore and the re-spill here.
         */
        PRE(ilist, instr, instr_create_save_to_tls(dcontext, scratch, slot));
        PRE(ilist, instr, INSTR_CREATE_mrs(dcontext, opnd_create_reg(scratch),
                                           opnd_create_reg(DR_REG_CPSR)));
        PRE(ilist, instr, INSTR_CREATE_push(dcontext, opnd_create_reg(scratch)));
        dstack_offs += XSP_SZ;
        if (opnd_is_immed_int(push_pc)) {
            PRE(ilist, instr, XINST_CREATE_load_int(dcontext, opnd_create_reg(scratch),
                                                    push_pc));
            PRE(ilist, instr, INSTR_CREATE_push(dcontext, opnd_create_reg(scratch)));
        } else {
            ASSERT(opnd_is_reg(push_pc));
            PRE(ilist, instr, INSTR_CREATE_push(dcontext, push_pc));
        }
        PRE(ilist, instr, instr_create_restore_from_tls(dcontext, scratch, slot));
        dstack_offs += XSP_SZ;
    }

#ifdef X64
    /* FIXME i#1569: NYI on AArch64 */
    ASSERT_NOT_IMPLEMENTED(false);
#else
    /* We rely on dr_get_mcontext_priv() to fill in the app's stolen reg value
     * and sp value.
     */
    if (dr_get_isa_mode(dcontext) == DR_ISA_ARM_THUMB) {
        /* We can't use sp with stm */
        PRE(ilist, instr, INSTR_CREATE_push(dcontext, opnd_create_reg(DR_REG_LR)));
        /* We can't push sp w/ writeback, and in fact dr_get_mcontext() gets
         * sp from the stack swap so we can leave this empty.
         */
        PRE(ilist, instr, XINST_CREATE_sub(dcontext, opnd_create_reg(DR_REG_SP),
                                           OPND_CREATE_INT8(XSP_SZ)));
        PRE(ilist, instr, INSTR_CREATE_stmdb_wb(dcontext, OPND_CREATE_MEMLIST(DR_REG_SP),
                                                DR_REG_LIST_LENGTH_T32, DR_REG_LIST_T32));
    } else {
        PRE(ilist, instr,
            INSTR_CREATE_stmdb_wb(dcontext, OPND_CREATE_MEMLIST(DR_REG_SP),
                                  DR_REG_LIST_LENGTH_ARM, DR_REG_LIST_ARM));
    }
    dstack_offs += 15 * XSP_SZ;
#endif
    ASSERT(cci->skip_save_aflags   ||
           cci->num_xmms_skip != 0 ||
           cci->num_regs_skip != 0 ||
           dstack_offs == (uint)get_clean_call_switch_stack_size());
    return dstack_offs;
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
    if (cci == NULL)
        cci = &default_clean_call_info;
#ifdef X64
    /* FIXME i#1569: NYI on AArch64 */
    ASSERT_NOT_IMPLEMENTED(false);
#else
    /* We rely on dr_set_mcontext_priv() to set the app's stolen reg value,
     * and the stack swap to set the sp value: we assume the stolen reg on
     * the stack still has our TLS base in it.
     */
    /* We can't use sp with ldm for Thumb, and we don't want to write sp for ARM. */
    PRE(ilist, instr, INSTR_CREATE_ldm_wb(dcontext, OPND_CREATE_MEMLIST(DR_REG_SP),
                                          DR_REG_LIST_LENGTH_T32, DR_REG_LIST_T32));
    /* We don't want the sp value */
    PRE(ilist, instr, XINST_CREATE_add(dcontext, opnd_create_reg(DR_REG_SP),
                                       OPND_CREATE_INT8(XSP_SZ)));
    PRE(ilist, instr, INSTR_CREATE_pop(dcontext, opnd_create_reg(DR_REG_LR)));
#endif

    /* pc and aflags */
    if (!cci->skip_save_aflags) {
        reg_id_t scratch = DR_REG_R0;
        uint slot = TLS_REG0_SLOT;
        /* just throw pc slot away */
        PRE(ilist, instr, XINST_CREATE_add(dcontext, opnd_create_reg(DR_REG_SP),
                                           OPND_CREATE_INT8(XSP_SZ)));
        PRE(ilist, instr, instr_create_save_to_tls(dcontext, scratch, slot));
        PRE(ilist, instr, INSTR_CREATE_pop(dcontext, opnd_create_reg(scratch)));
        PRE(ilist, instr, INSTR_CREATE_msr(dcontext, opnd_create_reg(DR_REG_CPSR),
                                           OPND_CREATE_INT_MSR_NZCVQG(),
                                           opnd_create_reg(scratch)));
        PRE(ilist, instr, instr_create_restore_from_tls(dcontext, scratch, slot));
    }
    /* FIXME i#1551: once we have cci->num_xmms_skip, skip this if possible */
    PRE(ilist, instr, INSTR_CREATE_vldm_wb(dcontext, OPND_CREATE_MEMLIST(DR_REG_SP),
                                           SIMD_REG_LIST_LEN, SIMD_REG_LIST_0_15));
    PRE(ilist, instr, INSTR_CREATE_vldm_wb(dcontext, OPND_CREATE_MEMLIST(DR_REG_SP),
                                           SIMD_REG_LIST_LEN, SIMD_REG_LIST_16_31));
}

reg_id_t
shrink_reg_for_param(reg_id_t regular, opnd_t arg)
{
#ifdef X64
    /* FIXME i#1569: NYI on AArch64 */
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
         * where args are all regs or immeds and do not conflict with param regs.
         */
        ASSERT_NOT_IMPLEMENTED((opnd_is_reg(args[i]) &&
                                opnd_get_size(args[i]) == OPSZ_PTR) ||
                               opnd_is_immed_int(args[i]));
        DODEBUG({
            uint j;
            /* assume no reg used by arg conflicts with regparms */
            for (j = 0; j < i; j++)
                ASSERT_NOT_IMPLEMENTED(!opnd_uses_reg(args[j], regparms[i]));
        });
        if (!opnd_is_reg(args[i]) || regparms[i] != opnd_get_reg(args[i])) {
            POST(ilist, mark, XINST_CREATE_move(dcontext,
                                                opnd_create_reg(regparms[i]),
                                                args[i]));
        }
    }
    return 0;
}

bool
insert_reachable_cti(dcontext_t *dcontext, instrlist_t *ilist, instr_t *where,
                     byte *encode_pc, byte *target, bool jmp, bool returns, bool precise,
                     reg_id_t scratch, instr_t **inlined_tgt_instr)
{
    instr_t *post_call = INSTR_CREATE_label(dcontext);
    /* load target into scratch register */
    insert_mov_immed_ptrsz(dcontext, (ptr_int_t)
                           PC_AS_JMP_TGT(dr_get_isa_mode(dcontext), target),
                           opnd_create_reg(scratch), ilist, where, NULL, NULL);
    /* even if a call and not a jmp, we can skip this if it doesn't return */
    if (!jmp && returns) {
        /* Trying to compute cur pc ourselves is fragile b/c for Thumb it
         * varies due to the back-align so we use an instr.
         */
        insert_mov_instr_addr(dcontext, post_call, encode_pc,
                              opnd_create_reg(DR_REG_LR), ilist, where, NULL, NULL);
    }
    /* mov target from scratch register to pc */
    PRE(ilist, where, INSTR_CREATE_mov(dcontext,
                                       opnd_create_reg(DR_REG_PC),
                                       opnd_create_reg(scratch)));
    PRE(ilist, where, post_call);
    return false /* an ind branch */;
}

int
insert_out_of_line_context_switch(dcontext_t *dcontext, instrlist_t *ilist,
                                  instr_t *instr, bool save)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return 0;
}

/*###########################################################################
 *###########################################################################
 *
 *   M A N G L I N G   R O U T I N E S
 */

/* If instr is inside an IT block, removes it from the block and
 * leaves it as an isolated (un-encodable) predicated instr, with any
 * other instrs from the same block made to be legal on both sides by
 * modifying and adding new OP_it instrs as necessary, which are marked
 * as app instrs.
 * Returns a new next_instr.
 */
static instr_t *
mangle_remove_from_it_block(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr)
{
    instr_t *prev, *it;
    uint prior, count;
    if (instr_get_isa_mode(instr) != DR_ISA_ARM_THUMB || !instr_is_predicated(instr))
        return instr_get_next(instr); /* nothing to do */
    for (prior = 0, prev = instr_get_prev(instr); prev != NULL;
         prior++, prev = instr_get_prev(prev)) {
        if (instr_get_opcode(prev) == OP_it)
            break;
        ASSERT(instr_is_predicated(instr));
    }
    ASSERT(prev != NULL);
    it = prev;
    count = instr_it_block_get_count(it);
    ASSERT(count > prior && count <= IT_BLOCK_MAX_INSTRS);
    if (prior > 0) {
        instrlist_preinsert
            (ilist, it, instr_it_block_create
             (dcontext, instr_it_block_get_pred(it, 0),
              prior > 1 ? instr_it_block_get_pred(it, 1) : DR_PRED_NONE,
              prior > 2 ? instr_it_block_get_pred(it, 2) : DR_PRED_NONE,
              DR_PRED_NONE));
        count -= prior;
    }
    count--; /* this instr */
    if (count > 0) {
        instrlist_postinsert
            (ilist, instr, instr_it_block_create
             (dcontext, instr_it_block_get_pred(it, prior + 1),
              count > 1 ? instr_it_block_get_pred(it, prior + 2) : DR_PRED_NONE,
              count > 2 ? instr_it_block_get_pred(it, prior + 3) : DR_PRED_NONE,
              DR_PRED_NONE));
    }
    /* It is now safe to remove the original OP_it instr */
    instrlist_remove(ilist, it);
    instr_destroy(dcontext, it);
    DOLOG(5, LOG_INTERP, {
        LOG(THREAD, LOG_INTERP, 4, "bb ilist after removing from IT block:\n");
        instrlist_disassemble(dcontext, NULL, ilist, THREAD);
    });
    return instr_get_next(instr);
}

/* Adds enough OP_it instrs to ensure that each predicated instr in [start, end)
 * (open-ended, so pass NULL to go to the final instr in ilist) is inside an IT
 * block and is thus legally encodable.  Marks the OP_it instrs as app instrs.
 */
static void
mangle_reinstate_it_blocks(dcontext_t *dcontext, instrlist_t *ilist, instr_t *start,
                           instr_t *end)
{
    instr_t *instr, *block_start = NULL;
    uint it_count = 0, block_count = 0;
    dr_pred_type_t block_pred[IT_BLOCK_MAX_INSTRS];
    if (dr_get_isa_mode(dcontext) != DR_ISA_ARM_THUMB)
        return; /* nothing to do */
    for (instr = start; instr != NULL && instr != end; instr = instr_get_next(instr)) {
        bool instr_predicated = instr_is_predicated(instr) &&
            /* Do not put OP_b exit cti into block: patch_branch can't handle */
            instr_get_opcode(instr) != OP_b;
        if (block_start != NULL) {
            ASSERT(block_count < IT_BLOCK_MAX_INSTRS);
            if (instr_predicated) {
                block_pred[block_count++] = instr_get_predicate(instr);
            }
            if (!instr_predicated || block_count == IT_BLOCK_MAX_INSTRS) {
                instrlist_preinsert
                    (ilist, block_start, instr_it_block_create
                     (dcontext, block_pred[0],
                      block_count > 1 ? block_pred[1] : DR_PRED_NONE,
                      block_count > 2 ? block_pred[2] : DR_PRED_NONE,
                      block_count > 3 ? block_pred[3] : DR_PRED_NONE));
                block_start = NULL;
            } else
                continue;
        }
        /* Skip existing IT blocks.
         * XXX: merge w/ adjacent blocks.
         */
        if (it_count > 0)
            it_count--;
        else if (instr_get_opcode(instr) == OP_it)
            it_count = instr_it_block_get_count(instr);
        else if (instr_predicated) {
            block_start = instr;
            block_pred[0] = instr_get_predicate(instr);
            block_count = 1;
        }
    }
    if (block_start != NULL) {
        instrlist_preinsert
            (ilist, block_start, instr_it_block_create
             (dcontext, block_pred[0],
              block_count > 1 ? block_pred[1] : DR_PRED_NONE,
              block_count > 2 ? block_pred[2] : DR_PRED_NONE,
              block_count > 3 ? block_pred[3] : DR_PRED_NONE));
    }
    DOLOG(5, LOG_INTERP, {
        LOG(THREAD, LOG_INTERP, 4, "bb ilist after reinstating IT blocks:\n");
        instrlist_disassemble(dcontext, NULL, ilist, THREAD);
    });
}

void
insert_mov_immed_arch(dcontext_t *dcontext, instr_t *src_inst, byte *encode_estimate,
                      ptr_int_t val, opnd_t dst,
                      instrlist_t *ilist, instr_t *instr,
                      instr_t **first, instr_t **second)
{
    instr_t *mov1, *mov2;
    if (src_inst != NULL)
        val = (ptr_int_t) encode_estimate;
    ASSERT(opnd_is_reg(dst));
    /* MVN writes the bitwise inverse of an immediate value to the dst register */
    /* XXX: we could check for larger tile/rotate immed patterns */
    if (src_inst == NULL && ~val >= 0 && ~val <= 0xff) {
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
        mov1 = INSTR_CREATE_movw(dcontext, dst,
                                 (src_inst == NULL) ?
                                 OPND_CREATE_INT(val & 0xffff) :
                                 opnd_create_instr_ex(src_inst, OPSZ_2, 0));
        PRE(ilist, instr, mov1);
        val = (val >> 16) & 0xffff;
        if (val == 0) {
            /* movw zero-extends so we're done */
            mov2 = NULL;
        } else {
            mov2 = INSTR_CREATE_movt(dcontext, dst,
                                     (src_inst == NULL) ?
                                     OPND_CREATE_INT(val) :
                                     opnd_create_instr_ex(src_inst, OPSZ_2, 16));
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

/* Adds a mov of the fall-through address into IBL_TARGET_REG, predicated
 * with the inverse of instr's predicate.
 * The caller must call mangle_reinstate_it_blocks() in Thumb mode afterward
 * in order to make for legal encodings.
 */
static void
mangle_add_predicated_fall_through(dcontext_t *dcontext, instrlist_t *ilist,
                                   instr_t *instr, instr_t *next_instr,
                                   instr_t *mangle_start)
{
    /* Our approach is to simply add a move-immediate of the fallthrough
     * address under the inverted predicate.  This is much simpler to
     * implement than adding a new kind of indirect branch ("conditional
     * indirect") and plumbing it through all the optimized emit and link
     * code (in particular, cbr stub sharing and other complex features).
     */
    dr_pred_type_t pred = instr_get_predicate(instr);
    ptr_int_t fall_through = get_call_return_address(dcontext, ilist, instr);
    instr_t *mov_imm, *mov_imm2;
    ASSERT(instr_is_predicated(instr)); /* caller should check */

    /* Mark the taken mangling as predicated.  We are starting after our r2
     * spill.  It gets complex w/ interactions with mangle_stolen_reg() (b/c
     * we aren't starting far enough back) so we bail for that.
     * For mangle_pc_read(), we simply don't predicate the restore (b/c
     * we aren't predicating the save).
     */
    if (!instr_uses_reg(instr, dr_reg_stolen)) {
        instr_t *prev = instr_get_next(mangle_start);
        for (; prev != next_instr; prev = instr_get_next(prev)) {
            if (instr_is_app(prev) ||
                !instr_is_reg_spill_or_restore(dcontext, prev, NULL, NULL, NULL))
                instr_set_predicate(prev, pred);
        }
    }

    insert_mov_immed_ptrsz(dcontext, (ptr_int_t)
                           PC_AS_JMP_TGT(instr_get_isa_mode(instr),
                                         (app_pc)fall_through),
                           opnd_create_reg(IBL_TARGET_REG), ilist, next_instr,
                           &mov_imm, &mov_imm2);
    instr_set_predicate(mov_imm, instr_invert_predicate(pred));
    if (mov_imm2 != NULL)
        instr_set_predicate(mov_imm2, instr_invert_predicate(pred));
}

instr_t *
mangle_direct_call(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                   instr_t *next_instr, bool mangle_calls, uint flags)
{
    /* Strategy: replace OP_bl with 2-step mov immed into lr + OP_b */
    ptr_uint_t retaddr;
    uint opc = instr_get_opcode(instr);
    ptr_int_t target;
    instr_t *mov_imm, *mov_imm2;
    /* XXX i#1551: move this to the mangle() loop to handle all instrs in one place */
    bool in_it = instr_get_isa_mode(instr) == DR_ISA_ARM_THUMB &&
        instr_is_predicated(instr);
    instr_t *bound_start = INSTR_CREATE_label(dcontext);
    if (in_it) {
        /* split instr off from its IT block for easier mangling (we reinstate later) */
        next_instr = mangle_remove_from_it_block(dcontext, ilist, instr);
    }
    PRE(ilist, instr, bound_start);
    ASSERT(opc == OP_bl || opc == OP_blx);
    ASSERT(opnd_is_pc(instr_get_target(instr)));
    target = (ptr_int_t) opnd_get_pc(instr_get_target(instr));
    retaddr = get_call_return_address(dcontext, ilist, instr);
    insert_mov_immed_ptrsz(dcontext, (ptr_int_t)
                           PC_AS_JMP_TGT(instr_get_isa_mode(instr), (app_pc)retaddr),
                           opnd_create_reg(DR_REG_LR), ilist, instr, &mov_imm, &mov_imm2);
    if (opc == OP_bl) {
        /* OP_blx predication is handled below */
        if (instr_is_predicated(instr)) {
            instr_set_predicate(mov_imm, instr_get_predicate(instr));
            if (mov_imm2 != NULL)
                instr_set_predicate(mov_imm2, instr_get_predicate(instr));
            /* Add exit cti for taken direction b/c we're removing the OP_bl */
            instrlist_preinsert
                (ilist, instr, INSTR_PRED
                 (XINST_CREATE_jump(dcontext, opnd_create_pc((app_pc)target)),
                  instr_get_predicate(instr)));
        }
    } else {
        /* Unfortunately while there is OP_blx with an immed, OP_bx requires
         * indirection through a register.  We thus need to swap modes separately,
         * but our ISA doesn't support mixing modes in one fragment, making
         * a local "blx next_instr" not easy.  We have two potential solutions:
         *   A) Implement far linking through stub's "ldr pc, [pc + 8]" and use
         *      it for blx.  We need to implement that anyway for reachability,
         *      but as it's not implemented yet, I'm going w/ B) for now.
         *   B) Pretend this is an indirect branch and use the ibl.
         *      This is slower so FIXME i#1551: switch to A once we have far links.
         */
        if (instr_get_isa_mode(instr) == DR_ISA_ARM_A32)
            target = (ptr_int_t) PC_AS_JMP_TGT(DR_ISA_ARM_THUMB, (app_pc)target);
        PRE(ilist, instr,
            instr_create_save_to_tls(dcontext, IBL_TARGET_REG, IBL_TARGET_SLOT));
        insert_mov_immed_ptrsz(dcontext, target, opnd_create_reg(IBL_TARGET_REG),
                               ilist, instr, NULL, NULL);
        if (instr_is_predicated(instr)) {
            mangle_add_predicated_fall_through(dcontext, ilist, instr, next_instr,
                                               bound_start);
            ASSERT(in_it || instr_get_isa_mode(instr) != DR_ISA_ARM_THUMB);
        }
    }
    /* remove OP_bl (final added jmp already targets the callee) or OP_blx */
    instrlist_remove(ilist, instr);
    instr_destroy(dcontext, instr);
    if (in_it)
        mangle_reinstate_it_blocks(dcontext, ilist, bound_start, next_instr);
    return next_instr;
}

void
mangle_indirect_call(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                     instr_t *next_instr, bool mangle_calls, uint flags)
{
    ptr_uint_t retaddr;
    /* XXX i#1551: move this to the mangle() loop to handle all instrs in one place */
    bool in_it = instr_get_isa_mode(instr) == DR_ISA_ARM_THUMB &&
        instr_is_predicated(instr);
    instr_t *bound_start = INSTR_CREATE_label(dcontext);
    if (in_it) {
        /* split instr off from its IT block for easier mangling (we reinstate later) */
        next_instr = mangle_remove_from_it_block(dcontext, ilist, instr);
    }
    PRE(ilist, instr,
        instr_create_save_to_tls(dcontext, IBL_TARGET_REG, IBL_TARGET_SLOT));
    /* We need the spill to be unconditional so start pred processing here */
    PRE(ilist, instr, bound_start);

    if (!opnd_same(instr_get_target(instr), opnd_create_reg(IBL_TARGET_REG))) {
        if (opnd_same(instr_get_target(instr), opnd_create_reg(dr_reg_stolen))) {
            /* if the target reg is dr_reg_stolen, the app value is in TLS */
            PRE(ilist, instr,
                instr_create_restore_from_tls(dcontext,
                                              IBL_TARGET_REG,
                                              TLS_REG_STOLEN_SLOT));
        } else {
            PRE(ilist, instr,
                XINST_CREATE_move(dcontext, opnd_create_reg(IBL_TARGET_REG),
                                  instr_get_target(instr)));
        }
    }
    retaddr = get_call_return_address(dcontext, ilist, instr);
    insert_mov_immed_ptrsz(dcontext, (ptr_int_t)
                           PC_AS_JMP_TGT(instr_get_isa_mode(instr), (app_pc)retaddr),
                           opnd_create_reg(DR_REG_LR), ilist, instr, NULL, NULL);

    if (instr_is_predicated(instr)) {
        mangle_add_predicated_fall_through(dcontext, ilist, instr, next_instr,
                                           bound_start);
        ASSERT(in_it || instr_get_isa_mode(instr) != DR_ISA_ARM_THUMB);
    }
    /* remove OP_blx_ind (final added jmp already targets the callee) */
    instrlist_remove(ilist, instr);
    instr_destroy(dcontext, instr);
    if (in_it)
        mangle_reinstate_it_blocks(dcontext, ilist, bound_start, next_instr);
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
    bool remove_instr = false;
    int opc = instr_get_opcode(instr);
    dr_isa_mode_t isa_mode = instr_get_isa_mode(instr);
    /* XXX i#1551: move this to the mangle() loop to handle all instrs in one place */
    bool in_it = instr_get_isa_mode(instr) == DR_ISA_ARM_THUMB &&
        instr_is_predicated(instr);
    instr_t *bound_start = INSTR_CREATE_label(dcontext);
    if (in_it) {
        /* split instr off from its IT block for easier mangling (we reinstate later) */
        next_instr = mangle_remove_from_it_block(dcontext, ilist, instr);
    }
    PRE(ilist, instr,
        instr_create_save_to_tls(dcontext, IBL_TARGET_REG, IBL_TARGET_SLOT));
    /* We need the spill to be unconditional so start pred processing here */
    PRE(ilist, instr, bound_start);
    if (instr_writes_gpr_list(instr)) {
        /* The load into pc will always be last (r15) so we remove it and add
         * a single-load instr into r2, with the same inc/dec and writeback.
         */
        uint i;
        bool found_pc;
        opnd_t memop = instr_get_src(instr, 0);
        instr_t *single;
        bool writeback = instr_num_srcs(instr) > 1;
        ASSERT(opnd_is_base_disp(memop));
        opnd_set_size(&memop, OPSZ_VAR_REGLIST);
        instr_set_src(instr, 0, memop);
        single = instr_clone(dcontext, instr);
        for (i = 0; i < instr_num_dsts(instr); i++) {
            ASSERT(opnd_is_reg(instr_get_dst(instr, i)));
            if (opnd_get_reg(instr_get_dst(instr, i)) == DR_REG_PC) {
                found_pc = true;
                if (i == 0 &&
                    (i == instr_num_dsts(instr) - 1 ||
                     (writeback && i == instr_num_dsts(instr) - 2)))
                    remove_instr = true;
                else
                    instr_remove_dsts(dcontext, instr, i, i+1);
                break;
            }
        }
        ASSERT(found_pc);
        if (i > 0)
            instr_remove_dsts(dcontext, single, 0, i); /* leave pc => r2 */
        instr_set_dst(single, 0, opnd_create_reg(IBL_TARGET_REG));
        instrlist_preinsert(ilist, next_instr, single); /* non-meta */
    } else if (opc == OP_bx || opc ==  OP_bxj) {
        ASSERT(opnd_is_reg(instr_get_target(instr)));
        if (opnd_same(instr_get_target(instr), opnd_create_reg(dr_reg_stolen))) {
            /* if the target reg is dr_reg_stolen, the app value is in TLS */
            PRE(ilist, instr,
                instr_create_restore_from_tls(dcontext,
                                              IBL_TARGET_REG,
                                              TLS_REG_STOLEN_SLOT));
        } else {
            PRE(ilist, instr,
                XINST_CREATE_move(dcontext, opnd_create_reg(IBL_TARGET_REG),
                                  instr_get_target(instr)));
        }
        /* remove the bx */
        remove_instr = true;
    } else if (opc == OP_tbb || opc == OP_tbh) {
        /* XXX: should we add add dr_insert_get_mbr_branch_target() for use
         * internally and by clients?  OP_tb{b,h} break our assumptions of the target
         * simply being stored as an absolute address at the memory operand location.
         * Instead, these are pc-relative: pc += memval*2.  However, it's non-trivial
         * to add that, as it requires duplicating all this mangling code.  Really
         * clients should use dr_insert_mbr_instrumentation(), and instr_get_target()
         * isn't that useful for mbrs.
         */
        ptr_int_t cur_pc = (ptr_int_t)
            decode_cur_pc(instr_get_raw_bits(instr), instr_get_isa_mode(instr),
                          opc, instr);
        if (opc == OP_tbb) {
            PRE(ilist, instr,
                INSTR_CREATE_ldrb(dcontext, opnd_create_reg(IBL_TARGET_REG),
                                  instr_get_src(instr, 0)));
        } else {
            PRE(ilist, instr,
                INSTR_CREATE_ldrh(dcontext, opnd_create_reg(IBL_TARGET_REG),
                                  instr_get_src(instr, 0)));
        }
        PRE(ilist, instr,
            INSTR_CREATE_lsl(dcontext, opnd_create_reg(IBL_TARGET_REG),
                             opnd_create_reg(IBL_TARGET_REG), OPND_CREATE_INT(1)));
        /* Rather than steal another register and using movw,movt to put the pc
         * into it, we split the add up into 4 pieces.
         * Even if the memref is pc-relative, this is still faster than sharing
         * the pc from mangle_rel_addr() if we have mangle_rel_addr() use r2
         * as the scratch reg.
         * XXX: arrange for that to happen, when we refactor the ind br vs PC
         * and stolen reg mangling, if memref doesn't already use r2.
         */
        if (opc == OP_tbb) {
            /* One byte x2 won't touch the top half, so we use a movt to add: */
            PRE(ilist, instr,
                INSTR_CREATE_movt(dcontext, opnd_create_reg(IBL_TARGET_REG),
                                  OPND_CREATE_INT((cur_pc & 0xffff0000) >> 16)));
        } else {
            PRE(ilist, instr,
                XINST_CREATE_add(dcontext, opnd_create_reg(IBL_TARGET_REG),
                                 OPND_CREATE_INT(cur_pc & 0xff000000)));
            PRE(ilist, instr,
                XINST_CREATE_add(dcontext, opnd_create_reg(IBL_TARGET_REG),
                                 OPND_CREATE_INT(cur_pc & 0x00ff0000)));
        }
        PRE(ilist, instr,
            XINST_CREATE_add(dcontext, opnd_create_reg(IBL_TARGET_REG),
                             OPND_CREATE_INT(cur_pc & 0x0000ff00)));
        PRE(ilist, instr,
            XINST_CREATE_add(dcontext, opnd_create_reg(IBL_TARGET_REG),
                             /* These do not switch modes so we set LSB */
                             OPND_CREATE_INT((cur_pc & 0x000000ff) | 0x1)));
        /* FIXME i#1551: handle instr using dr_reg_stolen */
        ASSERT_NOT_IMPLEMENTED(!instr_uses_reg(instr, dr_reg_stolen));
        /* remove the instr */
        remove_instr = true;
    } else if (opc == OP_rfe || opc == OP_rfedb || opc == OP_rfeda || opc == OP_rfeib ||
               opc == OP_eret) {
        /* FIXME i#1551: NYI on ARM */
        ASSERT_NOT_IMPLEMENTED(false);
    } else {
        /* Explicitly writes just the pc */
        uint i;
        bool found_pc;
        /* XXX: can anything (non-OP_ldm) have r2 as an additional dst? */
        ASSERT_NOT_IMPLEMENTED(!instr_writes_to_reg(instr, IBL_TARGET_REG,
                                                    DR_QUERY_INCLUDE_ALL));
        /* FIXME i#1551: handle instr using dr_reg_stolen */
        ASSERT_NOT_IMPLEMENTED(!instr_uses_reg(instr, dr_reg_stolen));
        for (i = 0; i < instr_num_dsts(instr); i++) {
            if (opnd_is_reg(instr_get_dst(instr, i)) &&
                opnd_get_reg(instr_get_dst(instr, i)) == DR_REG_PC) {
                found_pc = true;
                instr_set_dst(instr, i, opnd_create_reg(IBL_TARGET_REG));
                break;
            }
        }
        ASSERT(found_pc);
        if (isa_mode == DR_ISA_ARM_THUMB) {
            /* Thumb writes to the PC (OP_add and OP_mov are all that's allowed)
             * are non-mode-changing branches, so we set LSB to 1.
             */
            opnd_t src = opnd_create_reg(IBL_TARGET_REG);
            if (instr_get_opcode(instr) == OP_mov && !instr_is_predicated(instr)) {
                /* Optimization: we can replace the mov */
                src = instr_get_src(instr, 0);
                remove_instr = true;
            }
            PRE(ilist, next_instr,
                INSTR_CREATE_orr(dcontext, opnd_create_reg(IBL_TARGET_REG), src,
                                 OPND_CREATE_INT(1)));
        }
    }
    if (instr_is_predicated(instr)) {
        mangle_add_predicated_fall_through(dcontext, ilist, instr, next_instr,
                                           bound_start);
        ASSERT(in_it || isa_mode != DR_ISA_ARM_THUMB);
    }
    if (remove_instr) {
        instrlist_remove(ilist, instr);
        instr_destroy(dcontext, instr);
    }
    if (in_it)
        mangle_reinstate_it_blocks(dcontext, ilist, bound_start, next_instr);
}

/* Local single-instr-window scratch reg picker.  Only considers r0-r3, so the
 * caller must split up any GPR reg list first.  Assumes we only care about instrs
 * that read or write regs outside of r0-r3, so we'll only fail on instrs that
 * can access 5 GPR's, and again caller should split those up.
 */
static reg_id_t
pick_scratch_reg(instr_t *instr, ushort *scratch_slot OUT, bool *should_restore OUT)
{
    reg_id_t reg;
    ushort slot;
    *should_restore = true;
    for (reg  = SCRATCH_REG0, slot = TLS_REG0_SLOT;
         reg <= SCRATCH_REG3; reg++, slot+=sizeof(reg_t)) {
        if (!instr_uses_reg(instr, reg) &&
            /* Ensure no conflict in scratch regs for PC or stolen reg
             * mangling vs ind br mangling.  We can't just check for mbr b/c
             * of OP_blx.
             */
            (!instr_is_cti(instr) || reg != IBL_TARGET_REG))
            break;
    }
    if (reg > SCRATCH_REG3) {
        /* Likely OP_ldm.  We'll have to pick a dead reg (non-ideal b/c a fault
         * could come in: i#400).
         */
        for (reg  = SCRATCH_REG0, slot = TLS_REG0_SLOT;
             reg <= SCRATCH_REG3; reg++, slot+=sizeof(reg_t)) {
            if (!instr_reads_from_reg(instr, reg, DR_QUERY_INCLUDE_ALL) &&
                /* Ensure no conflict vs ind br mangling */
                (!instr_is_cti(instr) || reg != IBL_TARGET_REG))
                break;
        }
        *should_restore = false;
    }
    /* Only OP_stm could read all 4 of our scratch regs and also read or write
     * the PC or stolen reg (OP_smlal{b,t}{b,t} can read 4 GPR's but not a 4th),
     * and it's not allowed to have PC as a base reg (it's "unpredictable" at
     * least).  For stolen reg as base, we split it up before calling here.
     */
    ASSERT(reg <= SCRATCH_REG3);
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
    ptr_int_t r15 = (ptr_int_t)
        decode_cur_pc(instr_get_raw_bits(instr), instr_get_isa_mode(instr),
                      instr_get_opcode(instr), instr);
    opnd_t mem_op;
    ASSERT(instr_has_rel_addr_reference(instr));

    if (opc == OP_ldr || opc == OP_str || opc == OP_tbb || opc == OP_tbh) {
        ushort slot;
        bool should_restore;
        reg_id_t reg = pick_scratch_reg(instr, &slot, &should_restore);
        opnd_t new_op;
        dr_shift_type_t shift_type;
        uint shift_amt;
        if (opc == OP_str) {
            mem_op = instr_get_dst(instr, 0);
        } else {
            mem_op = instr_get_src(instr, 0);
        }
        ASSERT(opnd_is_base_disp(mem_op));
        shift_type = opnd_get_index_shift(mem_op, &shift_amt);
        new_op = opnd_create_base_disp_arm
            (reg, opnd_get_index(mem_op), shift_type, shift_amt, opnd_get_disp(mem_op),
             opnd_get_flags(mem_op), opnd_get_size(mem_op));
        PRE(ilist, instr, instr_create_save_to_tls(dcontext, reg, slot));
        insert_mov_immed_ptrsz(dcontext, r15, opnd_create_reg(reg),
                               ilist, instr, NULL, NULL);
        if (opc == OP_str) {
            instr_set_dst(instr, 0, new_op);
        } else {
            instr_set_src(instr, 0, new_op);
        }
        if (should_restore)
            PRE(ilist, next_instr, instr_create_restore_from_tls(dcontext, reg, slot));
    } else {
        /* FIXME i#1551: NYI on ARM */
        ASSERT_NOT_IMPLEMENTED(false);
    }
    return false;
}

#ifndef X64
/* mangle simple pc read, pc read in gpr_list is handled in mangle_gpr_list_read */
static void
mangle_pc_read(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                instr_t *next_instr)
{
    ushort slot;
    bool should_restore;
    reg_id_t reg = pick_scratch_reg(instr, &slot, &should_restore);
    ptr_int_t app_r15 = (ptr_int_t)
        decode_cur_pc(instr_get_raw_bits(instr), instr_get_isa_mode(instr),
                      instr_get_opcode(instr), instr);
    int i;

    ASSERT(!instr_is_meta(instr) &&
           instr_reads_from_reg(instr, DR_REG_PC, DR_QUERY_INCLUDE_ALL));

    PRE(ilist, instr, instr_create_save_to_tls(dcontext, reg, slot));
    insert_mov_immed_ptrsz(dcontext, app_r15, opnd_create_reg(reg),
                           ilist, instr, NULL, NULL);
    for (i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_uses_reg(instr_get_src(instr, i), DR_REG_PC)) {
            /* A memref should have been mangled already in mangle_rel_addr */
            opnd_t orig = instr_get_src(instr, i);
            ASSERT(opnd_is_reg(orig));
            instr_set_src(instr, i, opnd_create_reg_ex(reg, opnd_get_size(orig),
                                                       opnd_get_flags(orig)));
        }
    }
    if (should_restore)
        PRE(ilist, next_instr, instr_create_restore_from_tls(dcontext, reg, slot));
}
#endif /* !X64 */

/* save tls_base from dr_stolen_reg to reg and load app value to dr_reg_stolen */
static void
restore_app_value_to_stolen_reg(dcontext_t *dcontext, instrlist_t *ilist,
                                instr_t *instr, reg_id_t reg, ushort slot)
{
    PRE(ilist, instr, instr_create_save_to_tls(dcontext, reg, slot));
    PRE(ilist, instr, INSTR_CREATE_mov(dcontext,
                                       opnd_create_reg(reg),
                                       opnd_create_reg(dr_reg_stolen)));
    /* We always read the app value to make sure we write back
     * the correct value in the case of predicated execution.
     */
    /* XXX: optimize, we can skip this load and instead predicate the writeback
     * in restore_tls_base_to_stolen_reg (if app instr doesn't change flags).
     */
    PRE(ilist, instr, instr_create_restore_from_tls(dcontext, dr_reg_stolen,
                                                    TLS_REG_STOLEN_SLOT));
}

/* store app value from dr_reg_stolen to slot if writback is true and
 * restore tls_base from reg back to dr_reg_stolen
 */
static void
restore_tls_base_to_stolen_reg(dcontext_t *dcontext, instrlist_t *ilist,
                               instr_t *instr, reg_id_t reg, ushort slot,
                               bool writeback)
{
    if (writeback) {
        /* store app val back to its mem location */
        PRE(ilist, instr, XINST_CREATE_store
            (dcontext, opnd_create_base_disp(reg, REG_NULL, 0,
                                             os_tls_offset(TLS_REG_STOLEN_SLOT),
                                             OPSZ_PTR),
             opnd_create_reg(dr_reg_stolen)));
    }
    /* restore stolen reg from spill reg */
    PRE(ilist, instr, INSTR_CREATE_mov(dcontext,
                                       opnd_create_reg(dr_reg_stolen),
                                       opnd_create_reg(reg)));
}

static void
swap_to_app_val_in_stolen_reg(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                              bool writeback)
{
    ushort slot;
    bool should_restore;
    reg_id_t tmp;
    instr_t *next_instr = instr_get_next(instr);
    /* move stolen reg value into tmp reg for app instr execution */
    tmp = pick_scratch_reg(instr, &slot, &should_restore);
    restore_app_value_to_stolen_reg(dcontext, ilist, instr, tmp, slot);

    /* -- app instr executes here -- */

    /* restore tls_base back to dr_reg_stolen */
    restore_tls_base_to_stolen_reg(dcontext, ilist, next_instr, tmp, slot, writeback);
    /* restore tmp if necessary */
    if (should_restore)
        PRE(ilist, next_instr, instr_create_restore_from_tls(dcontext, tmp, slot));
}

static void
store_reg_to_memlist(dcontext_t *dcontext,
                     instrlist_t *ilist,
                     instr_t *instr,
                     instr_t *next_instr,
                     reg_id_t base_reg,     /* reg holding memlist base */
                     ushort   app_val_slot, /* slot holding app value */
                     reg_id_t tmp_reg,      /* scratch reg */
                     reg_id_t fix_reg,      /* reg to be fixed up */
                     uint     fix_reg_idx)
{
    bool writeback = instr_num_dsts(instr) > 1;
    uint num_srcs = instr_num_srcs(instr);
    int offs;

    switch (instr_get_opcode(instr)) {
    case OP_stmia:
        if (writeback)
            offs = -((num_srcs - 1/*writeback*/ - fix_reg_idx) * sizeof(reg_t));
        else
            offs = fix_reg_idx * sizeof(reg_t);
        break;
    case OP_stmdb:
        if (writeback)
            offs = fix_reg_idx * sizeof(reg_t);
        else
            offs = -((num_srcs - fix_reg_idx) * sizeof(reg_t));
        break;
    default:
        offs = 0;
        ASSERT_NOT_IMPLEMENTED(false); /* FIXME i#1551: NYI */
    }

    /* load proper value into spill reg */
    if (fix_reg == DR_REG_PC) {
        ptr_int_t app_r15 = (ptr_int_t)
            decode_cur_pc(instr_get_raw_bits(instr), instr_get_isa_mode(instr),
                          instr_get_opcode(instr), instr);
        insert_mov_immed_ptrsz(dcontext, app_r15, opnd_create_reg(tmp_reg),
                               ilist, next_instr, NULL, NULL);
    } else {
        /* load from app_val_slot */
        PRE(ilist, next_instr,
            instr_create_restore_from_tls(dcontext, tmp_reg, app_val_slot));
    }
    /* store to proper location */
    PRE(ilist, next_instr, XINST_CREATE_store
        (dcontext, opnd_create_base_disp(base_reg, REG_NULL, 0,
                                         offs, OPSZ_PTR),
         opnd_create_reg(tmp_reg)));
}

/* mangle dr_stolen_reg or pc read in a reglist store (i.e., stm).
 * Approach: fix up memory slot w/ app value after the store.
 */
static void
mangle_gpr_list_read(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                     instr_t *next_instr)
{
    reg_id_t spill_regs[2]  = {DR_REG_R0, DR_REG_R1};
    reg_id_t spill_slots[2] = {TLS_REG0_SLOT, TLS_REG1_SLOT};
    /* regs that need fix up in the memory slots */
    reg_id_t fix_regs[2] = { DR_REG_PC, dr_reg_stolen};
    bool reg_found[2] = { false, false };
    uint reg_pos[2]; /* position of those fix_regs in reglist  */
    uint i, j, num_srcs = instr_num_srcs(instr);
    bool writeback = instr_num_dsts(instr) > 1;
    bool stolen_reg_is_base = false;
    opnd_t memop = instr_get_dst(instr, 0);

    ASSERT(dr_reg_stolen != spill_regs[0] && dr_reg_stolen != spill_regs[1]);

    /* check base reg */
    /* base reg cannot be PC, so could only be dr_reg_stolen */
    if (opnd_uses_reg(memop, dr_reg_stolen)) {
        stolen_reg_is_base = true;
        restore_app_value_to_stolen_reg(dcontext, ilist, instr,
                                        spill_regs[0], spill_slots[0]);
        /* We do not need fix up memory slot for dr_reg_stolen since it holds
         * app value now, but we may need fix up the slot for spill_regs[0].
         */
        fix_regs[1] = spill_regs[0];
    }

    /* -- app instr executes here -- */

    /* restore dr_reg_stolen if used as base */
    if (stolen_reg_is_base) {
        ASSERT(fix_regs[1] == spill_regs[0]);
        ASSERT(opnd_uses_reg(memop, dr_reg_stolen));
        /* restore dr_reg_stolen from spill_regs[0]  */
        restore_tls_base_to_stolen_reg(dcontext, ilist,
                                       /* XXX: we must restore tls base right after instr
                                        * for other TLS usage, so we use instr_get_next
                                        * instead of next_instr.
                                        */
                                       instr_get_next(instr),
                                       spill_regs[0], spill_slots[0],
                                       writeback);
        /* do not restore spill_reg[0] as we may use it as scratch reg later */
    }

    /* fix up memory slot w/ app value after the store */
    for (i = 0; i < (writeback ? (num_srcs - 1) : num_srcs); i++) {
        reg_id_t reg;
        ASSERT(opnd_is_reg(instr_get_src(instr, i)));
        reg = opnd_get_reg(instr_get_src(instr, i));
        for (j = 0; j < 2; j++) {
            if (reg == fix_regs[j]) {
                reg_found[j] = true;
                reg_pos[j] = i;
            }
        }
    }

    if (reg_found[0] || reg_found[1]) {
        ushort app_val_slot; /* slot holding app value */
        reg_id_t base_reg;
        if (stolen_reg_is_base) {
            /* dr_reg_stolen is used as the base in the app, but it is holding
             * TLS base, so we now put dr_reg_stolen app value into spill_regs[0]
             * to use it as the base instead.
             */
            ASSERT(fix_regs[1] == spill_regs[0]);
            app_val_slot = spill_slots[0];
            base_reg = spill_regs[0];
            PRE(ilist, next_instr,
                instr_create_restore_from_tls(dcontext, spill_regs[0],
                                              TLS_REG_STOLEN_SLOT));
        } else {
            ASSERT(fix_regs[1] == dr_reg_stolen);
            app_val_slot = TLS_REG_STOLEN_SLOT;
            base_reg = opnd_get_base(memop);
        }

        /* save spill reg */
        PRE(ilist, next_instr,
            instr_create_save_to_tls(dcontext, spill_regs[1], spill_slots[1]));

        /* fixup the slot in memlist */
        for (i = 0; i < 2; i++) {
            if (reg_found[i]) {
                store_reg_to_memlist(dcontext, ilist, instr, next_instr,
                                     base_reg, app_val_slot,
                                     spill_regs[1], fix_regs[i], reg_pos[i]);
            }
        }

        /* restore spill reg */
        PRE(ilist, next_instr,
            instr_create_restore_from_tls(dcontext, spill_regs[1], spill_slots[1]));
    }

    if (stolen_reg_is_base) {
        ASSERT(fix_regs[1] == spill_regs[0]);
        PRE(ilist, next_instr,
            instr_create_restore_from_tls(dcontext, spill_regs[0], spill_slots[0]));
    }
}

static instr_t *
mangle_gpr_list_write(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                      instr_t *next_instr)
{
    /* This is extracted from mangle_stolen_reg, it handles reglist write
     * if dr_reg_stolen is in the reglist or in memop.
     * Other cases:
     * - pc cannot be used in memop,
     * - write to pc is to be handled in mangle_indirect_jump
     */

    /* FIXME i#1551: interactions w/ pc mangling: avoid same scratch reg */
    /* FIXME i#1551: interactions w/ branch mangling: any problems? */
    ASSERT(instr_writes_gpr_list(instr));
    /* Approach: split instr into 3 pieces to isolate the write.
     * OP_ldm* disallows ! if reglist includes base reg, so we should only see
     * either A) writeback of stolen reg or B) stolen reg in reglist.
     * Either way we want to split up the reglist to ensure we can get
     * a scratch reg.
     */
    uint i, num_dsts = instr_num_dsts(instr);
    bool found_reg;
    opnd_t memop = instr_get_src(instr, 0);
    instr_t *tomangle, *tail;
    bool writeback;
    reg_id_t last_reg;
    uint scratch_writes = 0;

    for (i = 0; i < num_dsts; i++) {
        ASSERT(opnd_is_reg(instr_get_dst(instr, i)));
        if (opnd_get_reg(instr_get_dst(instr, i)) <= SCRATCH_REG3)
            scratch_writes++;
        if (opnd_get_reg(instr_get_dst(instr, i)) == dr_reg_stolen) {
            found_reg = true;
            break;
        }
    }
    if (!found_reg && !opnd_uses_reg(memop, dr_reg_stolen))
        return next_instr;
    ASSERT(opnd_is_base_disp(memop) && opnd_get_index(memop) == REG_NULL);
    last_reg = opnd_get_reg(instr_get_dst(instr, num_dsts - 1));
    writeback = opnd_uses_reg(memop, last_reg);
    opnd_set_size(&memop, OPSZ_VAR_REGLIST);
    instr_set_src(instr, 0, memop);

    if (opnd_uses_reg(memop, dr_reg_stolen)) {
        /* Writeback reg for OP_ldm* is always last */
        ASSERT(!found_reg || i == num_dsts - 1);
        /* Ensure we can get one of r0-r3 */
        if (scratch_writes > 3) {
            /* split off 1st 3 and mangle both sides */
            i = 3;
            tail = instr_clone(dcontext, instr);
            instr_remove_dsts(dcontext, instr, i,
                              writeback ? num_dsts - 1 : num_dsts);
            if (writeback) {
                instr_set_dst(instr, instr_num_dsts(instr) - 1,
                              opnd_create_reg(last_reg));
            }
            instr_remove_dsts(dcontext, tail, 0, i);
            swap_to_app_val_in_stolen_reg(dcontext, ilist, instr, writeback);
            instrlist_preinsert(ilist, next_instr, tail); /* non-meta */
            swap_to_app_val_in_stolen_reg(dcontext, ilist, tail, writeback);
            return tail; /* could write pc */
        } else {
            /* no split necessary */
            swap_to_app_val_in_stolen_reg(dcontext, ilist, instr, writeback);
        }
    } else {
        /* 3-piece split */
        ASSERT(found_reg);
        tomangle = instr_clone(dcontext, instr);
        tail = instr_clone(dcontext, instr);
        /* do the split but leave writeback reg */
        instr_remove_dsts(dcontext, instr, i, writeback ? num_dsts - 1 : num_dsts);
        if (writeback) {
            instr_set_dst(instr, instr_num_dsts(instr) - 1,
                          opnd_create_reg(last_reg));
        }
        if (i + 1 < (writeback ? num_dsts - 1 : num_dsts)) {
            instr_remove_dsts(dcontext, tomangle, i + 1,
                              writeback ? num_dsts - 1 : num_dsts);
        }
        instr_remove_dsts(dcontext, tomangle, 0, i); /* leave stolen reg */
        if (writeback) {
            instr_set_dst(tomangle, instr_num_dsts(tomangle) - 1,
                          opnd_create_reg(last_reg));
        }
        instr_remove_dsts(dcontext, tail, 0, i + 1);
        instrlist_preinsert(ilist, next_instr, tomangle); /* non-meta */
        swap_to_app_val_in_stolen_reg(dcontext, ilist, tomangle, writeback);
        instrlist_preinsert(ilist, next_instr, tail); /* non-meta */
        return tail; /* could write pc */
    }
    return next_instr;
}

/* XXX; merge with or refactor out old STEAL_REGISTER x86 code? */
/* mangle simple dr_reg_stolen access, dr_reg_stolen in gpr_list
 * is handled in mangle_gpr_list_{read/write}
 */
static void
mangle_stolen_reg(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                  instr_t *next_instr)
{
    ushort slot;
    bool should_restore;
    reg_id_t reg = pick_scratch_reg(instr, &slot, &should_restore);
    /* Our stolen reg model is to expose to the client.  We assume that any
     * meta instrs using it are using it as TLS.
     */
    ASSERT(!instr_is_meta(instr) && instr_uses_reg(instr, dr_reg_stolen));

    /* move stolen reg value into reg for app instr execution */
    restore_app_value_to_stolen_reg(dcontext, ilist, instr, reg, slot);

    /* -- app instr executes here -- */

    /* store app value to its mem location */
    restore_tls_base_to_stolen_reg(dcontext, ilist,
                                   /* XXX: we must restore tls base right after instr
                                    * for other TLS usage, so we use instr_get_next
                                    * instead of next_instr.
                                    */
                                   instr_get_next(instr),
                                   reg, slot, true);
    if (should_restore)
        PRE(ilist, next_instr, instr_create_restore_from_tls(dcontext, reg, slot));
}

/* On ARM, we need mangle app instr accessing registers pc and dr_reg_stolen.
 * We use this centralized mangling routine here to handle complex issues with
 * more efficient mangling code.
 */
instr_t *
mangle_special_registers(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr,
                         instr_t *next_instr)
{
    /* XXX i#1551: move this to the mangle() loop to handle all instrs in one place */
    bool finished = false;
    bool in_it = instr_get_isa_mode(instr) == DR_ISA_ARM_THUMB &&
        instr_is_predicated(instr);
    instr_t *bound_start = NULL;
    if (in_it) {
        /* split instr off from its IT block for easier mangling (we reinstate later) */
        next_instr = mangle_remove_from_it_block(dcontext, ilist, instr);
        bound_start = INSTR_CREATE_label(dcontext);
        PRE(ilist, instr, bound_start);
    }

    /* FIXME i#1551: for indirect branch mangling, we first mangle the instr here
     * for possible pc read and dr_reg_stolen read/write,
     * and leave pc write mangling later in mangle_indirect_jump, which is
     * error-prone and inefficient.
     * We should split the mangling and only mangle non-ind-branch instructions
     * here and leave mbr instruction mangling to mangle_indirect_jump.
     */
    /* special handling reglist read */
    if (instr_reads_gpr_list(instr)) {
        mangle_gpr_list_read(dcontext, ilist, instr, next_instr);
        finished = true;
    }

    /* special handling reglist write */
    if (!finished && instr_writes_gpr_list(instr)) {
        next_instr = mangle_gpr_list_write(dcontext, ilist, instr, next_instr);
        finished = true;
    }

#ifndef X64
    if (!finished && instr_reads_from_reg(instr, DR_REG_PC, DR_QUERY_INCLUDE_ALL))
        mangle_pc_read(dcontext, ilist, instr, next_instr);
#endif /* !X64 */

    /* mangle_stolen_reg must happen after mangle_pc_read to avoid reg conflict */
    if (!finished && instr_uses_reg(instr, dr_reg_stolen) && !instr_is_mbr(instr))
        mangle_stolen_reg(dcontext, ilist, instr, next_instr);

    if (in_it) {
        mangle_reinstate_it_blocks(dcontext, ilist, bound_start, next_instr);
    }
    return next_instr;
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
