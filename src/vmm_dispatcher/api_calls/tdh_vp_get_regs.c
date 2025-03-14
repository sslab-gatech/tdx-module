// Copyright (C) 2023 Intel Corporation                                          
//                                                                               
// Permission is hereby granted, free of charge, to any person obtaining a copy  
// of this software and associated documentation files (the "Software"),         
// to deal in the Software without restriction, including without limitation     
// the rights to use, copy, modify, merge, publish, distribute, sublicense,      
// and/or sell copies of the Software, and to permit persons to whom             
// the Software is furnished to do so, subject to the following conditions:      
//                                                                               
// The above copyright notice and this permission notice shall be included       
// in all copies or substantial portions of the Software.                        
//                                                                               
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS       
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL      
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES             
// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,      
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE            
// OR OTHER DEALINGS IN THE SOFTWARE.                                            
//                                                                               
// SPDX-License-Identifier: MIT

/**
 * @file tdh_vp_get_regs
 * @brief TDHVPGETREGS API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"


api_error_type tdh_vp_get_regs(uint64_t target_tdvpr_pa, uint64_t regs_pa)
{
    pa_t tdvpr_pa = { .raw = target_tdvpr_pa };
    tdvps_t *tdvps_ptr = NULL;
    pamt_block_t tdvpr_pamt_block;
    pamt_entry_t *tdvpr_pamt_entry_ptr;
    bool_t tdvpr_locked_flag = false;

    tdr_t *tdr_ptr = NULL;
    pamt_entry_t *tdr_pamt_entry_ptr;
    bool_t tdr_locked_flag = false;

    tdcs_t *tdcs_ptr = NULL;

    uint16_t curr_hkid;

    kvm_regs_t *regs_ptr = map_pa((void *) regs_pa, TDX_RANGE_RW);

    api_error_type return_val = UNINITIALIZE_ERROR;

    TDX_ERROR("TDH_VP_GET_REGS to 0x%llx\n", regs_pa);

    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa,
                                                        OPERAND_ID_RCX,
                                                        TDX_LOCK_EXCLUSIVE,
                                                        PT_TDVPR,
                                                        &tdvpr_pamt_block,
                                                        &tdvpr_pamt_entry_ptr,
                                                        &tdvpr_locked_flag);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock a TDVPR page - error = %llx\n", return_val);
        goto EXIT;
    }

    return_val = lock_and_map_implicit_tdr(get_pamt_entry_owner(tdvpr_pamt_entry_ptr),
                                            OPERAND_ID_TDR,
                                            TDX_RANGE_RO,
                                            TDX_LOCK_EXCLUSIVE,
                                            &tdr_pamt_entry_ptr,
                                            &tdr_locked_flag,
                                            &tdr_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR page - error = %llx\n", return_val);
        goto EXIT;
    }

    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                                false, TDH_VP_ENTER_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    curr_hkid = tdr_ptr->key_management_fields.hkid;

    tdvps_ptr = map_tdvps(tdvpr_pa, curr_hkid, tdcs_ptr->management_fields.num_l2_vms, TDX_RANGE_RW);

    if (tdvps_ptr == NULL)
    {
        TDX_ERROR("TDVPS mapping failed\n");
        return_val = TDX_TDCX_NUM_INCORRECT;
        goto EXIT;
    }

    // Check the VCPU state
    // if (tdvps_ptr->management.state != VCPU_ACTIVE)
    // {
    //     TDX_ERROR("TDVPS is not active\n");
    //     return_val = TDX_VCPU_STATE_INCORRECT;
    //     goto EXIT;
    // }

    set_vm_vmcs_as_active(tdvps_ptr, tdvps_ptr->management.curr_vm);

    regs_ptr->rax = tdvps_ptr->guest_state.gpr_state.rax;
    regs_ptr->rcx = tdvps_ptr->guest_state.gpr_state.rcx;
    regs_ptr->rdx = tdvps_ptr->guest_state.gpr_state.rdx;
    regs_ptr->rbx = tdvps_ptr->guest_state.gpr_state.rbx;
    regs_ptr->rsp = tdvps_ptr->guest_state.gpr_state.rsp;
    regs_ptr->rbp = tdvps_ptr->guest_state.gpr_state.rbp;
    regs_ptr->rsi = tdvps_ptr->guest_state.gpr_state.rsi;
    regs_ptr->rdi = tdvps_ptr->guest_state.gpr_state.rdi;
    regs_ptr->r8 = tdvps_ptr->guest_state.gpr_state.r8;
    regs_ptr->r9 = tdvps_ptr->guest_state.gpr_state.r9;
    regs_ptr->r10 = tdvps_ptr->guest_state.gpr_state.r10;
    regs_ptr->r11 = tdvps_ptr->guest_state.gpr_state.r11;
    regs_ptr->r12 = tdvps_ptr->guest_state.gpr_state.r12;
    regs_ptr->r13 = tdvps_ptr->guest_state.gpr_state.r13;
    regs_ptr->r14 = tdvps_ptr->guest_state.gpr_state.r14;
    regs_ptr->r15 = tdvps_ptr->guest_state.gpr_state.r15;

    ia32_vmread(VMX_GUEST_RIP_ENCODE, &regs_ptr->rip);
    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &regs_ptr->rflags);

    TDX_ERROR("regs_ptr->rax=0x%llx\n", regs_ptr->rax);
    TDX_ERROR("regs_ptr->rcx=0x%llx\n", regs_ptr->rcx);
    TDX_ERROR("regs_ptr->rdx=0x%llx\n", regs_ptr->rdx);
    TDX_ERROR("regs_ptr->rbx=0x%llx\n", regs_ptr->rbx);
    TDX_ERROR("regs_ptr->rsp=0x%llx\n", regs_ptr->rsp);
    TDX_ERROR("regs_ptr->rbp=0x%llx\n", regs_ptr->rbp);
    TDX_ERROR("regs_ptr->rsi=0x%llx\n", regs_ptr->rsi);
    TDX_ERROR("regs_ptr->rdi=0x%llx\n", regs_ptr->rdi);
    TDX_ERROR("regs_ptr->r8=0x%llx\n", regs_ptr->r8);
    TDX_ERROR("regs_ptr->r9=0x%llx\n", regs_ptr->r9);
    TDX_ERROR("regs_ptr->rip=0x%llx\n", regs_ptr->rip);

    set_seam_vmcs_as_active();

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdcs_ptr != NULL)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->management_fields.op_state_lock);
        free_la(tdcs_ptr);
    }
    if (tdr_locked_flag)
    {
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE);
        free_la(tdr_ptr);
    }
    if (tdvpr_locked_flag)
    {
        pamt_unwalk(tdvpr_pa, tdvpr_pamt_block, tdvpr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        if (tdvps_ptr != NULL)
        {
            free_la(tdvps_ptr);
        }
    }
    free_la(regs_ptr);

    return TDX_SUCCESS;
}



