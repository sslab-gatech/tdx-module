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
 * @file tdx_td_dispatcher.h
 * @brief VM Exit from TD entry point and API dispatcher
 */
#ifndef __TDX_TD_DISPATCHER_H_INCLUDED__
#define __TDX_TD_DISPATCHER_H_INCLUDED__


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "td_transitions/td_exit_stepping.h"
#include "data_structures/tdx_local_data.h"


/**
 * @brief Entry point to TDX module from TD generated by a VM Exit
 *
 * @note Written in assembly and defined as the HOST_RIP in the TD VMCS
 *
 * @return None
 */
__attribute__((visibility("hidden"))) void tdx_tdexit_entry_point(void);

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
void tdx_failed_vmentry(void);
#endif

/**
 * @brief Common prologue flow for L1 and L2 TD dispatchers
 *
 * @param local_data - TDX module local data
 * @param vm_id - Current VM id. Should be 0 (zero) if called from L1 TD dispatcher
 * @param vm_exit_reason - Returns the value of VM_EXIT_REASON
 * @param vm_exit_qualification - Returns the value of VM_EXIT_QUALIFICATION
 * @param vm_exit_inter_info - Returns the value of VM_EXIT_INTER_INFO
 *
 * @return Stepping filter result
 */
stepping_filter_e tdx_td_l1_l2_dispatcher_common_prologue(tdx_module_local_t* local_data,
                                                          uint16_t vm_id,
                                                          vm_vmexit_exit_reason_t* vm_exit_reason,
                                                          vmx_exit_qualification_t* vm_exit_qualification,
                                                          vmx_exit_inter_info_t* vm_exit_inter_info);

/**
 * @brief Dispatcher for TD side VM Exits
 *
 * @note
 *
 * @return None
 */
void tdx_td_dispatcher(void);

/**
 * @brief Restores TDVPS registers state to local data and call the exit point to return to TD
 *
 * @note
 *
 * @return None
 */
void tdx_return_to_td(bool_t launch_state, bool_t called_from_tdenter, gprs_state_t* gpr_state);

/**
 * @brief If we got here and BUS_LOCK_PREEMPTED is still set, it means that a bus lock preemption
 * has been indicated on VM exit (bit 26 of the exit reason) but the VM exit handler decided
 * not to do a TD exit.
 * In this case, we do an asynchronous TD exit here with a synthetic BUS_LOCK (74) exit reason.
 *
 * @note
 *
 * @return None
 */
void bus_lock_exit(void);

/**
 * @brief Checks if we are returning to debug TD, and there's pending VOE that is also
 *        set in the configured TD exception bitmap. In that case do async TD-exit to VMM.
 *
 * @note
 *
 * @return None
 */
void check_pending_voe_on_debug_td_return(void);

/**
 * @brief Perform a generic VE exit - injecting a VE to the currently running TD
 *
 * @param vm_exit_reason
 * @param exit_qualification
 */
void td_generic_ve_exit(vm_vmexit_exit_reason_t vm_exit_reason, uint64_t exit_qualification);

/**
 * @brief Handler for all TDCALLs
 *
 * @param tdx_local_data_ptr - Pointer to local data
 * @param interrupt_occurred - Return a flag whether a hardware interrupt occurred during execution of
 *          one of the TDCALL leaves. Currently applicable for TDG.MEM.ACCEPT only.
 */
void td_call(tdx_module_local_t* tdx_local_data_ptr, bool_t* interrupt_occurred);

/**
 * @brief Dispatcher for TD side L2 VM Exits
 */
void tdx_td_l2_dispatcher(void);


/**
 * @brief Exit point returning to TD from TDX module
 *
 * @note Written in assembly
 *
 * @return None
 */
__attribute__((visibility("hidden"))) void tdx_tdentry_to_td(bool_t launch_state, gprs_state_t* gpr_state);



#endif // __TDX_TD_DISPATCHER_H_INCLUDED__
