/**
 * @file tdh_mem_page_accept
 * @brief TDHMEMPAGEACCEPT API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"

typedef enum tdaccept_failure_type_e
{
    TDACCEPT_SUCCESS              = 0,
    TDACCEPT_ALREADY_ACCEPTED     = 1,
    TDACCEPT_SIZE_MISMATCH        = 2,
    TDACCEPT_VIOLATION            = 3,
    TDACCEPT_AQCUIRE_LOCK_FAILURE = 4
} tdaccept_failure_type_t;

static tdaccept_failure_type_t check_tdaccept_failure(bool_t walk_failed, bool_t is_leaf,
                                                      ia32e_sept_t *sept_ptr, ia32e_sept_t* sept_entry_copy,
                                                      bool_t *sept_ptr_locked_flag, api_error_type* error)
{
    // SEPT walk fails only when reached level is smaller than requested level
    // i.e. (ept_level > req_accept_level)
    // Because when (ept_level == req_accept_level) - it means walk success
    // And (ept_level < req_accept_level) is impossible, because SEPT walk will break at requested level

    IF_RARE (walk_failed)
    {
        /* Case 1.1:
           SEPT walk failed and terminated due to a guest-accessible (MAPPED, BLOCKEDW or EXPORTED*) *leaf* entry
           at a level > requested ACCEPT size (e.g. 2 MB PTE for a 4 KB request) */
        if (sept_state_is_guest_accessible_leaf(*sept_entry_copy))
        {
            TDX_WARN("Guest-accessible *leaf* entry > requested ACCEPT size\n");
            return TDACCEPT_ALREADY_ACCEPTED;
        }

        /* Case 1.2:
           SEPT walk failed and terminated due to a non-guest-accessible (BLOCKED, PENDING*
           etc. *leaf* entry at a level > requested ACCEPT size (e.g. 2 MB PTE PENDING leaf
           for a 4 KB request).

           Or

           Case 2:
           SEPT walk failed due to intermediate paging structure missing or inaccessible (e.g.missing PDE for a
           4 KB request). */
        else
        {
            TDX_WARN("Non-guest-accessible *leaf* entry > requested ACCEPT size\n");
            return TDACCEPT_VIOLATION;
        }
    }

    // Lock the SEPT entry
    api_error_type return_val = sept_lock_acquire_guest(sept_ptr);
    if (TDX_SUCCESS != return_val)
    {
        TDX_ERROR("sept_lock_acquire_guest with error code 0x%llx\n", return_val);
        *error = return_val;
        return TDACCEPT_AQCUIRE_LOCK_FAILURE;
    }
    *sept_ptr_locked_flag = true;

    // Read the SEPT entry again (and update the copy) after it was locked
    sept_entry_copy->raw = sept_ptr->raw;

    /* Case 3:
        SEPT walk terminated at a non-leaf entry (e.g. ACCEPT requested 2M but page mapped as 4K) */
    IF_RARE (!is_sept_free(sept_entry_copy) && !is_leaf)
    {
        // Non-free non-leaf entry == requested ACCEPT size
        // (i.e. requested 2M entry is mapped to a EPT page instead of being a leaf)
        TDX_WARN("Non-free non-leaf entry < requested ACCEPT size\n");
        return TDACCEPT_SIZE_MISMATCH;
    }
    else
    {
        // Secure EPT walk terminated with leaf entry == requested ACCEPT size.
        // Entry state is a guest-accessible (MAPPED, BLOCKEDW or EXPORTED_*)
        if (sept_state_is_guest_accessible_leaf(*sept_entry_copy))
        {
            TDX_WARN("Guest-accessible leaf entry at level == requested ACCEPT size\n");
            return TDACCEPT_ALREADY_ACCEPTED;
        }

        // Secure EPT walk terminated with leaf entry == requested ACCEPT size.
        // Entry state is a non-ACCEPTable (not PENDING nor PENDING_EXPORTED_DIRTY)
        if (!sept_state_is_tdcall_leaf_allowed(TDG_MEM_PAGE_ACCEPT_LEAF, *sept_entry_copy))
        {
            TDX_WARN("Non-ACCEPTable leaf entry at level == requested ACCEPT size\n");
            return TDACCEPT_VIOLATION;
        }

        // Success in the last case (sept_state == SEPTE_PENDING)
        tdx_debug_assert(is_leaf);   // There are no PENDING* non-leaf entries
    }

    return TDACCEPT_SUCCESS;
}

static void init_sept_4k_page(tdr_t* tdr_p, ia32e_sept_t sept_entry)
{
    uint64_t page_to_accept_hpa = sept_entry.raw & IA32E_PAGING_STRUCT_ADDR_MASK;
    void* page_to_accept_la = map_pa_with_hkid((void*)page_to_accept_hpa, tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    // Initialize the 4KB page
    zero_area_cacheline(page_to_accept_la, TDX_PAGE_SIZE_IN_BYTES);

    free_la(page_to_accept_la);
}

api_error_type tdh_mem_page_accept(page_info_api_input_t gpa_mappings,
                                    uint64_t target_tdr_pa)
{
    api_error_type return_val = TDX_OPERAND_INVALID;
    tdx_module_local_t * local_data_ptr = get_local_data();

    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    ia32e_sept_t* sept_entry_ptr = NULL;
    ia32e_sept_t  sept_entry_copy;
    bool_t        sept_entry_locked_flag = false;
    ept_level_t   req_accept_level = gpa_mappings.level;

    pa_t page_gpa = { .raw = 0 };

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    tdr_pa.raw = target_tdr_pa;

    // Check, lock and map the owner TDR page (Shared lock!)
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_MEM_PAGE_AUG_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    /**
     * Memory operand checks
     */
    if (!verify_page_info_input(gpa_mappings, LVL_PT, LVL_PD))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    tdx_sanity_check(tdr_ptr != NULL, SCEC_TDCALL_SOURCE(TDG_MEM_PAGE_ACCEPT_LEAF), 0);
    tdx_sanity_check(tdcs_ptr != NULL, SCEC_TDCALL_SOURCE(TDG_MEM_PAGE_ACCEPT_LEAF), 1);

    if (!check_gpa_validity(page_gpa, tdcs_ptr->executions_ctl_fields.gpaw, PRIVATE_ONLY, tdcs_ptr->executions_ctl_fields.virt_maxpa))
    {
        TDX_ERROR("Page to accept GPA (=0x%llx) is not not valid\n", page_gpa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    ept_level_t ept_level = req_accept_level;
    return_val = walk_private_gpa(tdcs_ptr, page_gpa, tdr_ptr->key_management_fields.hkid,
                                  &sept_entry_ptr, &ept_level, &sept_entry_copy);

    bool_t is_leaf = is_secure_ept_leaf_entry(&sept_entry_copy);

    api_error_type error = TDX_OPERAND_BUSY;
    tdaccept_failure_type_t fail_type = check_tdaccept_failure((return_val != TDX_SUCCESS), is_leaf, sept_entry_ptr,
                                                                &sept_entry_copy, &sept_entry_locked_flag, &error);

    IF_RARE (fail_type != TDACCEPT_SUCCESS)
    {
        TDX_ERROR("Failing SEPT entry = 0x%llx, failure type = %d\n", sept_entry_copy.raw, fail_type);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // At this point we know that the page was PENDING when we sampled the SEPT entry above.
    // Atomically check that the entry has not changed and lock it on the guest side.
    // This guarantees that the SEPT entry can only be locked on the guest side for PENDING pages.

    // We're running in the guest TD context and the EPT walk was successful.
    // This means the page and is guaranteed by TLB tracking to exist at least
    // until the next TD exit, septe_p is valid throughout this function, and the page can be freely written.
    // However the state of the SEPT entry itself may change concurrently by the host VMM.

    if (req_accept_level == LVL_PT)
    {
        init_sept_4k_page(tdr_ptr, sept_entry_copy);
    }
    else 
    {
        // 2MB page
        bool_t tdaccept_2mb_done = false;
        do
        {
            init_sept_4k_page(tdr_ptr, sept_entry_copy);

            if (sept_entry_copy.accept_counter == (NUM_OF_4K_PAGES_IN_2MB - 1))
            {
                tdaccept_2mb_done = true;
                sept_entry_copy.accept_counter = 0;
            }
            else
            {
                sept_entry_copy.accept_counter += 1;
            }
        } while (!tdaccept_2mb_done);

    }

    // We're done.  Prepare a new SEPT entry value as MAPPED or EXPORTED_DIRTY as required
    sept_entry_copy.raw |= SEPT_PERMISSIONS_RWX;

    // Clearing the TDP bit relies of specific encoding of the SEPT entry state.
    // The following assertions verify this.

    if (is_sept_pending(&sept_entry_copy))
    {
        sept_update_state(&sept_entry_copy, SEPT_STATE_MAPPED_MASK);
    }
    else
    {
        sept_update_state(&sept_entry_copy, SEPT_STATE_EXP_DIRTY_MASK);
    }

    atomic_mem_write_64b(&sept_entry_ptr->raw, sept_entry_copy.raw);
    sept_lock_release(sept_entry_ptr);
    sept_entry_locked_flag = false;

    return_val = TDX_SUCCESS;

EXIT:
    // Free keyhole mappings
    if (sept_entry_ptr != NULL)
    {
        if (sept_entry_locked_flag)
        {
            sept_lock_release(sept_entry_ptr);
        }

        free_la(sept_entry_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->management_fields.op_state_lock);
        free_la(tdcs_ptr);
    }
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }

    return return_val;
}