/*
 * Helper macros for OpenTDX
 */

#ifdef OPENTDX

#define API_ERROR_WITH_OPERAND_ID(error, operand_id) \
    TDX_LOG("[opentdx] " #error "(" #operand_id ")\n");

#define EARLY_INIT_VMX_CTLS(dest, init, not_allowed0, allowed1) \
    *dest = ((init | not_allowed0) & allowed1);

#else

#define API_ERROR_WITH_OPERAND_ID(error, operand_id) \
    return api_error_with_operand_id(error, operand_id);

#define EARLY_INIT_VMX_CTLS(dest, init, not_allowed0, allowed1)

#endif
