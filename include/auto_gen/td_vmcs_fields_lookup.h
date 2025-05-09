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
 *  This File is Automatically generated by the TDX xls extract tool
 *  based on architecture commit id "a1b03ec5" 
 *  Spreadsheet Format Version - '26'
 **/

#ifndef _AUTO_GEN_TD_VMCS_FIELDS_LOOKUP_H_
#define _AUTO_GEN_TD_VMCS_FIELDS_LOOKUP_H_



#include "tdx_api_defs.h"
#include "metadata_handlers/metadata_generic.h"


#define MAX_NUM_TD_VMCS_LOOKUP 144

extern const md_lookup_t td_vmcs_lookup[MAX_NUM_TD_VMCS_LOOKUP];

typedef enum
{
    /* TD VMCS Controls:
       INIT:     Initial value
       VARIABLE: Mask of bits that can be set to 0 or 1
       UNKNOWN:  Mask of "Fixed" and "Reserved" bits, whos values are set during TDHSYSINIT */

    PINBASED_CTLS_INIT = 0x00000029,
    PINBASED_CTLS_VARIABLE = 0x00000080,
    PINBASED_CTLS_UNKNOWN = 0xFFFFFF16,
    PROCBASED_CTLS_INIT = 0x91220088,
    PROCBASED_CTLS_VARIABLE = 0x20400C00,
    PROCBASED_CTLS_UNKNOWN = 0x04046173,
    PROCBASED_CTLS2_INIT = 0x133CB3FA,
    PROCBASED_CTLS2_VARIABLE = 0xCC000400,
    PROCBASED_CTLS2_UNKNOWN = 0x00000000,
    PROCBASED_CTLS3_INIT = 0x0000000000000000,
    PROCBASED_CTLS3_VARIABLE = 0x00000000000000A0,
    PROCBASED_CTLS3_UNKNOWN = 0xFFFFFFFFFFFFFF40,
    EXIT_CTLS_INIT = 0x1F3C9204,
    EXIT_CTLS_VARIABLE = 0x40000000,
    EXIT_CTLS_UNKNOWN = 0x00036DFB,
    EXIT_CTLS2_INIT = 0x0000000000000000,
    EXIT_CTLS2_VARIABLE = 0x0000000000000001,
    EXIT_CTLS2_UNKNOWN = 0xFFFFFFFFFFFFFFFC,
    ENTRY_CTLS_INIT = 0x003EE004,
    ENTRY_CTLS_VARIABLE = 0x00400200,
    ENTRY_CTLS_UNKNOWN = 0xFF8011FB,
    GUEST_CR0_INIT = 0x00000021,
    GUEST_CR4_INIT = 0x00002040,
} td_vmcs_ctl_values_e;

#endif /* _AUTO_GEN_TD_VMCS_FIELDS_LOOKUP_H_ */
