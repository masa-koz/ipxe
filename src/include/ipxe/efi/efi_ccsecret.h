#ifndef _EFI_CCSECRET_H
#define _EFI_CCSECRET_H

/** @file
 *
 * 
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

struct ccsecret_entry {
    uint32_t base;
    uint32_t size;
};

int efi_find_ccsecret(void);

#endif