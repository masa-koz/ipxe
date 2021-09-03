/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <errno.h>
#include <ipxe/settings.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_ccsecret.h>
#include <ipxe/init.h>
#include <ipxe/uaccess.h>

/** @file
 *
 * Confidential Computing Secret
 *
 */
#define CCSECRET_GUID \
  { \
    0xadf956ad, 0xe98c, 0x484c, { 0xae, 0x11, 0xb5, 0x1c, 0x7d, 0x33, 0x64, 0x47 } \
  }

/** Confidential Computing Secret configuration table */
static struct ccsecret_entry *ccsecret_entry;
EFI_USE_TABLE ( CCSECRET, &ccsecret_entry, 0 );

/** Confidential Computing Secret settings scope */
static const struct settings_scope ccsecret_settings_scope;

/**
 * Check applicability of Confidential Computing Secret setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int ccsecret_settings_applies ( struct settings *settings __unused,
				    const struct setting *setting ) {

	return ( setting->scope == &ccsecret_settings_scope );
}


/**
 * Fetch value of Confidential Computing Secret setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int ccsecret_settings_fetch ( struct settings *settings __unused,
				  struct setting *setting,
				  void *data, size_t len ) {
	size_t frag_len = 0;
	size_t result_len = 0;
	char *ptr = NULL;
	uint32_t cert_size = 0;
	uint32_t key_size = 0;
	uint32_t data_size = 0;

	ptr = (char *)phys_to_user(ccsecret_entry->base);
	memcpy(&cert_size, ptr, 4);
	memcpy(&key_size, ptr + 4 + cert_size, 4);

	DBGC ( &ccsecret_entry, "cert_size:%d, key_size:%d\n", cert_size, key_size);

	if (setting->tag == 0) {
		data_size = cert_size;
		ptr += 4;
	} else {
		data_size = key_size;
		ptr += 4 + cert_size + 4;
	}
	frag_len = data_size;
	if (frag_len > len) {
		frag_len = len;
	}
	memcpy(data, ptr, frag_len);
	result_len += data_size;

	/* Set type if not already specified */
	if ( ! setting->type )
		setting->type = &setting_type_hex;
	return result_len;
}

/** Confidential Computing Secret settings operations */
static struct settings_operations ccsecret_settings_operations = {
	.applies = ccsecret_settings_applies,
	.fetch = ccsecret_settings_fetch,
};

/** Confidential Computing Secret settings */
static struct settings ccsecret_settings = {
	.refcnt = NULL,
	.siblings = LIST_HEAD_INIT ( ccsecret_settings.siblings ),
	.children = LIST_HEAD_INIT (ccsecret_settings.children ),
	.op = &ccsecret_settings_operations,
	.default_scope = &ccsecret_settings_scope,
};

/** Initialise Confidential Computing Secret settings */
static void ccsecret_settings_init ( void ) {
	int rc;

	DBGC ( &ccsecret_entry, "ccsecret_settings_init\n" );
	if ( ( rc = register_settings ( &ccsecret_settings, NULL,
					"ccsecret" ) ) != 0 ) {
		DBG ( "Confidential Computing Secret could not register settings: %s\n",
		      strerror ( rc ) );
		return;
	}
}

/** Confidential Computing Secret settings initialiser */
struct init_fn ccsecret_settings_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = ccsecret_settings_init,
};

const struct setting ccsecret_cert_setting __setting ( SETTING_HOST_EXTRA,
						   ccsecret_cert ) = {
	.name = "cert",
	.description = "Confidential Computing Secret Certificate",
	.tag = 0,
	.type = &setting_type_hexraw,
	.scope = &ccsecret_settings_scope,
};

const struct setting ccsecret_privkey_setting __setting ( SETTING_HOST_EXTRA,
						   ccsecret_privkey ) = {
	.name = "privkey",
	.description = "Confidential Computing Secret Private Key",
	.tag = 1,
	.type = &setting_type_hexraw,
	.scope = &ccsecret_settings_scope,
};

int efi_find_ccsecret(void)     {
	if ( ! ccsecret_entry ) {
    	DBGC ( &ccsecret_entry, "ConfidentialComputingSecret has no configuration table\n" );
    	return 0;
    }
    return 1;
}