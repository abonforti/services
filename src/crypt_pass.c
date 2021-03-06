/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* crypt_pass.h - crypt/decrypt password functions
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/misc.h"
#include "../inc/crypt_shs1.h"
#include "../inc/crypt_sha256.h"
#include "../inc/crypt_pass.h"
#include "../inc/main.h"
#include "../inc/users.h"


/*********************************************************
 * Hash passwords functions                              *
 *********************************************************/

STR password_to_hex(CSTR input)
{
	int      i, size;
	char     hex_str[]= "0123456789abcdef";
	char     *result;

	size = PASSHASHSIZE;
	if (!(result = malloc(size * 2 + 1)))
		return (NULL);

	result[size * 2] = 0;

	for (i = 0; i < size; i++)
	{
		result[i * 2 + 0] = hex_str[(input[i] >> 4) & 0x0F];
		result[i * 2 + 1] = hex_str[(input[i]     ) & 0x0F];
	}
	return result;
}

STR crypt_password(CSTR input) {
	char *buffer;
	uint8_t hash[32];
	CSTR s = str_merge(CONF_PASSWORD_SALT, input);

	crypt_sha256(hash, s, str_len(s));

	buffer = mem_malloc(32);
	memcpy(buffer, (char *)hash, 32);

	return buffer;
}

BOOL verify_hashed_password(CSTR input, CSTR stored_value) {
	for (int i = 0; i < PASSHASHSIZE; i++) {
		if (input[i] != stored_value[i]) {
			return FALSE;
		}
	}

	return TRUE;
}

void set_hashed_password(STR destination, CSTR hashed_password) {
	size_t dest_len = PASSHASHSIZE;

	if (IS_NOT_NULL(destination) && IS_NOT_NULL(hashed_password)) {
		STR ptr = destination;
		while ( (--dest_len >= 0) && ((*ptr++ = *hashed_password++)) );
	}
}
