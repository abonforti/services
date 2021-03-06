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

STR password_to_hex(char *input) {
	const char xx[]= "0123456789ABCDEF";
	int n = PASSSIZE;

	while (--n >= 0) {
		buffer[n] = xx[(hash[n >> 1] >> ((1 - (n & 1)) << 2)) & 0xF];
	}

	buffer[n] = '\0';

	return buffer;
}

STR crypt_password(char *input) {
	char *buffer;
	uint8_t hash[32];
	CSTR s = str_merge(CONF_PASSWORD_SALT, input);

	crypt_sha256(hash, s, str_len(input));

	buffer = mem_malloc((PASSSIZE) * sizeof(char));
	if (buffer == NULL)
		return NULL;

	str_copy_checked((char *) hash, buffer, 32 + 1);

	return buffer;
}

BOOL verify_password(char *input, char *stored_value) {
	if (str_equals(stored_value, crypt_password(input))) {
		return TRUE;
	}

	return FALSE;
}
