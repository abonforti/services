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

#ifndef SERVICES_CRYPT_PASS_H
#define SERVICES_CRYPT_PASS_H

/*********************************************************
 * Public code                                           *
 *********************************************************/

extern STR password_to_hex(CSTR input);
extern STR crypt_password(CSTR input);
extern BOOL verify_password(CSTR input, CSTR stored_value);
extern void set_hashed_password(STR destination, CSTR hashed_password);

#endif //SERVICES_CRYPT_PASS_H
