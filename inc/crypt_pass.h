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

extern STR crypt_password(char *input);
extern BOOL verify_password(char *input, char *stored_value);

#endif //SERVICES_CRYPT_PASS_H
