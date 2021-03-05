/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* crypt_sha256.h - provide sha256 hash function
*
*/

#ifndef SERVICES_CRYPT_SHA256_H
#define SERVICES_CRYPT_SHA256_H

/*********************************************************
 * Public code                                           *
 *********************************************************/

void crypt_sha256(uint8_t hash[32], const void *input, size_t len);

#endif //SERVICES_CRYPT_SHA256_H
