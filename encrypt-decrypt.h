#ifndef ENCRYPT_DECRYPT_H
#define ENCRYPT_DECRYPT_H

#include "pattimura/pattimura.h"
#include "pattimura/utils.h"

void encrypt(unsigned char* key, unsigned char* plain, unsigned char *encrypted, unsigned int keyLength = 128);
void decrypt(unsigned char* key, unsigned char* encrypted, unsigned char *decrypted, unsigned int keyLength = 128);

#endif
