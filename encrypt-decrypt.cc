#include "encrypt-decrypt.h"
#include "pattimura/utils.h"
#include <stdio.h>
#include <memory.h>

PATTIMURA_Context ctx;

void encrypt(unsigned char *key, unsigned char *plain, unsigned char *encrypted, unsigned int keyLength) {
  PATTIMURA_Open(&ctx, key, 128, PATTIMURA_ECB_ENC, PATTIMURA_default_userbox);
  PATTIMURA_EncryptDecript(&ctx, encrypted, plain, 1);
}

void decrypt(unsigned char *key, unsigned char *encrypted, unsigned char *decrypted, unsigned int keyLength) {
  PATTIMURA_Open(&ctx, key, 128, PATTIMURA_ECB_DEC, PATTIMURA_default_userbox);
  PATTIMURA_EncryptDecript(&ctx, decrypted, encrypted, 1);
}

