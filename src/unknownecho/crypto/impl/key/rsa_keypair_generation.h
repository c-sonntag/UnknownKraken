#ifndef UNKNOWNECHO_RSA_KEYPAIR_GENERATION_H
#define UNKNOWNECHO_RSA_KEYPAIR_GENERATION_H

#include <openssl/rsa.h>

RSA *ue_rsa_keypair_gen(int bits);

#endif
