#include "rsa_header.h"

uint64 RSAcrypt1BlockGmp(uint64 blockInt, rsaKey t pubKey){
  mpz_t res;
  puissance_mod_n_gmp(res,blockInt, pubKey.E, pubKey.N);
  return res;
}

void RSAfile_crypt(char *inFilename, char *outFilename, rsaKey t pubKey){
  return;
}
