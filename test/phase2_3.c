/// \author Vincent Dugat
/// \date summer 2019
#include "../src/rsa_header.h"

FILE *logfp;

int main(int argc,char **argv){
  logfp = stdout;

  rsaKey_t pubKey = {23,8889895013};
  rsaKey_t privKey = {3865086887,8889895013};

  //rsaKey_t pubKey = {7,1467103114917553699};
  //rsaKey_t privKey = {1818700663,1467103114917553699};

  printf("Chiffement du message...\n");
  RSAfile_crypt("Data/msg.txt","Data/res.txt",pubKey);
  printf("Fini, cryptage\n");
  printf("Déchiffement du message...\n");
  RSAfile_decrypt("Data/res.txt","Data/msg_decrypt.txt",privKey);
  printf("Fini, decryptage\n");
  return 0;
}
