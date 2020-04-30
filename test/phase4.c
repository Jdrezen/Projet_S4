#include "../src/rsa_header.h"

FILE *logfp;

int main(int argc,char **argv){

  rsaKey_t pubKey = {770733815355,1156103149051};
  rsaKey_t privKey = {3,1156103149051};
  
  /*A ajouter pour les fichiers cryptés*/
  //RSAfile_crypt("Data/msg.txt", "Data/msg_decrypt.txt", pubKey);
  signText("Data/msg.txt", "Data/msg_decrypt.txt", privKey);

  uncryptSignedText("Data/msg.txt", "Data/msg_decrypt.txt" , "Data/res.txt", pubKey, privKey);

  //requestBlockChain("../../Desktop/Java/Projet_S4_DIYPG/TxEnAttente.txt", "CCK", "jeremie.drezen@gmail.com", pubKey, privKey);
  return 0;
}
