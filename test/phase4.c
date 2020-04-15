#include "../src/rsa_header.h"

FILE *logfp;

int main(int argc,char **argv){

  rsaKey_t pubKey = {23,8889895013};
  rsaKey_t privKey = {3865086887,8889895013};

  /*A ajouter pour les fichiers cryptés*/
  //RSAfile_crypt("Data/msg.txt", "Data/msg_decrypt.txt", pubKey);

  printf("Calcul du hash...\n");
  signText("Data/msg.txt", "Data/msg_decrypt.txt", privKey);
  printf("Ecriture dans fichier...\n");
  printf("Début vérification...\n");

  uncryptSignedText("Data/msg.txt", "Data/msg_decrypt.txt" , "Data/res.txt", pubKey, privKey);



  /*if(verifyText("Data/msg.txt", "Data/msg_decrypt.txt" , pubKey) == true){
      printf("C'est validé\n");
  }
  else{
    printf("Malorie a encore frappé\n");
  }*/
  return 0;
}
