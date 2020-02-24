#include "rsa_header.h"

void RSAcryptFile(char *inFilename, char *outFilename, rsaKey_t pubKey, int *output_length){
  return;
}

void RSAunCryptFile(char *inFilename,char *outFilename,rsaKey_t privKey, int length){

  FILE *enter;
  FILE *exit;
  uchar *buffer_lecture ;
  uchar *buffer_ecriture =NULL;
  size_t output_length;

  buffer_lecture = malloc(length*sizeof(uchar));
  if(buffer_lecture == NULL){
    fprintf(stderr, "erreur malloc buffer\n");
    return;
  }

  if((enter = fopen(inFilename,"r")) == NULL){
    fprintf(stderr, "Erreur sur le fichier d'entrée\n");
    return;
  }
  if((exit = fopen(outFilename,"w")) == NULL){
    fprintf(stderr, "Erreur sur le fichier de sortie\n");
    return;
  }

  for( int i =0; i< length; i++){
    buffer_lecture[i] = fgetc(enter);
  }

  buffer_ecriture = base64_decode(buffer_lecture, length, &output_length);
  for(int i =0; i< output_length; i++){
    //buffer_ecriture[i] = puissance_mod_n(buffer_ecriture[i], privKey.E, privKey.N);
    fputc( buffer_ecriture[i], exit);
  }
  fclose(enter);
  fclose(exit);
  free(buffer_lecture);
}
