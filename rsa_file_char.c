#include "rsa_header.h"

void RSAcryptFile(char *inFilename, char *outFilename, rsaKey_t pubKey, int *output_length){

  FILE *enter;
  FILE *exit;
  uchar *buffer_lecture ;
  uchar *buffer_ecriture;
  int length=0;
  int k=0;

  /*Verification fopen*/
  if((enter = fopen(inFilename,"r")) == NULL){
    fprintf(stderr, "Erreur sur le fichier d'entrée\n");
    return;
  }
  if((exit = fopen(outFilename,"w")) == NULL){
    fprintf(stderr, "Erreur sur le fichier de sortie\n");
    return;
  }

  /*Recuperation de length*/
  fseek(enter, 0, SEEK_END);
  length=ftell(enter)/sizeof(uchar);
  fseek(enter, 0, SEEK_SET);
  printf("length=%d\n", length);

  /*Verification malloc*/
  buffer_lecture = malloc(length*sizeof(uchar));
  if(buffer_lecture == NULL){
    fprintf(stderr, "erreur malloc buffer\n");
    return;
  }
  buffer_ecriture = malloc(length*sizeof(uchar));
  if(buffer_ecriture == NULL){
    fprintf(stderr, "erreur malloc buffer\n");
    return;
  }

  /*Recuperation du ficher dans un tableau*/
  fseek(enter, 0, SEEK_SET);
  while (!feof(enter)) {
    buffer_lecture[k] = fgetc(enter);
    k++;
  }
  //j'ai verifie, normalement, jusque la ca marche
  /*Chiffrage avec la cle publique*/
  for(int i = 0; i < length; i++){
    buffer_ecriture[i] = puissance_mod_n(buffer_lecture[i], pubKey.E, pubKey.N);
  }
  /*Traduction en base 64*/
  buffer_ecriture = base64_encode(buffer_ecriture, length, output_length);
  printf("out_length=%d\n", *output_length);
  
  /*Ecriture du resultat dans le fichier outFilename*/
  for(int j = 0; j < length; j++){
    fputc( buffer_ecriture[j], exit);
  }
  fclose(enter);
  fclose(exit);
  free(buffer_lecture);
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
    fclose(enter);
    return;
  }

  for( int i =0; i< length; i++){
    buffer_lecture[i] = fgetc(enter);
  }

  buffer_ecriture = base64_decode(buffer_lecture, length, &output_length);
  for(int i = 0; i < output_length; i++){
    buffer_ecriture[i] = puissance_mod_n(buffer_ecriture[i], privKey.E, privKey.N);
    fputc( buffer_ecriture[i], exit);
  }
  fclose(enter);
  fclose(exit);
  free(buffer_lecture);
}
