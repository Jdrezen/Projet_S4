#include "rsa_header.h"

uint64 RSAcrypt1BlockGmp(uint64 blockInt, rsaKey_t pubKey){
  mpz_t calc;
  mpz_init(calc);
  puissance_mod_n_gmp(calc,blockInt, pubKey.E, pubKey.N);
  return mpz_get_ui(calc);
}

uint64 RSAdecrypt1BlockGmp(uint64 blockInt, rsaKey_t privKey){
  mpz_t calc;
  mpz_init(calc);
  puissance_mod_n_gmp(calc,blockInt, privKey.E, privKey.N);
  return mpz_get_ui(calc);
}

void RSAfile_crypt(char *inFilename, char *outFilename, rsaKey_t pubKey){
  FILE *enter;
  FILE *exit;
  uchar **buffer_lecture ;
  uchar *buffer_ecriture;
  int block;
  int nb_chars;
  int length_buffer;
  size_t output_length;
  int k=0;
  uint64 calc;

  /*Verification fopen*/
  if((enter = fopen(inFilename,"rb")) == NULL){
    fprintf(stderr, "Erreur sur le fichier d'entrée\n");
    return;
  }
  if((exit = fopen(outFilename,"wb")) == NULL){
    fprintf(stderr, "Erreur sur le fichier de sortie\n");
    return;
  }

  /*Recuperation de length*/
  fseek(enter, 0, SEEK_END);
  nb_chars=ftell(enter)/4;
  length_buffer = nb_chars + 1;

  /*Verification malloc*/
  buffer_lecture = malloc(length_buffer*sizeof(uchar*));
  if(buffer_lecture == NULL){
    fprintf(stderr, "erreur malloc buffer\n");
    return;
  }
  for(int i = 0; i<length_buffer; i++){
    buffer_lecture[i] = malloc(4*sizeof(uchar));
    if(buffer_lecture[i] == NULL){
      fprintf(stderr, "erreur malloc buffer\n");
      return;
    }
  }

  /*Recuperation du ficher dans un tableau*/
  fseek(enter, 0, SEEK_SET);
  while (!feof(enter)) {
      fread(buffer_lecture[k], sizeof(uchar), 4, enter);
      block = convert_4byte2int(buffer_lecture[k]);
      calc = RSAcrypt1BlockGmp(block, pubKey);
      buffer_ecriture = base64_encode(&calc,sizeof(uint64),&output_length);
      fwrite(buffer_ecriture, sizeof(uchar), output_length, exit);
      fwrite(" " , sizeof(uchar), 1,exit);
      fflush(stdout);
      k++;
  }

  fclose(enter);
  fclose(exit);
  free(buffer_lecture);
}

void RSAfile_decrypt(char *inFilename, char *outFilename, rsaKey_t privKey){
  FILE *enter;
  FILE *exit;
  uint64 *buffer_calcul;
  uchar *buffer_lecture;
  uchar buffer_ecriture[4];
  int taille = 0;
  uint64 block;
  size_t output_length;
  size_t fin_block;

  if((enter = fopen(inFilename,"r")) == NULL){
    fprintf(stderr, "Erreur sur le fichier d'entrée\n");
    return;
  }
  if((exit = fopen(outFilename,"w")) == NULL){
    fprintf(stderr, "Erreur sur le fichier de sortie\n");
    return;
  }

  while(fgetc(enter) != ' '){
    taille ++;
  }
  fseek(enter, 0, SEEK_SET);

  buffer_lecture = malloc(taille * sizeof(uchar));

  while (!feof(enter)) {
    fin_block = fread(buffer_lecture, sizeof(uchar), taille, enter);
    if (fin_block == taille){
      buffer_calcul = base64_decode(buffer_lecture, taille, &output_length);
      block = RSAdecrypt1BlockGmp(*buffer_calcul, privKey);
      convertInt2uchar(block, buffer_ecriture);
      fwrite(&buffer_ecriture, sizeof(uchar), 4,exit);
      fseek(enter,1,SEEK_CUR);
    }
  }

  fclose(enter);
  fclose(exit);
  return;
}
