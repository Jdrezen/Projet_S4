#include "rsa_header.h"

void text2sha(char *inFilename,char *shaStr){

  int nb_char = 0;
  BYTE *buffer;
  FILE *enter;
  if((enter = fopen(inFilename,"rb")) == NULL){
    fprintf(stderr, "Erreur sur le fichier d'entrée\n");
    return;
  }

  fseek(enter, 0, SEEK_END);
  nb_char = ftell(enter)/4;
  fseek(enter, 0, SEEK_SET);

  buffer = malloc(sizeof(BYTE) * nb_char);

  int i = 0;
  while (!feof(enter)) {
    fread(&buffer[i], sizeof(BYTE), 1, enter);
    i++;
  }

  sha256ofString(buffer,shaStr);
  fclose(enter);
}

void signText(char *inFilename, char *outFilename, rsaKey_t signKey){

  FILE *exit;
  char hashRes[SHA256_BLOCK_SIZE*2 + 1];
  uchar **buffer_lecture ;
  uchar *buffer_ecriture;
  int block;
  size_t output_length;
  int length_buffer = ((SHA256_BLOCK_SIZE * 2 + 1) / 4) + 1;
  int j = 0;
  int k = 0;
  uint64 calc;

  if((exit = fopen(outFilename,"wr")) == NULL){
    fprintf(stderr, "Erreur sur le fichier de sortie\n");
    return;
  }

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

  text2sha(inFilename, hashRes);


  for (size_t i = 0; i < (SHA256_BLOCK_SIZE * 2); i++) {
    if(i % 4 == 0){
      j = 0;
      k++;
    }

    buffer_lecture[k][j] = hashRes[i];
  //  printf("buffer[%d][%d] : %c\n",k,j,buffer_lecture[k][j]);

    j++;
    //printf("%d\n",i);
  }

  for (size_t i = 0; i < length_buffer; i++) {
    block = convert_4byte2int(buffer_lecture[i]);
    calc = RSAcrypt1BlockGmp(block, signKey);
    buffer_ecriture = base64_encode(&calc,sizeof(uint64),&output_length);
    fwrite(buffer_ecriture, sizeof(uchar), output_length, exit);
    fwrite(" " , sizeof(uchar), 1,exit);
    fflush(stdout);
  }
  fclose(exit);
}

bool verifyText(char *inFilename, char *sign, rsaKey_t pubKey){
  char signText[SHA256_BLOCK_SIZE * 2 + 1];
  char hashRes[SHA256_BLOCK_SIZE * 2 + 1];
  FILE *enter;

  if((enter = fopen(sign,"r")) == NULL){
    fprintf(stderr, "Erreur sur le fichier de sortie\n");
    return false;
  }

  uncryptSign(sign , signText, pubKey);

  text2sha(inFilename, hashRes);

  if(strcmp(signText,hashRes) == 0){
    return true;
  }
  return false;
}

void uncryptSign(char *inFilename , char *sign, rsaKey_t pubKey){
  FILE *enter;
  uint64 *buffer_calcul;
  uchar *buffer_lecture;
  uchar *temp  = malloc(sizeof(uchar)*4);
  int taille = 0;
  int k = 0;
  uint64 block;
  size_t output_length;

  if((enter = fopen(inFilename,"r")) == NULL){
    fprintf(stderr, "Erreur sur le fichier d'entrée\n");
    return;
  }

  while(fgetc(enter) != ' '){
    taille ++;
  }


  buffer_lecture = malloc(taille * sizeof(uchar));

  for(int i = 0; i < (SHA256_BLOCK_SIZE * 2 + 1)/4; i++){
    fread(buffer_lecture, sizeof(uchar), taille, enter);
    buffer_calcul = base64_decode(buffer_lecture, taille, &output_length);
    block = RSAdecrypt1BlockGmp(*buffer_calcul, pubKey);
    convertInt2uchar(block, temp);
    k = 0;
    for (size_t j = (i * 4); j < (i * 4 + 4); j++) {
      if(j < (SHA256_BLOCK_SIZE * 2 + 1)){
        sign[j] = temp[k];
        k++;
      }
    }
    fseek(enter,1,SEEK_CUR);
  }

  sign[SHA256_BLOCK_SIZE * 2] = '\0';

  fclose(enter);
}

void uncryptSignedText(char *inFilename , char *sign, char *outFilename, rsaKey_t pubKey, rsaKey_t privKey){
  if(verifyText(inFilename, sign, pubKey) == true){
    printf("Le document est vérifié\n");
    RSAfile_decrypt(inFilename, outFilename, privKey);
  }
  else{
    printf("Le document a été modifié\n");
  }
}
