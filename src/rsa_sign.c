#include "rsa_header.h"

/// \brief Fonctions de signature
/// \file rsa_sign.c
/// \author Jérémie Drezen
/// \date 15 Avril 2020

///\brief calcule le hash d'un fichier
/// \param[in] inFilename : le nom du fichier
/// \param[in] shaStr : le hash du fichier
void text2sha(char *inFilename,char *shaStr){

  int nb_char = 0;
  BYTE *buffer;
  FILE *enter;
  if((enter = fopen(inFilename,"rb")) == NULL){ //c'etait rb
    fprintf(stderr, "Erreur sur le fichier d'entrée\n");
    return;
  }

  fseek(enter, 0, SEEK_END);
  nb_char = ftell(enter);
  fseek(enter, 0, SEEK_SET);

  buffer = malloc(sizeof(BYTE) * nb_char+1);

  int i = 0;
  while (!feof(enter)) {
    fread(&buffer[i], sizeof(BYTE), 1, enter);
    i++;
  }

  sha256ofString(buffer,shaStr);
  fclose(enter);
}

///\brief calcule la signature d'un texte
/// \param[in] inFilename : le nom du fichier dont on veut la signature
/// \param[in] outFilename : le nom du fichier où la signature sera écrite
/// \param[in] signKey : la clé permettant de signer le fichier
void signText(char *inFilename, char *outFilename, rsaKey_t signKey){

  FILE *exit;
  char hashRes[SHA256_BLOCK_SIZE*2 + 1];
  uchar **buffer_lecture ;
  uchar *buffer_ecriture;
  uint64 block;
  size_t output_length;
  int length_buffer = ((SHA256_BLOCK_SIZE * 2 + 1) / 4) + 1;
  int j = 0;
  int k = 0;
  uint64 calc;

  if((exit = fopen(outFilename,"wrb")) == NULL){
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
    j++;
  }

  for (size_t i = 0; i < length_buffer; i++) {
    block = convert_4byte2int(buffer_lecture[i]);
    calc = RSAdecrypt1BlockGmp(block, signKey);
    buffer_ecriture = base64_encode(&calc,sizeof(uint64),&output_length);
    fwrite(buffer_ecriture, sizeof(uchar), output_length, exit);
    fwrite(" " , sizeof(uchar), 1,exit);
    fflush(stdout);
  }
  fclose(exit);
}

///\brief vérifie si un fichier corresponds à sa signature
/// \param[in] inFilename : le nom du fichier
/// \param[in] sign : la signature du fichier
/// \param[in] pubKey : la clé permettant de vérifier le fichier
/// \return : vrai si le fichier corresponds à sa signature, faux sinon
bool verifyText(char *inFilename, char *sign, rsaKey_t pubKey){
  char signText[SHA256_BLOCK_SIZE * 2 + 1];
  char hashRes[SHA256_BLOCK_SIZE * 2 + 1];

  uncryptSign(sign , signText, pubKey);

  text2sha(inFilename, hashRes);
  if(strcmp(signText,hashRes) == 0){
    return true;
  }
  return false;
}

///\brief decrypte la signature d'un fichier
/// \param[in] inFilename : le nom du fichier où se trouve la signature
/// \param[in] sign : la signature decrypté du fichier
/// \param[in] pubKey : la clé permettant de decrypter la signature
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

///\brief écrit une requête pour la blockchain dans un fichier
/// \param[in] file : le nom du fichier
/// \param[in] event : le type d'évenement de la blockchain
/// \param[in] mail : le mail de l'emetteur de la requête
/// \param[in] publicKey : la clé publique de l'emetteur
/// \param[in] signKey : la clé de signature de l'emetteur
void requestBlockChain(char *file, char *event, char *mail, rsaKey_t publicKey, rsaKey_t signKey){
    FILE *enter;
    time_t now = time(NULL);
    struct tm * tm = localtime(&now);
    char date[24];

    if((enter = fopen(file,"a")) == NULL){
      fprintf(stderr, "Erreur sur le fichier d'entrée\n");
      return;
    }

    strftime(date, sizeof date, "%d %B %Y", tm);
    fprintf(enter, "Date %s\n", date);
    fprintf(enter, "Type %s\n",event);
    fprintf(enter, "Clé Publique (%lu , %lu)\n",publicKey.E, publicKey.N);
    fprintf(enter, "Clé Signature (%lu , %lu)\n",signKey.E, signKey.N);
    fprintf(enter, "%s\n",mail);
    fclose(enter);
}
