#include "rsa_header.h"

/// \brief Fonctions de cryptage/decryptage dans des fichiers, par bloc de 4 caractère
/// \file rsa_files_blocks.c
/// \author Jérémie Drezen
/// \date 2 Mars 2020

///\brief crypt un bloc de 4 caratères
/// \param[in] blockInt : le bloc à crypter
/// \param[in] pubKey : la clé publique permettant de crypter le bloc
/// \return le résultat du cryptage
uint64 RSAcrypt1BlockGmp(uint64 blockInt, rsaKey_t pubKey){
  mpz_t calc;
  mpz_init(calc);
  puissance_mod_n_gmp(calc,blockInt, pubKey.E, pubKey.N);
  return mpz_get_ui(calc);
}

///\brief decrypt un bloc de 4 caratères
/// \param[in] blockInt : le bloc à decrypter
/// \param[in] privKey : la clé privée permettant de decrypter le bloc
/// \return le résultat du cryptage
uint64 RSAdecrypt1BlockGmp(uint64 blockInt, rsaKey_t privKey){
  mpz_t calc;
  mpz_init(calc);
  puissance_mod_n_gmp(calc,blockInt, privKey.E, privKey.N);
  return mpz_get_ui(calc);
}

///\brief crypt un message dans un fichier
/// \param[in] inFilename : le nom du fichier qui contient le message
/// \param[in] outFilename : le nom du fichier où le résultat sera écrit
/// \param[in] pubKey : la clé publique permettant de crypter le message
void RSAfile_crypt(char *inFilename, char *outFilename, rsaKey_t pubKey){
  FILE *enter;
  FILE *exit;
  uchar **buffer_lecture ;
  uchar *buffer_ecriture;
  uint64 block;
  int length_buffer;
  int ajout;
  size_t output_length;
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
  length_buffer = ftell(enter)/4;
  if((ajout = ftell(enter) % 4) != 0){
    length_buffer++;
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

  /*Recuperation du ficher dans un tableau*/
  fseek(enter, 0, SEEK_SET);
  int taille_block;
  for(int k = 0; k < length_buffer; k++) {
      taille_block = fread(buffer_lecture[k], sizeof(uchar), 4, enter);
      if(taille_block != 4){
        for(int i = taille_block; i <= 4; i++){
          buffer_lecture[k][i-1] = ' ';
        }
      }
      block = convert_4byte2int(buffer_lecture[k]);
      calc = RSAcrypt1BlockGmp(block, pubKey);
      buffer_ecriture = base64_encode(&calc,sizeof(uint64),&output_length);
      fwrite(buffer_ecriture, sizeof(uchar), output_length, exit);
      fwrite(" " , sizeof(uchar), 1,exit);
      fflush(stdout);
  }

  fclose(enter);
  fclose(exit);
  free(buffer_lecture);
}

///\brief decrypt un message dans un fichier
/// \param[in] inFilename : le nom du fichier qui contient le message
/// \param[in] outFilename : le nom du fichier où le résultat sera écrit
/// \param[in] privKey : la clé privée permettant de crypter le message
void RSAfile_decrypt(char *inFilename, char *outFilename, rsaKey_t privKey){
  FILE *enter;
  FILE *exit;
  uint64 *buffer_calcul;
  uchar *buffer_lecture;
  uchar buffer_ecriture[4];
  int taille = 0;
  int nb_cara;
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
  fseek(enter, 0, SEEK_END);
  nb_cara = ftell(enter)/taille;

  fseek(enter, 0, SEEK_SET);

  buffer_lecture = malloc(taille * sizeof(uchar));

  for(int i = 0; i < nb_cara; i++) {
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
