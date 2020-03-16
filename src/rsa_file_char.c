#include "rsa_header.h"

void RSAcryptFile(char *inFilename, char *outFilename, rsaKey_t pubKey, int *output_length){
 FILE *enter;
 FILE *exit;
 uchar *buffer_lecture ;
 uchar **buffer_ecriture;
 uint64 *buffer_calcul;
 int nb_chars;
 int length_buffer;
 int k=0;

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
 nb_chars=ftell(enter)/sizeof(uchar);

 length_buffer = nb_chars + 1;
 /*Verification malloc*/
 buffer_lecture = malloc(length_buffer*sizeof(uchar));
 if(buffer_lecture == NULL){
   fprintf(stderr, "erreur malloc buffer\n");
   return;
 }
 buffer_calcul = malloc(length_buffer*sizeof(uint64));
 if(buffer_calcul == NULL){
   fprintf(stderr, "erreur malloc buffer\n");
   return;
 }
 buffer_ecriture = malloc(length_buffer*sizeof(uchar*));
 if(buffer_ecriture == NULL){
   fprintf(stderr, "erreur malloc buffer\n");
   return;
 }

 /*Recuperation du ficher dans un tableau*/
 fseek(enter, 0, SEEK_SET);
 while (!feof(enter)) {
   //buffer_lecture[k] = fgetc(enter);
   fread(&buffer_lecture[k], sizeof(uchar), 1, enter);
   k++;
 }
 buffer_lecture[nb_chars] = '\0';

 /*Chiffrage avec la cle publique*/
 for(int i = 0; i < nb_chars; i++){
   buffer_calcul[i] = puissance_mod_n(buffer_lecture[i], pubKey.E, pubKey.N);
 }
 /*Traduction en base 64*/
 for (int i = 0; i < nb_chars; i++) {
   buffer_ecriture[i]=base64_encode(&buffer_calcul[i],sizeof(uint64),output_length);
 }

 /*Ecriture du resultat dans le fichier outFilename*/
 for(int i = 0; i < nb_chars; i++){
     fwrite(buffer_ecriture[i], sizeof(uchar), *output_length,exit);
     fwrite(" " , sizeof(uchar), 1,exit);
 }

 *output_length = nb_chars*(*output_length);

 fclose(enter);
 fclose(exit);
 for(int i =0; i<nb_chars; i++){
   free(buffer_ecriture[i]);
 }
 free(buffer_lecture);
 free(buffer_calcul);
 free(buffer_ecriture);
}

void RSAunCryptFile(char *inFilename,char *outFilename,rsaKey_t privKey, int length){
 FILE *enter;
 FILE *exit;
 uchar **buffer_lecture ;
 uint64 **buffer_calcul;
 uchar *buffer_ecriture;
 size_t output_length;
 size_t taille = 0;
 size_t nb = 0;

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
 nb = length/taille;

 buffer_lecture = malloc(nb*sizeof(uchar*));
 if(buffer_lecture == NULL){
   fprintf(stderr, "erreur malloc buffer\n");
   return;
 }

 buffer_calcul = malloc(nb*sizeof(uint64*));
 if(buffer_calcul == NULL){
   fprintf(stderr, "erreur malloc buffer\n");
   return;
 }

 buffer_ecriture = malloc(nb*sizeof(uchar));
 if(buffer_ecriture == NULL){
   fprintf(stderr, "erreur malloc buffer\n");
   return;
 }

 for(int i=0; i< nb; i++){
   buffer_lecture[i] = malloc(taille*sizeof(uchar));
   if(buffer_lecture[i] == NULL){
     fprintf(stderr, "erreur malloc buffer\n");
     return;
   }
 }


 for(int i = 0; i< nb; i++){
   fread(buffer_lecture[i], sizeof(uchar), taille, enter);
   fseek(enter,1,SEEK_CUR);
 }

 for(int i =0; i< nb; i++){
   buffer_calcul[i] = base64_decode(buffer_lecture[i],taille,&output_length);
   buffer_ecriture[i] = puissance_mod_n(*buffer_calcul[i], privKey.E, privKey.N);
   fwrite(&buffer_ecriture[i], sizeof(uchar), 1,exit);
 }

 fclose(enter);
 fclose(exit);
 
 for (int i = 0; i< nb; i++){
   free(buffer_lecture[i]);
   free(buffer_calcul[i]);
 }
 free(buffer_lecture);
 free(buffer_calcul);
 free(buffer_ecriture);
}
