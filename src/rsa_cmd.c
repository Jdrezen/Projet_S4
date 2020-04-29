/// \file rsa_cmd.c
/// \author Mylene BERCE
/// \date S4 2020
/// \brief interprète de commandes
#include "rsa_header.h"

/// \brief vide le buffer d'entrée
void clean_stdin(void){
  int c;
  do {
      c = getchar();
  } while (c != '\n' && c != EOF);
}

//V1 : sans le hash
void mot_de_passe(char* filemdp){
  Term_non_canonique();

  FILE* fichier;
  if ((fichier=fopen(filemdp, "r+")) == NULL) {
    perror(filemdp);
    Term_canonique();
    return;
  }
  printf("Ouverture du fichier %s\n", filemdp);
  //Est-ce qu'il y a quelque chose dans le fichier ?
  //Si y'a r ca veut dire le mec vient pour la premiere fois
  //dans ce cas la faut qu'il crée un mpd
  //sinon on lui demande le mdp et on le compare avec celui qu'on a
  char caracterePremier;
  //On lit le prmeier caractère du fichier
  caracterePremier = fgetc(fichier);
  if(caracterePremier==EOF){
    //le fichier est vide
    //creation de mot de passe
    char mdp[200];
    char mdp_verif[200];
    int taille;
    printf("Création du mot de passe\n");
    printf("Tapez votre mot de passe de 32 caractere maximum : ");
    fgets(mdp, sizeof(mdp), stdin);
    //enleve le \n
    taille = strlen(mdp);
    mdp[taille -1] = '\0';
    printf("\nTapez de nouveau votre mot de passe : ");
    fgets(mdp_verif, sizeof(mdp_verif), stdin);
    taille = strlen(mdp_verif);
    mdp_verif[taille -1] = '\0';
    while (strcmp(mdp, mdp_verif)) {
      printf("\nLes mot de passe ne correspondent pas, veuillez réessayer\n");
      printf("Tapez votre mot de passe de 32 caractere maximum : ");
      fgets(mdp, sizeof(mdp), stdin);
      //enleve le \n
      taille = strlen(mdp);
      mdp[taille -1] = '\0';
      printf("\nTapez de nouveau votre mot de passe : ");
      fgets(mdp_verif, sizeof(mdp_verif), stdin);
      taille = strlen(mdp_verif);
      mdp_verif[taille -1] = '\0';
    }
    //stocke le mot de passe dans le fichier
    //HASH DU MDP AVANT DE LE STOCKER
    fprintf(fichier, "%s\n", mdp);
    fclose(fichier);
    printf("Fermeture du fichier %s\n", filemdp);
    text2sha(filemdp, mdp);
    fichier = fopen(filemdp, "w");
    printf("Ouverture du fichier %s\n", filemdp);
    fprintf(fichier, "%s\n", mdp);
    fclose(fichier);
    printf("Fermeture du fichier %s\n", filemdp);
    printf("\nVous êtes entrés dans l'interprète\n");
  }
  else{
    //le fichier n'est pas vide
    //verification de mot de passe
    char mdp[200];
    int taille;
    char mdp_fichier[200];
    printf("Tapez votre mot de passe :");
    fgets(mdp, sizeof(mdp), stdin);
    //enleve le \n
    taille = strlen(mdp);
    mdp[taille -1] = '\0';
    //FAUT FAIRE LE HASH DU MDP
    FILE* fichier_aux = fopen("fichier_aux.txt", "w+");
    printf("Ouverture du fichier fichier_aux.txt\n");
    fprintf(fichier_aux, "%s\n", mdp);
    fclose(fichier_aux);
    printf("Fermeture du fichier fichier_aux.txt\n");
    text2sha("fichier_aux.txt", mdp);
    fichier_aux = fopen("fichier_aux.txt", "w+");
    printf("Ouverture du fichier fichier_aux.txt\n");
    fclose(fichier_aux);
    printf("Fermeture du fichier fichier_aux.txt\n");
    char caractere;
    fseek(fichier, 0, SEEK_SET);
    caractere = fgetc(fichier);
    int i = 0;
    while(caractere!='\n'){
      mdp_fichier[i] = caractere;
      i++;
      caractere = fgetc(fichier);
    }
    mdp_fichier[i] = '\0';
    //printf("mdp_fichier : %s\n", mdp_fichier);
    //DANS LE WHILE FAUT COMPARER LES 2 HASH
    while (strcmp(mdp, mdp_fichier)) {
      printf("\nMot de passe incorrect. Veuillez réessayer.\n");
      printf("Tapez votre mot de passe : ");
      fgets(mdp, sizeof(mdp), stdin);
      //enleve le \n
      taille = strlen(mdp);
      mdp[taille -1] = '\0';
      //FAUT FAIRE LE HASH DU MDP
      FILE* fichier_aux = fopen("fichier_aux.txt", "w+");
      printf("Ouverture du fichier fichier_aux.txt\n");
      fprintf(fichier_aux, "%s\n", mdp);
      fclose(fichier_aux);
      printf("Fermeture du fichier fichier_aux.txt\n");
      text2sha("fichier_aux.txt", mdp);
      fichier_aux = fopen("fichier_aux.txt", "w+");
      printf("Ouverture du fichier fichier_aux.txt\n");
      fclose(fichier_aux);
      printf("Fermeture du fichier fichier_aux.txt\n");
      //FAUT FAIRE LE HASH
    }
    fclose(fichier);
    printf("Fermeture du fichier %s\n", filemdp);
    printf("\nMot de passe correct, vous entrez dans l'interprète.\n");
  }
  Term_canonique();
}

/// \brief separe l'idClef et l'idContact et met -1 a idContact si il n'y en a pas
/// \brief verifie que la chaine soit un nombre soit deux nombres separes d'un '/'
/// \param[in] chaine : chaine a analyser
/// \param[in] idContact : emplacement du futur idContact
/// \param[in] idClef : emplacement du futur idClef
/// \returns 1 si le format n'est pas correct et 0 sinon
int extraire(char* chaine, char idContact[NAME_MAX_SIZE], int* idClef){
  // printf("[Extraire] debut\n");
  // clean_stdin();
  char* pCaractere;
  char* end;
  long nombre;
  if (!strcmp(chaine, "")) {
    *idClef = -1;
    strcpy(idContact, "");
    return 0;
  }
  if ((pCaractere = strchr(chaine, '/')) == NULL){
    // printf("[Extraire] y'a pas /\n");
    //y'a pas /
    nombre = strtol(chaine, &end, 10);
    if (strcmp(end, "")){
      //que idContact
      // printf("[Extraire] y'a que idContact\n");
      strcpy(idContact, chaine);
      // printf("[Extraire] apres strcpy\n");
      *idClef = -1;
      // printf("[Extraire] fin que idContact\n");
      return 0;
    }
    //que idClef
    // printf("[Extraire] y'a que idClef\n");
    strcpy(idContact, "");
    // printf("[Extraire] apres strcpy\n");
    *idClef = (int)nombre;
    // printf("[Extraire] fin que idClef\n");
    return 0;
  }
  // printf("[Extraire] y'a /\n");
  //y'a /
  //pCaractere contient l'adresse du / dans la chaine
  char idClef_char[100];
  int i=0;
  while (chaine[i] != '/') {
    idContact[i] = chaine[i];
    i++;
  }
  idContact[i] = '\0';
  printf("[Extraire] idContact : %s\n", idContact);
  i++;
  int j=0;
  while (chaine[i] != '\0') {
    idClef_char[j] = chaine[i];
    i++;
    j++;
  }
  idClef_char[j] = '\0';
  printf("[Extraire] idClef_char : %s\n", idClef_char);
  nombre = strtol(idClef_char, &end, 10);
  if (strcmp(end, "")){
    //idClef n'est pas un nombre
    strcpy(idContact, "");
    *idClef = -1;
    printf("[Extraire] idClef n'est pas un nombre\n");
    return 1;
  }
  *idClef = (int)nombre;
  printf("[Extraire] fin idContact & idClef\n");
  return 0;
}

/// \brief initialise la structure de données en mettant le nombre de clefs et le nombre de contacts à 0
/// \param[in] u : structure de données de l'utilisateur
void init(utilisateur_t* u){
  u->nb_keys=0;
  u->nb_contacts=0;
}
/// \brief affiche les differentes fonctions que l'utilisateur peut utiliser
void help(){
  printf("quit : sort de l'interprète\n");
  printf("listkeys [<idcontact/idclef>] : liste l'ensemble des clefs de l'idContact et/ou de l'idClef demandé.\n");
  printf("rmkeys <idcontact/idclef> : supprime les clefs de l'idContact et/ou de l'idClef demandé.\n");
  printf("newkeys <idclef> <type> : crée une nouvelle paire de clefs aléatoires avec l’identificateur et le type fourni.\n");
  printf("crypt <fileIn> <fileOut> <idcontact/idclef> : chiffre un fichier avec la clé publique de l'identificateur et sauve le résultat en base 64 dans le fichier de sortie. Le type de la clé doit être \"Chiffrement\".\n");
  printf("uncrypt <filein> <fileout> <id> : dechiffre un fichier en base 64 avec la cle privee de l’identificateur et sauve le resultat dans le fichier de sortie. Le type de la clef doit être ”Chiffrement”.\n");
  printf("save [<fileout>] : sauve l'ensemble des informations dans un fichier par défaut ou donné en paramètre.\n");
  printf("savepub <idcontact/idclef> <file> : sauve la clef publique <keyid> dans le fichier <file> en base 64.\n");
  printf("load [<filein>] : charge de fichier de sauvegarde.\n");
  printf("show <idcontact/idclef> [”pub”] [”priv”] : affiche les clefs en b64.\n");
  printf("signtext <filein> <idClef> <fileOut> : signe un texte, lu dans le fichier d'entrée, avec la clef privée de l'identificateur et écrit le résultat en base64 dans le fichier <outfile>. Le type de la clef doit être \"Signature\"\n");
  printf("verifysign <filein> <filesign> <idContact/idClef> : verifie la signature d’un un texte. \n");
  printf("certify <id> : envoie une requête à l’autorité de certification \n");
  printf("revoke <id> : envoie une requête à l’autorité de révocation.\n");
  printf("listcontacts [<idContact>] [<nom>] : liste l'ensemble des contacts et les clefs associées ou celui correspondant au nom ou à l'identificateur donné.\n");
  printf("addcontact <idClef> : ajoute un nouveau contact, crée l'identificateur et affiche un menu de saisie.\n");
  printf("modifycontact <id> : affiche des informations et un menu de modification.\n");
  printf("addkeys <id> ou <nom> : ajoute une clef à un contact");
  printf("rmcontact <idContact> : supprime le contact et toutes ses clefs.\n");
  printf("help : affiche l'ensemble de ces instructions\n");
}
/// \brief libère la mémoire et quitte l'interprète de commandes
void quit(void){
  exit(0);
}

/// \brief liste les clefs e l'utilisateur si idContact = "" et id = -1
/// \brief liste les clefs d'un contact si id = -1 et si l'idContact correpond à celui du contact voulu
/// \brief liste des clefs particulières si id != -1
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] id : identificateur d'une clef
/// \param[in] idContact : identificateur d'un contact
void listkeys(utilisateur_t u, int id, char* idContact){
  if (id == -1 && !strcmp(idContact, "")){
    printf("Vos clefs :\n");
    for (int i = 0; i < u.nb_keys; i++) {
      printf("  Identificateur : %d\n", u.list_key[i].id);
      printf("  Type : %s\n", u.list_key[i].type);

    }
    for (int i = 0; i < u.nb_contacts; i++) {
      printf("Les clefs de %s %s :\n", u.repertoire[i].prenom, u.repertoire[i].nom);
      for (int j = 0; j < u.repertoire[i].nb_keys; j++) {
        printf("  Identificateur : %d\n", u.repertoire[i].list_key[j].id);
        printf("  Type : %s\n", u.repertoire[i].list_key[j].type);
      }
    }
  }
  else{
    if (!strcmp(idContact, "")){
      int i = 0;
      while (i < u.nb_keys && id != u.list_key[i].id) {
        i++;
      }
      if (i >= u.nb_keys){
        printf("L'identificateur de la clef recherché n'existe pas\n");
        return;
      }
      printf("Identificateur : %d\nType : %s\n", u.list_key[i].id, u.list_key[i].type);
    }

    else{
      if (id == -1) {
        int i = 0;
        while (i < u.nb_contacts && strcmp(idContact ,u.repertoire[i].identificateur)) {
          i++;
        }
        if (i >= u.nb_contacts){
          printf("L'identificateur du contact recherché n'existe pas\n");
          return;
        }
        printf("Les clefs de %s %s :\n", u.repertoire[i].prenom, u.repertoire[i].nom);
        for (int j = 0; j < u.repertoire[i].nb_keys; j++) {
          printf("  Identificateur : %d\n", u.repertoire[i].list_key[j].id);
          printf("  Type : %s\n", u.repertoire[i].list_key[j].type);
        }
      }
      else{
        //on a id et idContact
        int iC= 0;
        while (iC < u.nb_contacts && strcmp(idContact ,u.repertoire[iC].identificateur)) {
          iC++;
        }
        if (iC >= u.nb_contacts){
          printf("L'identificateur du contact recherché n'existe pas\n");
          return;
        }
        int i = 0;
        while (i < u.repertoire[iC].nb_keys && id != u.repertoire[iC].list_key[i].id) {
          i++;
        }
        if (i >= u.repertoire[iC].nb_keys){
          printf("L'identificateur de la clef recherché n'existe pas\n");
          return;
        }
        printf("Identificateur : %d\nType : %s\n", u.repertoire[iC].list_key[i].id, u.repertoire[iC].list_key[i].type);
      }
    }
  }
}

/// \brief supprime une clef de l'utilisateur ou d'un contact
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] id : identificateur d'une clef
/// \param[in] idContact : identificateur d'un contact
void rmkeys(utilisateur_t* u, int id, char* idContact){
  if (strcmp(idContact, "")) {
    // suppression clef d'un contact
    int iC= 0;
    while (iC < u->nb_contacts && strcmp(idContact ,u->repertoire[iC].identificateur)) {
      iC++;
    }
    if (iC >= u->nb_contacts){
      printf("L'identificateur du contact recherché n'existe pas\n");
      return;
    }
    int i = 0;
    while (i < u->repertoire[iC].nb_keys && id != u->repertoire[iC].list_key[i].id) {
      i++;
    }
    if (i >= u->repertoire[iC].nb_keys){
      printf("L'identificateur de la clef recherché n'existe pas\n");
      return;
    }
    else{
      while (i < u->repertoire[iC].nb_keys-1) {
        u->repertoire[iC].list_key[i] = u->repertoire[iC].list_key[i+1];
        i++;
      }
      u->repertoire[iC].nb_keys--;
    }
  }
  else{
    // isuppression clef de l'utilisateur
    int i = 0;
    while (i < u->nb_keys && id != u->list_key[i].id) {
      i++;
    }
    if (i >= u->nb_keys){
      printf("L'id recherché n'existe pas\n");
      return;
    }
    else{
      while (i < u->nb_keys-1) {
        u->list_key[i] = u->list_key[i+1];
        i++;
      }
      u->nb_keys--;
    }
  }
}

/// \brief génère une nouvelle paire de clef à l'utilisateur
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] id : identificateur de la nouvelle clef
/// \param[in] type : type de la nouvelle clef
void newkeys(utilisateur_t* u, int id, char type[NAME_MAX_SIZE]){
  int i = 0;
  while (i < u->nb_keys && id != u->list_key[i].id) {
    i++;
  }
  if (i < u->nb_keys){
    printf("L'id demandé existe déjà\n");
    return;
  }
  strcpy(u->list_key[u->nb_keys].type, type);
  u->list_key[u->nb_keys].id = id;
  genKeysRabin(&(u->list_key[u->nb_keys].keys.pubKey), &(u->list_key[u->nb_keys].keys.privKey));
  u->nb_keys++;
}

/// \brief crypte un fichier dans un autre fichier grace à la clef publique d'un utilisateur ou d'un contact
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] fileIn : ficher d'entree
/// \param[in] fileOut : fichier de sortie
/// \param[in] id : identificateur d'une clef
/// \param[in] idContact : identificateur d'un contact
void crypte(utilisateur_t u, char* fileIn, char* fileOut, int id, char* idContact){
  if (strcmp(idContact, "")) {
    // cryptage avec une clef d'un contact
    int iC= 0;
    while (iC < u.nb_contacts && strcmp(idContact ,u.repertoire[iC].identificateur)) {
      iC++;
    }
    if (iC >= u.nb_contacts){
      printf("L'identificateur du contact recherché n'existe pas\n");
      return;
    }
    int i = 0;
    while (i < u.repertoire[iC].nb_keys && id != u.repertoire[iC].list_key[i].id) {
      i++;
    }
    if (i >= u.repertoire[iC].nb_keys){
      printf("L'identificateur de la clef recherché n'existe pas\n");
      return;
    }
    printf(" N de la pubkey : %lu\n", u.repertoire[iC].list_key[i].keys.pubKey.N);
    if (!strcmp(u.repertoire[iC].list_key[i].type, "Chiffrement")){
      printf("%lu\n", u.repertoire[iC].list_key[i].keys.pubKey.N);
      RSAfile_crypt(fileIn, fileOut, u.repertoire[iC].list_key[i].keys.pubKey);
      return;
    }
    printf("La clé n'est pas de type crypt\n");
  }
  else{
    // cryptage avec une clef de l'utilisateur
    int i = 0;
    while (i < u.nb_keys && id != u.list_key[i].id) {
      i++;
    }
    if (i >= u.nb_keys){
      printf("L'id recherché n'existe pas\n");
      return;
    }
    printf(" N de la pubkey : %lu\n", u.list_key[i].keys.pubKey.N);
    if (!strcmp(u.list_key[i].type, "Chiffrement")){
      printf("%lu\n", u.list_key[i].keys.pubKey.N);
      RSAfile_crypt(fileIn, fileOut, u.list_key[i].keys.pubKey);
      return;
    }
    printf("La clé n'est pas de type crypt\n");
  }
}

/// \brief décrypte un fichier dans un autre fichier grace à la clef privée de l'utilisateur
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] fileIn : ficher d'entree
/// \param[in] fileOut : fichier de sortie
/// \param[in] id : identificateur d'une clef
void uncrypt(utilisateur_t u, char* fileIn, char* fileOut, int id){
  int i = 0;
  while (i < u.nb_keys && id != u.list_key[i].id) {
    i++;
  }
  if (i >= u.nb_keys){
    printf("L'id recherché n'existe pas\n");
    return;
  }

  if (!strcmp(u.list_key[i].type, "Chiffrement")){
    RSAfile_decrypt(fileIn, fileOut, u.list_key[i].keys.privKey);
    return;
  }
  printf("La clé n'est pas de type crypt\n");
}

/// \brief sauve la structude de données dans un fichier
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] fileOut : fichier où on stocke les données de l'utilisateur
void save(utilisateur_t u, char* fileOut){
  FILE* out = fopen(fileOut, "w+");
  printf("Ouverture du fichier %s\n", fileOut);
  fprintf(out, "Nombre de clefs : %d\n", u.nb_keys);
  for (int i = 0; i < u.nb_keys; i++) {
    fprintf(out, "Identificateur %d :\n", u.list_key[i].id);
    fprintf(out, "%s\n", u.list_key[i].type);
    fprintf(out, "PubKey : (%lu,%lu)\n", u.list_key[i].keys.pubKey.E, u.list_key[i].keys.pubKey.N);
    fprintf(out, "PrivKey : (%lu,%lu)\n", u.list_key[i].keys.privKey.E, u.list_key[i].keys.privKey.N);
  }
  fprintf(out, "Nombre de contacts : %d\n", u.nb_contacts);
  for (int i = 0; i < u.nb_contacts; i++) {
    fprintf(out, "Identificateur du contact : %s\n", u.repertoire[i].identificateur);
    fprintf(out, "Nom : %s\n", u.repertoire[i].nom);
    fprintf(out, "Prenom : %s\n", u.repertoire[i].prenom);
    fprintf(out, "Commentaire : %s\n", u.repertoire[i].commentaire);
    fprintf(out, "Nombre de clefs : %d\n", u.repertoire[i].nb_keys);
    for (int j = 0; j < u.repertoire[i].nb_keys; j++) {
      fprintf(out, "Identificateur %d :\n", u.repertoire[i].list_key[j].id);
      fprintf(out, "%s\n", u.repertoire[i].list_key[j].type);
      fprintf(out, "PubKey : (%lu,%lu)\n", u.repertoire[i].list_key[j].keys.pubKey.E, u.repertoire[i].list_key[j].keys.pubKey.N);
      fprintf(out, "PrivKey : (%lu,%lu)\n", u.repertoire[i].list_key[j].keys.privKey.E, u.repertoire[i].list_key[j].keys.privKey.N);
    }
  }
  fclose(out);
  printf("Fermeture du fichier %s\n", fileOut);
}

/// \brief sauve la clef publique de l'utilisateur ou d'un contact dans un fichier en base64
/// \brief si idContact = "" on sauve une clef de l'utilisateur, sinon on sauve une clef d'un contact
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] fileOut : fichier de sortie
/// \param[in] idContact : identificateur d'un contact
void savepub(utilisateur_t u, int id, char* fileOut) {
  FILE* out = fopen(fileOut, "w+");
  printf("Ouverture du fichier %s\n", fileOut);
  int i = 0;
  int output_length;
  while (i < u.nb_keys && id != u.list_key[i].id) {
    i++;
  }
  if (i >= u.nb_keys){
    printf("L'id recherché n'existe pas\n");
    return;
  }
  char *strKey=base64_encode(&(u.list_key[i].keys.pubKey),sizeof(u.list_key[i].keys.pubKey),&output_length);
  fprintf(out,"%s\n",strKey);
  fclose(out);
  printf("Fermeture du fichier %s\n", fileOut);
}

/// \brief charge les données de l'utilisateur qui étaient stockées dans un fichier dans une structure de données
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] fileIn : fichier contenant les donnnées de l'utilisateur
void load(utilisateur_t* u, char* fileIn){
  printf("[load] debut\n");
  FILE* in;
  if ((in = fopen(fileIn, "r+")) == NULL) {
    perror(fileIn);
    return;
  }
  printf("Ouverture du fichier %s\n", fileIn);
  //nb_keys
  fseek(in, 18, SEEK_SET);
  fscanf(in, "%d", &u->nb_keys);
  //printf(" Nombre de key : %d\n", u->nb_keys);
  for (int i = 0; i < u->nb_keys; i++) {
    //identificateur
    fseek(in, 16, SEEK_CUR);
    fscanf(in, "%d", &u->list_key[i].id);
    //printf(" id : %d\n", u->list_key[i].id);

    //type
    fseek(in, 3, SEEK_CUR);
    fscanf(in, "%s", u->list_key[i].type);
    //printf(" type : %s\n", u->list_key[i].type);

    //PubKey pour le E
    fseek(in, 11, SEEK_CUR);
    fscanf(in, "%lu", &u->list_key[i].keys.pubKey.E);
    //printf(" E de la pubkey : %lu\n", u->list_key[i].keys.pubKey.E);
    //PubKey pour le N
    fseek(in, 1, SEEK_CUR);
    fscanf(in, "%lu", &u->list_key[i].keys.pubKey.N);
    printf(" N de la pubkey : %lu\n", u->list_key[i].keys.pubKey.N);

    //PrivKey pour le E
    fseek(in, 13, SEEK_CUR);
    fscanf(in, "%lu", &u->list_key[i].keys.privKey.E);
    //printf(" E de la PrivKey : %lu\n", u->list_key[i].keys.privKey.E);
    //PrivKey pour le N
    fseek(in, 1, SEEK_CUR);
    fscanf(in, "%lu", &u->list_key[i].keys.privKey.N);
    //printf(" N de la PrivKey : %lu\n", u->list_key[i].keys.privKey.N);
    fseek(in, 1, SEEK_CUR); //pour la parenthese
    printf(" N de la pubkey : %lu\n", u->list_key[i].keys.pubKey.N);
  }
  //nb_contacts
  fseek(in, 22, SEEK_CUR);
  fscanf(in, "%d", &u->nb_contacts);
  for (int i = 0; i < u->nb_contacts; i++) {
    //identificateur
    printf("[load] identificateur\n");
    fseek(in, 29, SEEK_CUR);
    int i_identificateur = 0;
    char caractere;
    while ((caractere=fgetc(in)) != '\n') {
      u->repertoire[i].identificateur[i_identificateur] = caractere;
      i_identificateur++;
    }
    u->repertoire[i].identificateur[i_identificateur] = '\0';
    printf("[load] identificateur : %s\n", u->repertoire[i].identificateur);
    //fscanf(in, "%s", u->repertoire[i].identificateur);
    //nom
    printf("[load] nom\n");
    fseek(in, 6, SEEK_CUR);
    int i_nom = 0;
    while ((caractere=fgetc(in)) != '\n') {
      u->repertoire[i].nom[i_nom] = caractere;
      i_nom++;
    }
    u->repertoire[i].nom[i_nom] = '\0';
    printf("[load] nom : %s\n", u->repertoire[i].nom);
    //fscanf(in, "%s", u->repertoire[i].nom);
    //prenom
    printf("[load] prenom\n");
    fseek(in, 9, SEEK_CUR);
    int i_prenom = 0;
    while ((caractere=fgetc(in)) != '\n') {
      u->repertoire[i].prenom[i_prenom] = caractere;
      i_prenom++;
    }
    u->repertoire[i].prenom[i_prenom] = '\0';
    //fscanf(in, "%s", u->repertoire[i].prenom);
    //commentaire
    printf("[load] commentaire\n");
    fseek(in, 14, SEEK_CUR);
    int i_commentaire = 0;
    while ((caractere=fgetc(in)) != '\n') {
      u->repertoire[i].commentaire[i_commentaire] = caractere;
      i_commentaire++;
    }
    u->repertoire[i].commentaire[i_commentaire] = '\0';
    //nb_keys
    printf("[load] nb_keys\n");
    fseek(in, 17, SEEK_CUR);
    fscanf(in, "%d", &u->repertoire[i].nb_keys);
    printf(" Nombre de key : %d\n", u->repertoire[i].nb_keys);
    for (size_t j = 0; j < u->repertoire[i].nb_keys; j++) {
      //identificateur
      printf("[load] id\n");
      fseek(in, 16, SEEK_CUR);
      fscanf(in, "%d", &u->repertoire[i].list_key[j].id);
      printf(" id : %d\n", u->repertoire[i].list_key[j].id);

      //type
      printf("[load] type\n");
      fseek(in, 3, SEEK_CUR);
      fscanf(in, "%s", u->repertoire[i].list_key[j].type);
      printf(" type : %s\n", u->repertoire[i].list_key[j].type);

      //PubKey pour le E
      fseek(in, 11, SEEK_CUR);
      fscanf(in, "%lu", &u->repertoire[i].list_key[j].keys.pubKey.E);
      //printf(" E de la pubkey : %lu\n", u->list_key[i].keys.pubKey.E);
      //PubKey pour le N
      fseek(in, 1, SEEK_CUR);
      fscanf(in, "%lu", &u->repertoire[i].list_key[j].keys.pubKey.N);
      printf(" N de la pubkey : %lu\n", u->repertoire[i].list_key[j].keys.pubKey.N);

      //PrivKey pour le E
      fseek(in, 13, SEEK_CUR);
      fscanf(in, "%lu", &u->repertoire[i].list_key[j].keys.privKey.E);
      //printf(" E de la PrivKey : %lu\n", u->list_key[i].keys.privKey.E);
      //PrivKey pour le N
      fseek(in, 1, SEEK_CUR);
      fscanf(in, "%lu", &u->repertoire[i].list_key[j].keys.privKey.N);
      //printf(" N de la PrivKey : %lu\n", u->list_key[i].keys.privKey.N);
      fseek(in, 1, SEEK_CUR); //pour la parenthese
      printf(" N de la pubkey : %lu\n", u->repertoire[i].list_key[j].keys.pubKey.N);
    }
  }
  fclose(in);
  printf("Fermeture du fichier %s\n", fileIn);
  printf("[load] FIN FIN FIN\n");
}


/// \brief affiche une clef publique et/ou privée de l'utilisateur ou une clef publique d'un contact en base64
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] id : identificateur de la paire de clef
/// \param[in] pub : si pub est à 1 on affiche la clef publique
/// \param[in] priv : si priv est à 1 on affiche la clef privée
/// \param[in] idContact : identificateur d'un contact
void show(utilisateur_t u, int id, int priv, int pub, char* idContact){
  if (strcmp(idContact, "")) {
    // affichage de la clef publique d'un contact
    int iC= 0;
    while (iC < u.nb_contacts && strcmp(idContact ,u.repertoire[iC].identificateur)) {
      iC++;
    }
    if (iC >= u.nb_contacts){
      printf("L'identificateur du contact recherché n'existe pas\n");
      return;
    }
    int i = 0;
    while (i < u.repertoire[iC].nb_keys && id != u.repertoire[iC].list_key[i].id) {
      i++;
    }
    if (i >= u.repertoire[iC].nb_keys){
      printf("L'identificateur de la clef recherché n'existe pas\n");
      return;
    }

    if (priv == 1) {
      printf("Il est impossible d'afficher la clef privée d'un contact\n");
      return;
    }
    int output_length_priv;
    char *strPrivKey=base64_encode(&(u.repertoire[iC].list_key[i].keys.privKey),sizeof(u.repertoire[iC].list_key[i].keys.privKey),&output_length_priv);
    printf("%s\n",strPrivKey);
  }
  else{
    // affichage d'une/des clef(s) de l'utilisateur
    int i=0;
    while (i < u.nb_keys && id != u.list_key[i].id) {
      i++;
    }
    if (i >= u.nb_keys){
      printf("L'id recherché n'existe pas\n");
      return;
    }

    int output_length_pub, output_length_priv;

    if ((priv && pub) || (!priv && !pub)){
      char *strPubKey=base64_encode(&(u.list_key[i].keys.pubKey),sizeof(u.list_key[i].keys.pubKey),&output_length_pub);
      printf("%s\n",strPubKey);
      char *strPrivKey=base64_encode(&(u.list_key[i].keys.privKey),sizeof(u.list_key[i].keys.privKey),&output_length_priv);
      printf("%s\n",strPrivKey);
    }
    else{
      if (priv){
        char *strPrivKey=base64_encode(&(u.list_key[i].keys.privKey),sizeof(u.list_key[i].keys.privKey),&output_length_priv);
        printf("%s\n",strPrivKey);
      }
      else{
        char *strPubKey=base64_encode(&(u.list_key[i].keys.pubKey),sizeof(u.list_key[i].keys.pubKey),&output_length_pub);
        printf("%s\n",strPubKey);
      }
    }
  }
}

/// \brief liste les contacts de l'utilisateur ou un en particulier si idContact != ""
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] idContact : identificateur d'un contact
/// \param[in] nom : nom d'un contact
void listcontact(utilisateur_t u, char idContact_nom[NAME_MAX_SIZE], char nom[NAME_MAX_SIZE]){
  if (!strcmp(idContact_nom, "")) {
    for (int i = 0; i < u.nb_contacts; i++) {
      printf("Identificateur : %s\n", u.repertoire[i].identificateur);
      printf("Nom : %s\n", u.repertoire[i].nom);
      printf("Prenom : %s\n", u.repertoire[i].prenom);
      printf("Commentaire : %s\n", u.repertoire[i].commentaire);
      printf("Les clefs de %s %s :\n", u.repertoire[i].prenom, u.repertoire[i].nom);
      for (int j = 0; j < u.repertoire[i].nb_keys; j++) {
        printf("  Identificateur : %d\n", u.repertoire[i].list_key[j].id);
        printf("  Type : %s\n", u.repertoire[i].list_key[j].type);
      }
    }
  }
  else{
    int iC= 0;
    while (iC < u.nb_contacts && strcmp(idContact_nom ,u.repertoire[iC].identificateur)) {
      iC++;
    }
    if (!strcmp(idContact_nom ,u.repertoire[iC].identificateur)){
      if (strcmp(nom, "") && strcmp(u.repertoire[iC].nom, nom)) {
        printf("Le nom ne correspond pas à l'identificateur donné\n");
        return;
      }
      printf("Identificateur : %s\n", u.repertoire[iC].identificateur);
      printf("Nom : %s\n", u.repertoire[iC].nom);
      printf("Prenom : %s\n", u.repertoire[iC].prenom);
      printf("Commentaire : %s\n", u.repertoire[iC].commentaire);
      printf("Les clefs de %s %s :\n", u.repertoire[iC].prenom, u.repertoire[iC].nom);
      for (int j = 0; j < u.repertoire[iC].nb_keys; j++) {
        printf("  Identificateur : %d\n", u.repertoire[iC].list_key[j].id);
        printf("  Type : %s\n", u.repertoire[iC].list_key[j].type);
      }
    }
    else{
      if (strcmp(nom, "")) {
        printf("L'identificateur n'existe pas\n");
        return;
      }
      //on cherche pour le nom
      iC = 0;
      while (iC < u.nb_contacts && strcmp(idContact_nom ,u.repertoire[iC].nom)) {
        iC++;
      }
      if (iC >= u.nb_contacts){
        //on est dans le cas ou l'idContact et le nom n'existent pas
        printf("L'identificateur ou le nom n'existe pas\n");
        return;
      }
      printf("Les clefs de %s %s :\n", u.repertoire[iC].prenom, u.repertoire[iC].nom);
      for (int j = 0; j < u.repertoire[iC].nb_keys; j++) {
        printf("  Identificateur : %d\n", u.repertoire[iC].list_key[j].id);
        printf("  Type : %s\n", u.repertoire[iC].list_key[j].type);
      }
    }
  }
}

/// \brief liste les contacts de l'utilisateur ou un en particulier si idContact != ""
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] idContact : identificateur d'un contact
/// \param[in] nom : nom d'un contact
void modifycontact(utilisateur_t *u, char idContact[NAME_MAX_SIZE]){
  int iC= 0;
  while (iC < u->nb_contacts && strcmp(idContact ,u->repertoire[iC].identificateur)) {
    iC++;
  }
  if (iC >= u->nb_contacts){
    printf("L'identificateur du contact recherché n'existe pas\n");
    return;
  }
  printf("Identificateur : %s\n", u->repertoire[iC].identificateur);
  printf("Nom : %s\n", u->repertoire[iC].nom);
  printf("Prenom : %s\n", u->repertoire[iC].prenom);
  printf("Commentaire : %s\n", u->repertoire[iC].commentaire);
  printf("Vous pouvez modifier:\n");
  printf("0 - Exit\n");
  printf("1 - Identificateur\n");
  printf("2 - Nom\n");
  printf("3 - Prenom\n");
  printf("4 - Commentaire\n");

  int taille;
  char entree[NAME_MAX_SIZE];
  //clean_stdin();
  fgets(entree, sizeof(entree), stdin);
  //enleve le \n
  taille = strlen(entree);
  entree[taille -1] = '\0';
  long nombre = -1;
  char* end;
  nombre = strtol(entree, &end, 10);
  while (strcmp(end, "") || (nombre != 0 && nombre != 1 && nombre != 2 && nombre != 3 && nombre != 4)){
    printf("Réessayez\n");
    //clean_stdin();
    fgets(entree, sizeof(entree), stdin);
    taille = strlen(entree);
    entree[taille -1] = '\0';
    nombre = strtol(entree, &end, 10);
  }

  if (nombre != 0) {
    char modification[COMMENTAIRE_SIZE];
    printf("Tapez la modification\n");
    //clean_stdin();
    fgets(modification, sizeof(modification), stdin);
    //enleve le \n
    taille = strlen(modification);
    modification[taille -1] = '\0';

    if (nombre == 1) {
      // Identificateur
      int iM= 0;
      while (iM < u->nb_contacts && strcmp(modification ,u->repertoire[iM].identificateur)) {
        iM++;
      }
      if (iM < u->nb_contacts && !strcmp(modification ,u->repertoire[iM].identificateur)){
        printf("L'identificateur du contact existe déjà\n");
      }
      else{
        if (!strcmp(modification, "")) {
          printf("Le contact doit avoir un identificateur\n");
        }
        else{
          strcpy(u->repertoire[iC].identificateur, modification);
          printf("Nouvel identificateur : %s\n", u->repertoire[iC].identificateur);
        }
      }
    }

    if (nombre == 2) {
      // Nom
      strcpy(u->repertoire[iC].nom, modification);
    }

    if (nombre == 3) {
      // Prenom
      strcpy(u->repertoire[iC].prenom, modification);
    }

    if (nombre == 4) {
      // Commentaire
      printf("[modifycontact] modification : %s\n", modification);
      int i_commentaire = 0;
      strcpy(u->repertoire[iC].commentaire,"");
      while (modification[i_commentaire] != '\0') {
        printf("[modifycontact] boucle \n");
        u->repertoire[iC].commentaire[i_commentaire] = modification[i_commentaire];
        i_commentaire++;
      }
      u->repertoire[iC].commentaire[i_commentaire] = '\0';
      printf("%s\n",   u->repertoire[iC].commentaire);
    }
  }

  while (nombre != 0) {
    printf("Identificateur : %s\n", u->repertoire[iC].identificateur);
    printf("Nom : %s\n", u->repertoire[iC].nom);
    printf("Prenom : %s\n", u->repertoire[iC].prenom);
    printf("Commentaire : %s\n", u->repertoire[iC].commentaire);
    printf("Vous pouvez modifier:\n");
    printf("0 - Exit\n");
    printf("1 - Identificateur\n");
    printf("2 - Nom\n");
    printf("3 - Prenom\n");
    printf("4 - Commentaire\n");

    //clean_stdin();
    fgets(entree, sizeof(entree), stdin);
    //enleve le \n
    taille = strlen(entree);
    entree[taille -1] = '\0';
    nombre = -1;
    nombre = strtol(entree, &end, 10);
    while (strcmp(end, "") || (nombre != 0 && nombre != 1 && nombre != 2 && nombre != 3 && nombre != 4)){
      printf("Réessayez\n");
      //clean_stdin();
      fgets(entree, sizeof(entree), stdin);
      taille = strlen(entree);
      entree[taille -1] = '\0';
      nombre = strtol(entree, &end, 10);
    }
    if (nombre != 0) {
      char modification[COMMENTAIRE_SIZE];
      printf("Tapez la modification\n");
      //clean_stdin();
      fgets(modification, sizeof(modification), stdin);
      //enleve le \n
      taille = strlen(modification);
      modification[taille -1] = '\0';

      if (nombre == 1) {
        // Identificateur
        int iM= 0;
        while (iM < u->nb_contacts && strcmp(modification ,u->repertoire[iM].identificateur)) {
          iM++;
        }
        if (!strcmp(modification, "")) {
          printf("Le contact doit avoir un identificateur\n");
        }
        else{
          if (iM < u->nb_contacts && !strcmp(modification ,u->repertoire[iM].identificateur)){
            printf("L'identificateur du contact existe déjà\n");
          }
          else{
            strcpy(u->repertoire[iC].identificateur, modification);
            printf("Nouvel identificateur : %s\n", u->repertoire[iC].identificateur);
          }
        }
      }

      if (nombre == 2) {
        // Nom
        strcpy(u->repertoire[iC].nom, modification);
      }

      if (nombre == 3) {
        // Prenom
        strcpy(u->repertoire[iC].prenom, modification);
      }

      if (nombre == 4) {
        // Commentaire
        int i_commentaire = 0;
        strcpy(u->repertoire[iC].commentaire,"");
        while (modification[i_commentaire] != '\0') {
          u->repertoire[iC].commentaire[i_commentaire] = modification[i_commentaire];
          i_commentaire++;
        }
        u->repertoire[iC].commentaire[i_commentaire] = '\0';
      }
    }
  }
}

/// \brief ajoute une clef publique à un contact
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] idContact_nom : identificateur du contact ou son nom
void addkeys(utilisateur_t *u, char idContact_nom[NAME_MAX_SIZE]){
  //on regarde si c'est un idContact
  int iC= 0;
  while (iC < u->nb_contacts && strcmp(idContact_nom ,u->repertoire[iC].identificateur)) {
    iC++;
  }
  if (iC < u->nb_contacts){
    //on ajoute une clef
    printf("Identificateur de la nouvelle clef : ");
    char entree[NAME_MAX_SIZE];
    char *end;
    fgets(entree, sizeof(entree), stdin);
    //enleve le \n
    int taille = strlen(entree);
    entree[taille -1] = '\0';
    long nombre = -1;
    nombre = strtol(entree, &end, 10);
    while (strcmp(end, "") || nombre < 0){
      printf("L'idenficateur doit être un nombre supérieur à 0\n");
      printf("Identificateur de la nouvelle clef : ");
      fgets(entree, sizeof(entree), stdin);
      taille = strlen(entree);
      entree[taille -1] = '\0';
      nombre = strtol(entree, &end, 10);
    }
    u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id = nombre;
    int indice = 0;
    while (indice < u->repertoire[iC].nb_keys && u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id != u->repertoire[iC].list_key[indice].id) {
      indice++;
    }
    while (indice < u->repertoire[iC].nb_keys) {
      printf("L'id demandé existe déjà\n");
      printf("Identificateur de la nouvelle clef : ");
      fgets(entree, sizeof(entree), stdin);
      taille = strlen(entree);
      entree[taille -1] = '\0';
      nombre = strtol(entree, &end, 10);
      while (strcmp(end, "") || nombre < 0){
        printf("L'idenficateur doit être un nombre supérieur à 0\n");
        printf("Identificateur de la nouvelle clef : ");
        fgets(entree, sizeof(entree), stdin);
        taille = strlen(entree);
        entree[taille -1] = '\0';
        nombre = strtol(entree, &end, 10);
      }
      u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id = nombre;
      indice = 0;
      while (indice < u->repertoire[iC].nb_keys && u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id != u->repertoire[iC].list_key[indice].id) {
        indice++;
      }
    }
    printf("Type de la nouvelle clef : ");
    scanf("%s", u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type);
    while (strcmp(u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type, "Signature") && strcmp(u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type, "Chiffrement")) {
      printf("Le type de la clef doit etre Signature ou Chiffrement\n");
      printf("Type de la nouvelle clef : ");
      scanf("%s", u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type);
    }
    printf("Partie E de la clef publique à ajouter : ");
    scanf("%lu", &u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].keys.pubKey.E);
    printf("Partie N de la clef publique à ajouter : ");
    scanf("%lu", &u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].keys.pubKey.N);
    u->repertoire[iC].nb_keys++;
    return;
  }
  iC= 0;
  while (iC < u->nb_contacts && strcmp(idContact_nom ,u->repertoire[iC].nom)) {
    iC++;
  }
  if (iC < u->nb_contacts){
    // il faut que le nom soit unique pour ajouter la clef a la bonne personne
    int nb_personnes_meme_nom = 0;
    int i_nb_personnes_meme_nom = 0;
    while (i_nb_personnes_meme_nom < u->nb_contacts) {
      if (!strcmp(idContact_nom ,u->repertoire[i_nb_personnes_meme_nom].nom)) {
        nb_personnes_meme_nom++;
      }
      i_nb_personnes_meme_nom++;
    }
    if (nb_personnes_meme_nom > 1) {
      printf("Plusieurs personnes portent le même nom, veuillez réessayer avec l'identificateur du contact\n");
      return;
    }
    //on ajoute une clef
    printf("Identificateur de la nouvelle clef : ");
    char entree[NAME_MAX_SIZE];
    char* end;
    //clean_stdin();
    fgets(entree, sizeof(entree), stdin);
    //enleve le \n
    int taille = strlen(entree);
    entree[taille -1] = '\0';
    long nombre = -1;
    nombre = strtol(entree, &end, 10);
    while (strcmp(end, "") || nombre < 0){
      printf("L'idenficateur doit être un nombre supérieur à 0\n");
      printf("Identificateur de la nouvelle clef : ");
      //clean_stdin();
      fgets(entree, sizeof(entree), stdin);
      taille = strlen(entree);
      entree[taille -1] = '\0';
      nombre = strtol(entree, &end, 10);
    }
    u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id = nombre;
    int indice = 0;
    while (indice < u->repertoire[iC].nb_keys && u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id != u->repertoire[iC].list_key[indice].id) {
      indice++;
    }
    while (indice < u->repertoire[iC].nb_keys) {
      printf("L'id demandé existe déjà\n");
      printf("Identificateur de la nouvelle clef : ");
      fgets(entree, sizeof(entree), stdin);
      taille = strlen(entree);
      entree[taille -1] = '\0';
      nombre = strtol(entree, &end, 10);
      while (strcmp(end, "") || nombre < 0){
        printf("L'idenficateur doit être un nombre supérieur à 0\n");
        printf("Identificateur de la nouvelle clef : ");
        fgets(entree, sizeof(entree), stdin);
        taille = strlen(entree);
        entree[taille -1] = '\0';
        nombre = strtol(entree, &end, 10);
      }
      u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id = nombre;
      indice = 0;
      while (indice < u->repertoire[iC].nb_keys && u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id != u->repertoire[iC].list_key[indice].id) {
        indice++;
      }
    }
    printf("Type de la nouvelle clef : ");
    scanf("%s", u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type);
    while (strcmp(u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type, "Signature") && strcmp(u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type, "Chiffrement")) {
      printf("Le type de la clef doit etre Signature ou Chiffrement\n");
      printf("Type de la nouvelle clef : ");
      scanf("%s", u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type);
    }
    printf("Partie E de la clef publique à ajouter : ");
    scanf("%lu", &u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].keys.pubKey.E);
    printf("Partie N de la clef publique à ajouter : ");
    scanf("%lu", &u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].keys.pubKey.N);
    u->repertoire[iC].nb_keys++;
    return;
  }
  //on creer un nouveau contact
  addcontact(u, idContact_nom);
  printf("Identificateur de la nouvelle clef : ");
  char entree[NAME_MAX_SIZE];
  char* end;
  clean_stdin();
  fgets(entree, sizeof(entree), stdin);
  //enleve le \n
  int taille = strlen(entree);
  entree[taille -1] = '\0';
  long nombre = -1;
  nombre = strtol(entree, &end, 10);
  while (strcmp(end, "") || nombre < 0){
    printf("L'idenficateur doit être un nombre supérieur à 0\n");
    printf("Identificateur de la nouvelle clef : ");
    //clean_stdin();
    fgets(entree, sizeof(entree), stdin);
    taille = strlen(entree);
    entree[taille -1] = '\0';
    nombre = strtol(entree, &end, 10);
  }
  u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id = nombre;
  int indice = 0;
  while (indice < u->repertoire[iC].nb_keys && u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id != u->repertoire[iC].list_key[indice].id) {
    indice++;
  }
  while (indice < u->repertoire[iC].nb_keys) {
    printf("L'id demandé existe déjà\n");
    printf("Identificateur de la nouvelle clef : ");
    fgets(entree, sizeof(entree), stdin);
    taille = strlen(entree);
    entree[taille -1] = '\0';
    nombre = strtol(entree, &end, 10);
    while (strcmp(end, "") || nombre < 0){
      printf("L'idenficateur doit être un nombre supérieur à 0\n");
      printf("Identificateur de la nouvelle clef : ");
      fgets(entree, sizeof(entree), stdin);
      taille = strlen(entree);
      entree[taille -1] = '\0';
      nombre = strtol(entree, &end, 10);
    }
    u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id = nombre;
    indice = 0;
    while (indice < u->repertoire[iC].nb_keys && u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].id != u->repertoire[iC].list_key[indice].id) {
      indice++;
    }
  }
  printf("Type de la nouvelle clef : ");
  scanf("%s", u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type);
  while (strcmp(u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type, "Signature") && strcmp(u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type, "Chiffrement")) {
    printf("Le type de la clef doit etre Signature ou Chiffrement\n");
    printf("Type de la nouvelle clef : ");
    scanf("%s", u->repertoire[iC].list_key[u->repertoire[iC].nb_keys].type);
  }
  printf("Partie E de la clef publique à ajouter : ");
  scanf("%lu", &u->repertoire[u->nb_contacts-1].list_key[u->repertoire[iC].nb_keys].keys.pubKey.E);
  printf("Partie N de la clef publique à ajouter : ");
  scanf("%lu", &u->repertoire[u->nb_contacts-1].list_key[u->repertoire[iC].nb_keys].keys.pubKey.N);
  u->repertoire[iC].nb_keys++;
  return;
}

/// \brief supprime un contact
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] idContact : identificateur du contact
void rmcontact(utilisateur_t *u, char idContact[NAME_MAX_SIZE]){
  int iC= 0;
  while (iC < u->nb_contacts && strcmp(idContact ,u->repertoire[iC].identificateur)) {
    iC++;
  }
  if (iC >= u->nb_contacts){
    printf("L'identificateur du contact recherché n'existe pas\n");
    return;
  }
  // on supprime les chaines de caracteres car on ne les écrasera pas quand on les remplira de nouveau
  strcpy(u->repertoire[iC].commentaire, "");
  strcpy(u->repertoire[iC].nom, "");
  strcpy(u->repertoire[iC].identificateur, "");
  strcpy(u->repertoire[iC].prenom, "");
  for (; iC < u->nb_contacts -1; iC++) {
    u->repertoire[iC] = u->repertoire[iC +1];
  }
  u->nb_contacts--;
}

/// \brief ajoute un contact
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] idContact : identificateur du nouveau contact
void addcontact(utilisateur_t* u, char idContact[NAME_MAX_SIZE]){
  int i = 0;
  while (i < u->nb_contacts && strcmp(idContact, u->repertoire[i].identificateur)) {
    i++;
  }
  if (i < u->nb_contacts){
    printf("L'identificateur du contact demandé existe déjà\n");
    return;
  }
  strcpy(u->repertoire[u->nb_contacts].identificateur, idContact);
  printf("Nom : ");
  scanf("%s", u->repertoire[u->nb_contacts].nom);
  printf("Prenom : ");
  scanf("%s", u->repertoire[u->nb_contacts].prenom);
  printf("Commentaire : ");
  scanf("%s", u->repertoire[u->nb_contacts].commentaire);
  u->repertoire[u->nb_contacts].nb_keys = 0;
  u->nb_contacts++;
}

/// \brief signe un texte avec une clef privée de l'utilisateur
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] fileIn : fichier d'entrée
/// \param[in] id : identificateur de la clef
/// \param[in] fileSign : fichier contenant la signature
void signtext_interprete(utilisateur_t u, char *fileIn, int id, char* fileOut){
  //faut verifier si la clef existe
  int i = 0;
  while (i < u.nb_keys && id != u.list_key[i].id) {
    i++;
  }
  if (i >= u.nb_keys){
    printf("L'id n'existe pas\n");
    return;
  }
  if (strcmp(u.list_key[i].type, "Signature")) {
    printf("La clef doit etre de type Signature\n");
    return;
  }
  printf("avant jerem\n");
  printf("clef privée : (%lu, %lu)\n", u.list_key[i].keys.privKey.E, u.list_key[i].keys.privKey.N);
  signText(fileIn, fileOut, u.list_key[i].keys.privKey);
  printf("apres jerem\n");
}

/// \brief vérifie une signature avec une clef publique de l'utilisateur
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] fileIn : fichier d'entrée
/// \param[in] fileSign : fichier contenant la signature
/// \param[in] id : identificateur de la clef
void verifysign_interprete(utilisateur_t u, char *fileIn, char* fileSign, int id, char idContact[NAME_MAX_SIZE]){
  if (strcmp(idContact, "")) {
    //y'a idContact
    int iC = 0;
    while (iC < u.nb_contacts && strcmp(idContact ,u.repertoire[iC].identificateur)) {
      iC++;
    }
    if (iC >= u.nb_contacts){
      printf("L'identificateur du contact recherché n'existe pas\n");
      return;
    }
    int i = 0;
    while (i < u.repertoire[iC].nb_keys && id != u.repertoire[iC].list_key[i].id) {
      i++;
    }
    if (i >= u.repertoire[iC].nb_keys){
      printf("L'identificateur de la clef recherché n'existe pas\n");
      return;
    }
    if (strcmp(u.repertoire[iC].list_key[i].type, "Signature")) {
      printf("La clef doit etre de type Signature\n");
      return;
    }
    bool result = verifyText(fileIn, fileSign, u.repertoire[iC].list_key[i].keys.pubKey);
    if (result){
      printf("Le document est correct\n");
    }
    else{
      printf("Le document a été modifié\n");
    }
  }
  else{
    //y'a pas idContact
    int i = 0;
    while (i < u.nb_keys && id != u.list_key[i].id) {
      i++;
    }
    if (i >= u.nb_keys){
      printf("L'id n'existe pas\n");
      return;
    }
    if (strcmp(u.list_key[i].type, "Signature")) {
      printf("La clef doit etre de type Signature\n");
      return;
    }
    bool result = verifyText(fileIn, fileSign, u.list_key[i].keys.pubKey);
    if (result){
      printf("Le document est correct\n");
    }
    else{
      printf("Le document a été modifié\n");
    }
  }
}

/// \brief envoie une requête à l'autorité de certification
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] id : identificateur de la clef
void certify(utilisateur_t u, int id){
    //Type CCK -> certify crypt
    //Type CSK -> certify sign
  int i = 0;
  while (i < u.nb_keys && id != u.list_key[i].id) {
    i++;
  }
  if (id == u.list_key[i].id){
    char mail[COMMENTAIRE_SIZE];
    if (strcmp(u.list_key[i].type, "Signature")){
      printf("Quel est votre mail ?\n");
      scanf("%s", mail);
      printf("mail : %s\n", mail);
      requestBlockChain("TxEnAttente", "CSK", mail, u.list_key[i].keys.pubKey, u.list_key[i].keys.privKey);
    }
    else{
      printf("Quel est votre mail ?\n");
      scanf("%s", mail);
      printf("mail : %s\n", mail);
      requestBlockChain("TxEnAttente", "CCK", mail, u.list_key[i].keys.pubKey, u.list_key[i].keys.privKey);
    }
    return;

  }
  printf("L'id n'exsite pas\n");
}

/// \brief envoie une requête à l'autorité de révocation
/// \param[in] u : structure de données de l'utilisateur
/// \param[in] id : identificateur de la clef
void revoke_interpreteur(utilisateur_t u, int id){
    //Type RCK -> revoke crypt
    //Type RSK -> revoke sign
  int i = 0;
  while (i < u.nb_keys && id != u.list_key[i].id) {
    i++;
  }
  if (id == u.list_key[i].id){
    char* mail;
    if (strcmp(u.list_key[i].type, "Signature")){
      printf("Quel est votre mail ?\n");
      scanf("%s", mail);
      requestBlockChain("TxEnAttente", "RSK", mail, u.list_key[i].keys.pubKey, u.list_key[i].keys.privKey);
    }
    else{
      printf("Quel est votre mail ?\n");
      scanf("%s", mail);
      requestBlockChain("TxEnAttente", "RCK", mail, u.list_key[i].keys.pubKey, u.list_key[i].keys.privKey);
    }
    return;
  }
  printf("L'id n'existe pas\n");
}
/// \brief appelle les fonctions précédentes en fonction de ce que l'utilisateur tape, vérifie le format de ce qui est tapé
/// \param[in] u : structure de données de l'utilisateur
void balises(utilisateur_t* user){
  // printf("[balises] debut\n");
  char entree[100];
  char fonction[100];
  char arg1[100];
  char arg2[100];
  char arg3[100];
  int idClef;
  char idContact[NAME_MAX_SIZE];
  //logfp = fopen("poubelle.txt", "w+");
  //clean_stdin();
  fgets(entree, sizeof(entree), stdin);
  int i=0;
  int i_arg;
  arg1[0] = '\0';
  arg2[0] = '\0';
  arg3[0] = '\0';
  while (entree[i] != '\0' && entree[i] != ' ' && entree[i] != '\n') {
    fonction[i] = entree[i];
    i++;
  }
  fonction[i] = '\0';
  //printf("fonction : %s\n", fonction);

  if (entree[i] == ' '){
    i++;
    i_arg =0;
    while (entree[i] != '\0' && entree[i] != ' ' && entree[i] != '\n') {
      arg1[i_arg] = entree[i];
      i++;
      i_arg++;
    }
    arg1[i_arg] = '\0';
    //printf("arg1 : %s\n", arg1);

    if (entree[i] == ' '){
      i++;
      i_arg=0;
      while (entree[i] != '\0' && entree[i] != ' ' && entree[i] != '\n') {
        arg2[i_arg] = entree[i];
        i++;
        i_arg++;
      }
      arg2[i_arg] = '\0';
      //printf("arg2 : %s\n", arg2);

      if (entree[i] == ' '){
        i++;
        i_arg=0;
        while (entree[i] != '\0' && entree[i] != ' ' && entree[i] != '\n') {
          arg3[i_arg] = entree[i];
          i++;
          i_arg++;
        }
        arg3[i_arg] = '\0';
        //printf("arg3 : %s\n", arg3);
      }
    }
  }

  //quit
  if (!strcmp("quit",fonction)){
    quit();
  }

  //listkeys
  if (!strcmp("listkeys", fonction)){
    if (extraire(arg1, idContact, &idClef)) {
      //printf("[Balises] cas 1\n");
      printf("Usage : listkeys [<idcontact/idclef>]\n");
      return;
    }

    if (strcmp(arg2 , "") || strcmp(arg3, "")){
      printf("Usage : listkeys [<idcontact/idclef>]\n");
      return;
    }
    listkeys(*user, idClef, idContact);
    printf("Done.\n");
    return;
  }

  //rmkeys
  if (!strcmp("rmkeys", fonction)){
    if (extraire(arg1, idContact, &idClef)) {
      printf("Usage : rmkeys <idcontact/idclef> \n");
      return;
    }

    if (strcmp(arg2 , "")|| strcmp(arg3, "") || !strcmp(arg1, "")){
      printf("Usage : rmkeys <idcontact/idclef> \n");
      return;
    }
    rmkeys(user, idClef, idContact);
    printf("Done.\n");
    return;
  }

  //newkeys
  //remettre la verification de si c'est un nombre
  //faut verifier que le nombre est >0
  if (!strcmp("newkeys", fonction)){
    char* end;
    long nombre;
    nombre = strtol(arg1, &end, 10);
    if (strcmp(end, "") || nombre < 0 || strcmp(arg3, "") || !strcmp(arg1, "") || (strcmp(arg2, "Chiffrement") && strcmp(arg2, "Signature"))){
      printf("Usage : newkeys <id> <type> \n");
      return;
    }
    newkeys(user, nombre, arg2);
    printf("Done.\n");
    return;
  }

  //crypt
  if (!strcmp("crypt", fonction)){
    if (extraire(arg3, idContact, &idClef)) {
      printf("Usage : crypt <fileIn> <fileOut> <idcontact/idclef>\n");
      return;
    }

    if (!strcmp(arg2 , "") || !strcmp(arg3, "") || !strcmp(arg1, "") ){
      printf("Usage : crypt <fileIn> <fileOut> <idcontact/idclef> \n");
      return;
    }
    crypte(*user,arg1,arg2,idClef ,idContact);
    printf("Done.\n");
    return;
  }

  //uncrypt
  if (!strcmp("uncrypt", fonction)){
    char* end;
    long nombre;
    nombre = strtol(arg3, &end, 10);
    if (strcmp(end, "") || !strcmp(arg2 , "") || !strcmp(arg3, "") || !strcmp(arg1, "") ){
      printf("Usage : uncrypt <fileIn> <fileOut> <id> \n");
      return;
    }
    uncrypt(*user,arg1, arg2, nombre);
    printf("Done.\n");
    return;
  }

  //save
  if (!strcmp("save", fonction)){
    if (strcmp(arg2 , "")|| strcmp(arg3, "")){
      printf("Usage : save [<fileout>]\n");
      return;
    }
    if (!strcmp(arg1, "")){
      save(*user, FILEOUTDEFAULT);
      printf("Done.\n");
      return;
    }
    save(*user, arg1);
    printf("Done.\n");
    return;
  }

  //savepub
  if (!strcmp("savepub", fonction)){
    char* end;
    long nombre;
    nombre = strtol(arg1, &end, 10);
    if (strcmp(end, "") || !strcmp(arg2, "") || strcmp(arg3, "") || !strcmp(arg1, "")){
      printf("Usage : savepub <id> <file> \n");
      return;
    }
    savepub(*user, nombre, arg2);
    printf("Done.\n");
    return;
  }

  //load
  if (!strcmp("load", fonction)){
    if (strcmp(arg2 , "") || strcmp(arg3, "")){
      printf("Usage : load [<fileout>]\n");
      return;
    }
    if (!strcmp(arg1, "")){
      load(user, FILEOUTDEFAULT);
      printf("Done.\n");
      return;
    }
    load(user,arg1);
    printf("Done.\n");
    return;
  }

  //show
  if (!strcmp("show", fonction)){
    if (extraire(arg1, idContact, &idClef)) {
      printf("Usage : show <idcontact/idclef> [”pub”] [”priv”]\n");
      return;
    }
    if ( !strcmp(arg1, "")){
      printf("Usage : show <idcontact/idclef> [”pub”] [”priv”] \n");
      return;
    }

    int pub = 0;
    int priv = 0;
    if (!strcmp(arg2, "pub")){
      pub = 1;
    }
    if (!strcmp(arg2, "priv") || !strcmp(arg3, "priv")){
      priv = 1;
    }
    show(*user, idClef, priv, pub, idContact);
    printf("Done.\n");
    return;
  }
  //help
  if (!strcmp("help", fonction)) {
    help();
    return;
  }

  //listcontact
  if (!strcmp("listcontact", fonction)) {
    if (strcmp(arg3, "")){
      printf("Usage : listcontacts [<idcontact>] [<nom>] \n");
      return;
    }
    listcontact(*user, arg1, arg2);
    printf("Done.\n");
    return;
  }

  //addcontact
  if (!strcmp("addcontact", fonction)) {
    if (strcmp(arg3, "") || strcmp(arg2, "") || !strcmp(arg1, "")){
      printf("Usage : addcontact <idContact> \n");
      return;
    }
    addcontact(user, arg1);
    printf("Done.\n");
    return;
  }

  //rmcontact
  if (!strcmp("rmcontact", fonction)) {
    if (strcmp(arg3, "") || strcmp(arg2, "") || !strcmp(arg1, "")){
      printf("Usage : rmcontact <idContact> \n");
      return;
    }
    rmcontact(user, arg1);
    printf("Done.\n");
    return;
  }

  //modifycontact
  if (!strcmp("modifycontact", fonction)) {
    if (strcmp(arg3, "") || strcmp(arg2, "") || !strcmp(arg1, "")){
      printf("Usage : modifycontact <idContact> \n");
      return;
    }
    modifycontact(user, arg1);
    printf("Done.\n");
    return;
  }

  //addkeys
  if (!strcmp("addkeys", fonction)) {
    if (strcmp(arg3, "") || strcmp(arg2, "") || !strcmp(arg1, "")){
      printf("Usage : addkeys <idContact> ou <nom> \n");
      return;
    }
    addkeys(user, arg1);
    printf("Done.\n");
    return;
  }

  //signtext
  if (!strcmp("signtext", fonction)) {
    char* end;
    long nombre;
    nombre = strtol(arg2, &end, 10);
    if (strcmp(end, "") || !strcmp(arg3, "") || !strcmp(arg2, "") || !strcmp(arg1, "")){
      printf("Usage : signtext <filein> <id> <fileout> \n");
      return;
    }
    // printf("[balises] fonction : %s\n", fonction);
    // printf("[balises] arg1 : %s\n", arg1);
    // printf("[balises] arg2 : %s\n", arg2);
    // printf("[balises] nombre : %d\n", nombre);
    // printf("[balises] arg3 : %s\n", arg3);
    signtext_interprete(*user, arg1, nombre, arg3);
    printf("Done.\n");
    return;
  }

  //verifysign
  if (!strcmp("verifysign", fonction)) {
    if (extraire(arg3, idContact, &idClef)) {
      printf("Usage : verifysign <filein> <filesign> <idContact/idClef>\n");
      return;
    }
    if (!strcmp(arg3, "") || !strcmp(arg2, "") || !strcmp(arg1, "")){
      printf("Usage : verifysign <filein> <filesign> <idContact/idClef>\n");
      return;
    }
    verifysign_interprete(*user, arg1, arg2, idClef, idContact);
    printf("Done.\n");
    return;
  }

  //certify
  if (!strcmp("certify", fonction)) {
    char* end;
    long nombre;
    nombre = strtol(arg1, &end, 10);
    if (strcmp(end, "") || strcmp(arg3, "") || strcmp(arg2, "") || !strcmp(arg1, "")){
      printf("Usage : certify <id>\n");
      return;
    }
    certify(*user, nombre);
    printf("Done.\n");
    return;
  }

  //revoke
  if (!strcmp("revoke", fonction)) {
    char* end;
    long nombre;
    nombre = strtol(arg1, &end, 10);
    if (strcmp(end, "") || strcmp(arg3, "") || strcmp(arg2, "") || !strcmp(arg1, "")){
      printf("Usage : revoke <id>\n");
      return;
    }
    revoke_interpreteur(*user, nombre);
    printf("Done.\n");
    return;
  }

  //fin
  if (strcmp(fonction, "")) {
    printf("Veuillez réessayer.\n");
  }
}
