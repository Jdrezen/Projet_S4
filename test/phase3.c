#include "../src/rsa_header.h"
FILE *logfp;

// ATTENTION, QUAND ON OUVRE UN FICHIER ON SUPPRIME AUTOMATIQUEMENT

int main(int argc, char* argv[]) {
  //Term_non_canonique();

  if (argc>1){
    logfp = fopen(argv[1],"w+");
    assert(logfp!=NULL);
  }
  else
    logfp = stdout;

  printf("\033[H\033[J");//effacement du terminal

  printf("Bienvenue dans l'interprète de commande\n\n");
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

  mot_de_passe("mot_de_passe.txt");

  utilisateur_t user;
  init(&user);

  // user.list_key[0].keys.pubKey.E = 23;
  // user.list_key[0].keys.pubKey.N = 8889895013;
  // user.list_key[0].keys.privKey.E = 3865086887;
  // user.list_key[0].keys.privKey.N = 8889895013;
  // user.list_key[0].id = 1;
  // strcpy(user.list_key[0].type, "Chiffrement");
  // user.nb_keys++;
  // listkeys(user, 1, "");

  newkeys(&user, 3, "Signature");
  // signtext_interprete(user, "a.txt", 3, "b.txt");
  while (true){
    balises(&user);
  }
  Term_canonique();
  return 0;
}
