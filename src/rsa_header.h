/// \file rsa_header.h
/// \author Vincent Dugat
/// \date august 2019
#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include "Sha-256/sha256_utils.h"
#include <gmp.h>
#include <unistd.h>

#define MAX_U_INT 4294967296
#define MAX_U_INT64 18446744073709551616
#define OK 0
#define ERREUR -1
#define READ_ERROR -1
#define BLOCK_SIZE 4 // octets
#define BLOCK_BASE_64 12
#define NAME_MAX_SIZE 32 // caractères
#define MAX_STR 10 //
#define COMMENTAIRE_SIZE 250
#define REPERTOIRE_SIZE 100
#define FILEOUTDEFAULT "default.txt"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAXI(a,b) (((a)>(b))?(a):(b))

extern FILE * logfp;

typedef unsigned long int uint64;
typedef unsigned int uint; // même taille que int aka uint32
typedef unsigned char uchar; // 8 bits = octet aka uint8

/* Type of a block of data */
typedef uchar block_t[BLOCK_SIZE]; // une case par octet

typedef struct tabUint64_s{
	uint64 * uint64array;
	int dim;
} tabUint64_t;

typedef struct rsaKey_s {
	uint64 E;// exposant
	uint64 N;// modulo
} rsaKey_t;

// struct pour définir une paire de clefs
typedef struct keyPair_s {
	rsaKey_t pubKey; // (C,N)
	rsaKey_t privKey; //(U,N)
} keyPair_t;

typedef struct identificateur_s {
	int id;
	keyPair_t keys;
	char type[NAME_MAX_SIZE];
} identificateur_t;

typedef struct contact_s {
	char identificateur[NAME_MAX_SIZE];
	char nom[NAME_MAX_SIZE];
	char prenom[NAME_MAX_SIZE];
	char commentaire[COMMENTAIRE_SIZE];
	identificateur_t list_key[REPERTOIRE_SIZE];
	int nb_keys;
}contact_t;

typedef struct utilisateur_s {
	identificateur_t list_key[REPERTOIRE_SIZE];
	contact_t repertoire[REPERTOIRE_SIZE];
	int nb_keys;
	int nb_contacts;
} utilisateur_t;


// prototypes de sp
void erreur(char* msg); // pour afficher les msg d'erreurs

// phase 1
int decompose (uint facteur[], uint64 n) ; // reçoit n, remplit le tableau de facteurs premiers (realloc)
uint64 puissance_mod_n (uint64 a, uint64 e, uint64 n); // puissance modulaire
long bezoutRSA(uint64 a,uint64 b,long *u,long *v); // Bézout
void printKey(rsaKey_t key);
void printUint64Array(tabUint64_t tab);
void genKeysRabin(rsaKey_t *pubKey,rsaKey_t *privKey);

//phase 2
void RSAcrypt(unsigned char *msg, uint64 *cryptedMsg, rsaKey_t pKey);
void RSAdecrypt(unsigned char *msg, uint64 *cryptedMsg, rsaKey_t privKey);
uint convert_4byte2int(uchar *b);
void printBlock(block_t blk);
void convertInt2uchar(uint nb,uchar *tab4bytes);
char *base64_encode(const uchar *data,size_t input_length,size_t *output_length);
unsigned char *base64_decode(const char *data,size_t input_length,size_t *output_length);
void base64_cleanup();

// avec les blocs
uint64 RSAcrypt1BlockGmp(uint64 blockInt, rsaKey_t pubKey);
uint64 RSAdecrypt1BlockGmp(uint64 blockInt, rsaKey_t privKey);

// avec les fichiers
void RSAfile_crypt(char *inFilename,char *outFilename, rsaKey_t pubKey);
void RSAfile_decrypt(char *inFilename,char *outFilename,rsaKey_t privKey);
void RSAcryptFile(char *inFilename,
                    char *outFilename,
                    rsaKey_t pubKey,
                    int *output_length);
void RSAunCryptFile(char *inFilename,char *outFilename,rsaKey_t privKey, int length);

// signature
//tabUint64_t * signText(char *inFilename,rsaKey_t signKey);
void inputKey(uint64 E,uint64 N,rsaKey_t *key);
tabUint64_t * string2intBlocks(uchar *str);
uchar * num2string(tabUint64_t numArray);
uint64 * giveMeMem(int dim);
tabUint64_t * RSAcryptUint64(tabUint64_t numMsg,rsaKey_t pubKey);
tabUint64_t * RSAunCryptUint64(tabUint64_t numMsgC,rsaKey_t privKey);
void text2sha(char *inFilename,char shaStr[SHA256_BLOCK_SIZE*2 + 1]);
void signText(char *inFilename, char *outFilename, rsaKey_t signKey);
bool verifyText(char *sign, char *inFilename, rsaKey_t pubKey);
void uncryptSign(char *inFilename , char *sign, rsaKey_t pubKey);
void uncryptSignedText(char *inFilename , char *sign, char *outFilename, rsaKey_t pubKey, rsaKey_t privKey);
// GMP
void mersenneGmp(mpz_t resGmp,uint64 max,uint64 p); // ovni
void printKeyPair(keyPair_t keyPair);
char * verifySignText(char *inFilename,tabUint64_t cryptAr, rsaKey_t verifyKey);
void puissance_mod_n_gmp(mpz_t res,uint64 a, uint64 e, uint64 n); // puis mod avec gmp
// interpreteur de commandes
int extraire(char* chaine, char idContact[NAME_MAX_SIZE], int* idClef);
void init();
void quit();
void listkeys(utilisateur_t u, int id, char* idContact);
void rmkeys(utilisateur_t* u, int id, char* idContact);
void newkeys(utilisateur_t* u, int id, char type[NAME_MAX_SIZE]);
void save(utilisateur_t u, char* fileOut);
void load(utilisateur_t* u, char* fileIn);
void savepub(utilisateur_t u, int id, char* fileOut);
void crypte(utilisateur_t u, char* fileIn, char* fileOut, int id, char* idContact);
void uncrypt(utilisateur_t u, char* fileIn, char* fileOut, int id);
void show(utilisateur_t u, int id, int priv, int pub, char* idContact);
void listcontact(utilisateur_t u, char idContact_nom[NAME_MAX_SIZE], char nom[NAME_MAX_SIZE]);
void modifycontact(utilisateur_t *u, char idContact[NAME_MAX_SIZE]);
void addkeys(utilisateur_t *u, char idContact[NAME_MAX_SIZE]);
void rmcontact(utilisateur_t *u, char idContact[NAME_MAX_SIZE]);
void addcontact(utilisateur_t* u, char idContact[NAME_MAX_SIZE]);
void addkeys(utilisateur_t *u, char idContact_nom[NAME_MAX_SIZE]);
void signtext_interprete(utilisateur_t u, char *fileIn, int id, char* fileOut);
void verifysign_interprete(utilisateur_t u, char *fileIn, char* fileSign, int id, char idContact[NAME_MAX_SIZE]);
void certify(utilisateur_t u, int id);
void revoke_interpreteur(utilisateur_t u, int id);
void balises(utilisateur_t* user);
void mot_de_passe(char* filemdp);

/* Term canon VT100 ===================================	*/
/* deux fonctions pour passer du mode de communication	  */
/* canonique au mode non-canonique avec le terminal :	  */
/*  mode canonique : communication du terminal en mode	  */
/*    interactif, c-à-d : écho, les touches frappées   */
/*    au clavier sont affichées sur le terminal ; et	  */
/*    entrée par ligne : la lecture se fait lorsqu'une   */
/*    ligne complète est saisie (terminée par la touche */
/*    Entrée). 					  */
/*  mode non-canonique : l'écho est supprimé et la	  */
/*    lecture se fait caractère par caractère sans	  */
/*    attendre la fin de la ligne.			  */
/* 							  */
/*  Created on: 2017					  */
/* 	Author: C. Collet				  */
/*  Copyright 2017 IRIT-Université Toulouse 3   	  */
/*	Paul Sabatier, France. All rights reserved.	*/
/* ====================================================	*/


/* ANSI/VT100 term color and formatting from			*/
/* https://misc.flogisoft.com/bash/tip_colors_and_formatting	*/

/* Term_non_canonique =================================
//  Permet de lire le clavier touche par touche, sans
// écho.
//===================================================*/
int Term_non_canonique ();

/* Term_canonique =====================================
//  Mode normal du clavier: lecture par ligne et écho.
//===================================================*/
int Term_canonique ();
#endif
