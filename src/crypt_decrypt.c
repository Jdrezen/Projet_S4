#include "rsa_header.h"
/// \brief Fonctions de cryptage/decryptage avec des buffers
/// \file crypt_decrypt.c
/// \author Jérémie Drezen et Mylène Berce
/// \date 24 Janvier 2020

///\brief crypt un message dans un buffer
/// \param[in] msg : le buffer contenant le message à crypter
/// \param[in] cryptedMsg : le résultat du cryptage
/// \param[in] pubKey : la clé publique permettant de crypter le message
void RSAcrypt(unsigned char *msg, uint64 *cryptedMsg, rsaKey_t pubKey){

  for (int i = 0; i< strlen(msg); i++) {
    cryptedMsg[i] = puissance_mod_n(msg[i], pubKey.E, pubKey.N);
  }
}

///\brief decrypt un message dans un buffer
/// \param[in] msg : le buffer contenant le message à decrypter
/// \param[in] cryptedMsg : le résultat du decryptage
/// \param[in] pubKey : la clé privée permettant de decrypter le message
void RSAdecrypt(unsigned char *msg, uint64 *cryptedMsg, rsaKey_t privKey){

  for (int i = 0; i< 100; i++) {
    msg[i] = puissance_mod_n(cryptedMsg[i], privKey.E, privKey.N);
  }
}
