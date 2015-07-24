#ifndef SECURITY_H_1234
#define SECURITY_H_1234

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>


#define SYM_CIPHER EVP_aes_128_cbc() //symmetric cipher used
#define KEY_LENGTH EVP_CIPHER_key_length(SYM_CIPHER) //cipher key length
#define HASH EVP_sha1() //hash algorithm used
#define DIGEST_LEN EVP_MD_size(HASH) //digest length

EVP_PKEY * load_keys(char * username, int mode);
unsigned char * key_establishment_client(int socket_server, EVP_PKEY * pkey_server, EVP_PKEY * priv_key);
unsigned char * key_establishment_server(int socket_client, EVP_PKEY * pkey_client, EVP_PKEY * priv_key);
unsigned char * symmetric_encrypt(char * source, int source_len, int * cipher_len, unsigned char * key, int mode);
void symmetric_decrypt(unsigned char * source, char * destination, int cipher_len, int * plain_len, unsigned char * key, int mode);
void sha1_hash (unsigned char * destination, char * source, int source_len);
unsigned char * signature(char * input, int in_len, int * sgnt_size, EVP_PKEY * priv_key);
void verify_signature(unsigned char * sgnt, int sgnt_size, char * msg, int msg_len, EVP_PKEY * pub_key);
unsigned char * key_generation();

#endif /* SECURITY_H_1234 */
