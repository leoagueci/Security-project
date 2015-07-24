#include "security.h"
#include "utility.h"

EVP_PKEY * load_keys(char * username, int mode){ //mode 0: load private key, mode 1: load public key

	FILE * fp;
	EVP_PKEY * key;
	char * concat = NULL;

	/* prepare the path of the key file */
	concat = (char *)malloc(25 + strlen(username));
	strcpy(concat, "./keys/");
	concat = strcat(concat, username);
	if(mode == 0){

		concat = strcat(concat, "/rsa_privkey.pem");
	}
	else{

		concat = strcat(concat, "/rsa_pubkey.pem");		
	}

	/* opening pem file */
	fp = fopen(concat, "r");
	if( fp == NULL ){

		return NULL;
	}

	/* read the key */
	if(mode == 0){

		key = PEM_read_PrivateKey(fp, NULL, NULL,NULL);
	}
	else{

		key = PEM_read_PUBKEY(fp, NULL, NULL,NULL);
	}
	if(key == NULL){

		exit(EXIT_FAILURE);
	}
	
	fclose(fp);
	free(concat);

	return key;
}

unsigned char * key_generation(){ //generate a new random key for bit commitment

	unsigned char * key;
	int key_size;

	key_size = KEY_LENGTH;

	key = (unsigned char *)malloc(key_size);
	
	RAND_seed(key, key_size);//adds entropy to the PRNG

	/* Key generation */
	RAND_bytes(key, key_size);

	return key;
}

void sha1_hash (unsigned char * destination, char * source, int source_len){

	EVP_MD_CTX * ctx; //hashing context
	int ret;

	/* context creation */
	ctx = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
	EVP_MD_CTX_init(ctx); //initializes digest context ctx

    /* hashing */
    EVP_DigestInit(ctx, HASH); //sets up digest context ctx to use a digest type obtained by the function EVP_sha1()
	EVP_DigestUpdate(ctx, source, source_len); //hashes dim_buf bytes of data at buffer into the digest context ctx
	EVP_DigestFinal(ctx, destination, (unsigned int *)&ret); //retrieves the digest value from ctx and places it in digest. The number of bytes of data written (i.e. the length of the digest) will be written in ret

	/* context destruction */
	EVP_MD_CTX_cleanup(ctx); //cleans up digest context ctx
	free(ctx);
}

unsigned char * symmetric_encrypt(char * source, int source_len, int * cipher_len, unsigned char * key, int mode){ //mode 0: result -- {source,H(source)}key
																												   //mode 1: result -- {source}key
	unsigned char * ciphertext = NULL;
	unsigned char * plaintext = NULL;
	int block_size;
	int plain_len;
	int outlen; //amount of bytes encrypted at each step
	EVP_CIPHER_CTX * ctx;

	plain_len = (mode == 0) ? source_len + DIGEST_LEN : source_len;
	plaintext = (unsigned char *)malloc(plain_len);
	memcpy((void *)plaintext, (void *)source, source_len);

	if(mode == 0){

		sha1_hash(plaintext + source_len, source, source_len);
	}
	
	block_size = EVP_CIPHER_block_size(SYM_CIPHER); //16 bytes
	
	/* Context allocation and initialization */
	ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);

	/* Context setup for encryption */
	EVP_EncryptInit(ctx, SYM_CIPHER, key, NULL);

	/* Buffer allocation for the ciphertext */
	ciphertext = (unsigned char*)malloc(plain_len + block_size);

	/* Encryption (one step only) */
	outlen = 0;
	*cipher_len = 0;
	
	EVP_EncryptUpdate(ctx, ciphertext, &outlen, (unsigned char*)plaintext, plain_len);
	*cipher_len += outlen;
	
	EVP_EncryptFinal(ctx, ciphertext + *cipher_len, &outlen);
	*cipher_len += outlen;

	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
	free(plaintext);

	return ciphertext;
}

void symmetric_decrypt(unsigned char * source, char * destination, int cipher_len, int * plain_len, unsigned char * key, int mode){ //mode 0: decrypt and verify hash, mode 1: decrypt without hash verification

	EVP_CIPHER_CTX* ctx;
	unsigned char * plaintext;
	int outlen, outlen_tot;
	unsigned char * hash = NULL;
	int dest_len;
	int ret;

	/* Context allocation and initialization */
	ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);

	plaintext = (unsigned char *)malloc(cipher_len);//alloco per dimensione ciphertext

	/* Decryption context initialization */
	EVP_CIPHER_CTX_init(ctx);
	EVP_DecryptInit(ctx, SYM_CIPHER, key, NULL);

	/* Decryption (one step only) */
	outlen = 0;
	outlen_tot = 0;

	EVP_DecryptUpdate(ctx, plaintext, &outlen, source, cipher_len);
	outlen_tot += outlen;

	ret = EVP_DecryptFinal(ctx, plaintext + outlen_tot, &outlen);
	if(ret == 0){
		
		printf("ERROR in decrypting.\n");
		exit(EXIT_FAILURE);
	}
	outlen_tot += outlen;
	*plain_len = outlen_tot;

	dest_len = (mode == 0) ? outlen_tot - DIGEST_LEN : outlen_tot;
	memcpy(destination, plaintext, dest_len);
	
	if(mode == 0){

		hash = (unsigned char *)malloc(DIGEST_LEN);
		sha1_hash(hash, destination, dest_len); //compute the hash

		/* verify the hash */	
		if(CRYPTO_memcmp(hash, plaintext + dest_len, DIGEST_LEN) != 0){

			printf("Messaggio corrotto!\n");
    		exit(EXIT_FAILURE);
		}

		free(hash);
	}

	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
	free(plaintext);
}

unsigned char * signature(char * input, int in_len, int * sgnt_size, EVP_PKEY * priv_key){

	EVP_MD_CTX * ctx;
	unsigned char * sgnt;
	int res;

	/* allocate the context for the signature */
	ctx = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
	EVP_MD_CTX_init(ctx);
	sgnt = (unsigned char *)malloc (EVP_PKEY_size(priv_key));

	/* create signature context */
	res = EVP_SignInit(ctx, HASH);
	if(res == 0){

		exit(EXIT_FAILURE);
	}

	/* Signing process */
	res = EVP_SignUpdate(ctx, input, (unsigned int)in_len);
	if(res == 0){

		exit(EXIT_FAILURE);
	}
	res = EVP_SignFinal(ctx, sgnt, (unsigned int *)sgnt_size, priv_key);
	if(res == 0){

		exit(EXIT_FAILURE);
	}

	EVP_MD_CTX_cleanup(ctx);
	free(ctx);

	return sgnt;
 }

void verify_signature(unsigned char * sgnt, int sgnt_size, char * msg, int msg_len, EVP_PKEY * pub_key){

	EVP_MD_CTX * ctx;
	int ret;

	/* allocate signature context */
	ctx = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
	EVP_MD_CTX_init(ctx);
	ret = EVP_VerifyInit(ctx, HASH);
	if(ret == 0){

		exit(EXIT_FAILURE);
	}

	/* verify signature */
	ret = EVP_VerifyUpdate(ctx, msg, (unsigned int)msg_len);
	if(ret == 0){

		exit(EXIT_FAILURE);
	}

	ret = EVP_VerifyFinal(ctx, sgnt, (unsigned int)sgnt_size, pub_key);	
	if(ret == 0){

		printf("Invalid signature!\n");
		exit(EXIT_FAILURE);
	}
	else if (ret < 0){

		exit(EXIT_FAILURE);
	}

	EVP_MD_CTX_cleanup(ctx);
	free(ctx);
}

unsigned char * key_establishment_client(int socket_server, EVP_PKEY * pkey_server, EVP_PKEY * priv_key){

	BIGNUM * server_pub;
	DH * dh;
	int len, ret, codes, len1, len2; //len1: yc length, len2: ys length
	unsigned char * buffer; //temp buffer for the msgs
	unsigned char * shared_secret;
	unsigned char * key;
	unsigned char * sgnt; //signature
	unsigned char * yc; //g^(client_secret) mod p
	unsigned char * ys; //g^(server_secret) mod p
	int sgnt_size;
	char * concat;

	/* allocate bignums */
	server_pub = BN_new();
	dh = DH_new();
	dh->p = BN_new();
	dh->g = BN_new();

	/* receive p */
	len = recv_len(socket_server);
	buffer = (unsigned char *)malloc(len);
	recv_msg(socket_server, buffer, len);
	BN_bin2bn((const unsigned char *)buffer, len, dh->p);

	/* receive g */
	len = recv_len(socket_server);
	buffer = (unsigned char *)realloc(buffer, len);
	recv_msg(socket_server, buffer, len);
	BN_bin2bn((const unsigned char *)buffer, len, dh->g);

	/* check parameters */
	ret = DH_check(dh, &codes);
	if(codes != 0){

		printf("Not valid p and g!\n");
		exit(EXIT_FAILURE);
	}

	/* generate own public key */
	ret = DH_generate_key(dh);
	if(ret != 1){

		printf("Public/Private keys not generated\n");
		exit(EXIT_FAILURE);
	}

	/* receive other public key */
	len2 = recv_len(socket_server);
	ys = (unsigned char *)malloc(len2);
	recv_msg(socket_server, ys, len2);
	BN_bin2bn((const unsigned char *)ys, len2, server_pub);

	/* allocate buffer for bignum conversions */
	len1 = BN_num_bytes(dh->pub_key);
	yc = (unsigned char *)malloc(len1);
	len1 = BN_bn2bin((const BIGNUM *)dh->pub_key, yc);
	
	/* send my public key */
	send_len(socket_server, len1);
	send_msg(socket_server, (void *)yc, len1);

	/* compute the shared secret */
	len = DH_size(dh);
	shared_secret = (unsigned char *) malloc(len);
	DH_compute_key(shared_secret, server_pub, dh);

	/* allocation for the session key */
	key = (unsigned char *)malloc(KEY_LENGTH);
	memcpy(key, shared_secret, 16); //128 bits = 16 bytes

	/* prepare the string to sign */
	concat = (char *)malloc(len1 + len2); //my public key, other public key
	memcpy(concat, yc, len1);
	memcpy(concat + len1, ys, len2);

	/* sign and the string */
	sgnt = signature(concat, len1 + len2, &sgnt_size, priv_key);
	
	/* send my signature */
	send_len(socket_server, sgnt_size);
	send_msg(socket_server, sgnt, sgnt_size);

	/* receive other signature */
	sgnt_size = recv_len(socket_server);
	sgnt = (unsigned char *)realloc(sgnt, sgnt_size);
	recv_msg(socket_server, sgnt, sgnt_size);

	/* verify signature */
	verify_signature(sgnt, sgnt_size , concat, len1 + len2, pkey_server);

	free(buffer);
	BN_free(server_pub);
	DH_free(dh);
	free(concat);
	free(shared_secret);
	free(yc);
	free(ys);
	free(sgnt);

	return key;
}

unsigned char * key_establishment_server(int socket_client, EVP_PKEY * pkey_client, EVP_PKEY * priv_key){
	
	BIGNUM * client_pub;
	DH * dh;
	unsigned char * buffer;
	unsigned char * sgnt;
	unsigned char * shared_secret;
	unsigned char * key;
	unsigned char * ys;
	unsigned char * yc;
	char * concat;
	int sgnt_size;
	int len, len1, len2;
	int ret;

	/* allocate bignums */
	client_pub = BN_new();

	/* allocate structure and generate p and g */
    dh = DH_generate_parameters(512, DH_GENERATOR_5, NULL, NULL);

    /* send p */
    len = BN_num_bytes(dh->p);
    send_len(socket_client, len);

	buffer = (unsigned char *)malloc(len); //buffer for bignum conversion
	BN_bn2bin((const BIGNUM *)dh->p, buffer);
	send_msg(socket_client, (void *)buffer, len);

	/* send g */
	len = BN_num_bytes(dh->g);
	send_len(socket_client, len);

	buffer = (unsigned char *)realloc(buffer, len); //buffer for bignum conversion
	BN_bn2bin((const BIGNUM *)dh->g, buffer);
	send_msg(socket_client, (void *)buffer, len);

	/* generate public keys */
	ret = DH_generate_key(dh);
	if(ret != 1){

		printf("Public/Private keys not generated\n");
		exit(EXIT_FAILURE);
	}

	/* conversion of the bignum into bin */
	len2 = BN_num_bytes(dh->pub_key); 
	ys = (unsigned char *)malloc(len2);
	len2 = BN_bn2bin((const BIGNUM *)dh->pub_key, ys);

	/* send my public key */
	send_len(socket_client, len2);
	send_msg(socket_client, (void *)ys, len2);

	/* receive other public key */
	len1 = recv_len(socket_client);
	yc = (unsigned char *)malloc(len1);
	recv_msg(socket_client, yc, len1);
	BN_bin2bn((const unsigned char *)yc, len1, client_pub);
	
	/* compute the shared secret */
	len = DH_size(dh);
	shared_secret = (unsigned char *) malloc(len);
	DH_compute_key(shared_secret, client_pub, dh);

	/* take the session key */
	key = (unsigned char *)malloc(KEY_LENGTH);
	memcpy(key, shared_secret, 16); //128 bits = 16 bytes

	/* receive signature from client */
	sgnt_size = recv_len(socket_client);
	sgnt = (unsigned char *)malloc(sgnt_size);
	recv_msg(socket_client, sgnt, sgnt_size);

	/* verify the client signature */
	concat = (char *)malloc(len1 + len2);
	memcpy(concat, yc, len1);
	memcpy(concat + len1, ys, len2);
	verify_signature(sgnt, sgnt_size , concat, len1 + len2, pkey_client);
	free(sgnt);
	
	/* sign msg */
	sgnt = signature(concat, len1 + len2, &sgnt_size, priv_key);

	/* send my signature */
	send_len(socket_client, sgnt_size); //length of encrypted signature
	send_msg(socket_client, sgnt, sgnt_size);

	BN_free(client_pub);
	DH_free(dh);
	free(buffer);
	free(sgnt);
	free(concat);
	free(shared_secret);
	free(ys);
	free(yc);

	return key;	
}
