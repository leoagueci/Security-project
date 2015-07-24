#include "security.h"
#include "utility.h"

#include <unistd.h>

void handle_combination (int * combination){ //manage the combination inserted by the user

	int i = 0, ret, res;

	memset(combination,0,10 * sizeof(int));

	printf("Insert combination (five numbers between 1 and 10)\n");
	while(i < 5){

		printf("%d° number: ", i + 1);
		while (getchar()!='\n') ; //empty keyboard buffer
		res = scanf("%d", &ret); 
		if(res != 1){
			
			printf("Not a number!\n");
		}
		else if(ret < 1 || ret > 10){

			printf("Number not valid!\n");
		}
		else{

			if(combination[ret - 1] == 0){

				combination[ret - 1] = 1;
				i++;
			}
			else{

				printf("Number already inserted!\n");
			}
		}	
	}

	printf("Combination: ");
	print_combination(combination);
}

int main(){

	struct sockaddr_in srv_addr;
	char username [100];
	char password [100];
	int combination [10];
	int w_combination [10];
	int sk, ret, res;
	double prize; //money won
	unsigned char * en_combination = NULL; //encrypted combination
	unsigned char * session_key;
	unsigned char * bc_key = NULL; //bit commitment key
	unsigned char * w4l1, * w4l2, * w4l3, * w4l4; //buffers for the protocol msgs
	int w4l1_len, w4l2_len, w4l3_len, w4l4_len;
	EVP_PKEY * s_pub_key, * priv_key; //public and private key
	unsigned char * en_pass = NULL; //encrypted password
	int cipher_len;
	char * msg; //temp variable
	int msg_len;
	int extraction_id; //identificator of the extraction
	unsigned char * sgnt;
	int sgnt_size;

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET; // IPv6
	srv_addr.sin_port = htons(4444);
	inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);

	sk = socket(AF_INET, SOCK_STREAM, 0);
	ret = connect(sk, (struct sockaddr*) &srv_addr, sizeof(srv_addr));
	if(ret < 0){ // connection error

		printf("Connection error\n");
		exit(EXIT_FAILURE);
	}

	/* take server public key */
	s_pub_key = load_keys("server", 1);
	if(s_pub_key == NULL){

		printf("Server key not found. Download it!\n");
		exit(EXIT_FAILURE);
	}

	session_key = NULL;
	res = 1;
	while(res != 0){

		printf("Insert your username : ");
		ret = scanf("%s", username);

		printf("Insert your password : ");
		ret = scanf("%s", password);

		/* send name */
		send_len(sk, strlen(username));
		send_msg(sk, (void*)username, strlen(username) + 1);

		/* take my private key */
		priv_key = load_keys(username, 0);
		if(priv_key == NULL){

			printf("Key not found!\n");
		}
		else{

			session_key = key_establishment_client(sk, s_pub_key, priv_key);

			/* encrypt password */
			en_pass = symmetric_encrypt(password, strlen(password), &cipher_len, session_key, 1);

			/* send encrypted password */
			send_len(sk, cipher_len);
			send_msg(sk, (void*)en_pass, cipher_len);
		
			/* receive acknowledgement */
			recv_msg(sk, (void *)&res, sizeof(int));
		
			if(res == 1){

		    	printf("Username already connected!\n");
		    }
		    else if(res == 2){

		    	printf("Username or password not valid!\n");
		    }
		}
	}
	
	/* S-->C W4L1: {extraction_id, w_combination, H(extraction_id||w_combination)}Kbc, extraction_id */
	w4l1_len = recv_len(sk);
	w4l1 = (unsigned char *)malloc(w4l1_len);
	recv_msg(sk, (void *)w4l1, w4l1_len);
	recv_msg(sk,(void *)&extraction_id, sizeof(int));
    
	handle_combination(combination);

	/* prepare W4L2: {extraction_id, combination, Sc(extraction_id || combination)}session_key */
	msg_len = 11 * sizeof(int);
	msg = (char *)malloc(msg_len);
	memcpy(msg, &extraction_id, sizeof(int));
	memcpy(msg + sizeof(int), combination, 10 * sizeof(int));
	sgnt = signature(msg, msg_len, &sgnt_size, priv_key);
	msg_len += sgnt_size;
	msg = (char *)realloc(msg, msg_len);
	memcpy(msg + 11 * sizeof(int), sgnt, sgnt_size);
	
	/* C-->S W4L2: {extraction_id, combination, Sc(extraction_id || combination)}session_key */
	w4l2 = symmetric_encrypt(msg, msg_len, &w4l2_len, session_key, 1);
	send_len(sk, w4l2_len);
	send_msg(sk, (void *)w4l2, w4l2_len);
	
	/* S-->C W4L3: {extraction_id, combination, Ss(extraction_id||combination)}session_key */
	sgnt_size = recv_len(sk);
	w4l3_len = recv_len(sk);
	w4l3 = (unsigned char *)malloc(w4l3_len);
	recv_msg(sk, (void *)w4l3, w4l3_len);

	/* decrypt W4L3 */
	msg = (char *)realloc(msg, w4l3_len);
	symmetric_decrypt(w4l3, msg, w4l3_len, &msg_len, session_key, 1);
	verify_signature((unsigned char *)msg + 11 * sizeof(int), sgnt_size, msg, 11 * sizeof(int), s_pub_key);
	if(memcmp(&extraction_id, msg, sizeof(int)) != 0){

		printf("Extraction_id received is not valid!\n");
		exit(EXIT_FAILURE);
	}
	if(memcmp(combination, msg + sizeof(int), 10 * sizeof(int)) != 0){

		printf("Combination received is not valid!\n");
		exit(EXIT_FAILURE);
	}

	/* S-->C W4L4: {prize, extraction_id, bc_key, H(prize||extraction_id, bc_key)}session_key */
	w4l4_len = recv_len(sk);
	w4l4 = (unsigned char *)malloc(w4l4_len);
	recv_msg(sk, (void *)w4l4, w4l4_len);

	/* decrypt W4L4 */
	msg = (char *)realloc(msg, w4l4_len);
	bc_key = (unsigned char *)malloc(KEY_LENGTH);
	symmetric_decrypt(w4l4, msg, w4l4_len, &msg_len, session_key, 0);
	memcpy(&prize, msg, sizeof(double));
	memcpy(bc_key, msg + sizeof(double) + sizeof(int), KEY_LENGTH);
	if(memcmp(&extraction_id, msg + sizeof(double), sizeof(int)) != 0){

		printf("Extraction_id received is not valid!\n");
		exit(EXIT_FAILURE);
	}

    /* decrypt W4L1 */
    msg = (char *)realloc(msg, w4l1_len);
    symmetric_decrypt(w4l1, msg, w4l1_len, &msg_len, bc_key, 0);
    memcpy(w_combination, msg + sizeof(int), 10 * sizeof(int));
    if(memcmp(&extraction_id, msg, sizeof(int)) != 0){

		printf("Extraction_id received is not valid!\n");
		exit(EXIT_FAILURE);
	}
  
    printf("Extraction number %d --> ", extraction_id);
    printf("Winning ");
    print_combination(w_combination); //it must be equal to the one published by the server

    /* print the prize won */
    if(prize == 0){

    	printf("You lose!\n");
    }
    else{

    	printf("You win %.02f €!\n", prize);
    }

    free(msg);
    free(en_pass);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(s_pub_key);
    free(bc_key);
    free(en_combination);
	close(sk);	
	free(session_key);
	
	return 0;
}
