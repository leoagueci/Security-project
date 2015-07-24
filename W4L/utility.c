#include "utility.h"

void recv_msg(int sk, void * msg, int len){ //receive a msg from socket sk

	int ret;

	ret = recv(sk, msg, len, 0);
	if (ret != len){

	    printf("%s\n", strerror(errno));
	    exit(EXIT_FAILURE);
	}
}

int recv_len(int sk){ //receive a msg length from socket sk

	int ret;
	int len;

	ret = recv(sk, (void *)&len, sizeof(len), 0);
	if (ret != sizeof(len)){ //communication error

	  	printf("%s\n", strerror(errno));
       	exit(EXIT_FAILURE);
    }
	len = ntohl(len);

	return len;
}

void send_len(int sk, int len){ //send a length to socket sk

	int ret;

	ret = htonl(len);
	ret = send(sk, (void*) &ret, sizeof(int), 0);
	if(ret != sizeof(int)){ //communication error

		printf("Comunication error\n");
		exit(EXIT_FAILURE);
	}
}

void send_msg(int sk, void * msg, int len){ //send a msg to socket sk

	int ret;

	ret = send(sk, msg, len, 0);
	if(ret != len){ //communication error

		printf("Comunication error\n");
		exit(EXIT_FAILURE);
	}
}

void print_bytes(const unsigned char * buf, int len) {
	
	int i;

	for (i = 0; i < len - 1; i++){

		printf("%02X:", buf[i]);
	}

	printf("%02X", buf[len - 1]);
	printf("\n");
}

void print_combination(int * combination){

	int i;

	for(i = 0; i < 10; i++){

		if(combination[i] == 1){

			printf(" %d", i + 1);

		}
	}

	printf("\n");
}

int combcmp(int * combination1, int * combination2){

	int i, ret = 0;

	for (i = 0; i < 10; i++){

		if ((combination1[i] == combination2[i]) && (combination1[i] == 1)) {
			
			ret++;
		}
	}

	return ret; //number of equal numbers in the combinations
}
