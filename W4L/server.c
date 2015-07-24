#include "security.h"
#include "utility.h"

#include <unistd.h>
#include <time.h>

#define BACKLOG_SIZE 15
#define BET_DURATION 60
#define STARTING_POT 100
#define	RAISE 20


/* GLOBAL VARIABLES */
struct client{

	char name[100];	//client username
	char password[100];
	int combination [10]; //combination chosen from the client
	int socket;
	int w_pot1, w_pot2; //1 if win the pot, 0 otherwise
	EVP_PKEY * pub_key; //client public key
	unsigned char * session_key;
	struct client * next;
};

struct sockaddr_in server_addr, client_addr;
int lst_socket; //listening socket
struct client * clients = NULL; //list of connected clients
int num_client; //number of connected clients
int w_combination [10]; //winning combination
struct timeval time_out, * timer; //timer structures
unsigned char * w4l1, * w4l2, * w4l3, * w4l4; //msgs of the protocol
int w4l1_len, w4l2_len, w4l3_len, w4l4_len; //protocol msgs lengths
char * msg = NULL; //temp variable
int msg_len; //temp variable length
double pot; //amount of money
unsigned char * bc_key = NULL; //key for bit commitment
EVP_PKEY * s_priv_key; //server private key
int extraction_id = 0; //identificator of the current extraction

void reset_timer(){

	time_out.tv_sec = BET_DURATION; //duration of the game
    time_out.tv_usec = 0;
}

void generate_combination(){ //generate new winning combination

	int n, i = 0;

	memset(w_combination, 0, 10 * sizeof(int));

	srand(time(NULL));

	while(i < 5){

		n = rand() % 10;
		
		if(w_combination[n] == 0){

			w_combination[n] = 1;
			i++;
		}		
	}

	if(bc_key != NULL){

		free(bc_key);
	}
	bc_key = key_generation(); //generate bit commitment key

	extraction_id++;

	/* prepare W4L1 msg: {extraction_id, w_combination, H(extraction_id||w_combination)}bc_key */
	msg_len = 11 * sizeof(int);
	msg = (char *)malloc(msg_len);
	memcpy(msg, &extraction_id, sizeof(int));
	memcpy(msg + sizeof(int), w_combination, 10 * sizeof(int));
	w4l1 = symmetric_encrypt(msg, msg_len, &w4l1_len, bc_key, 0);
	free(msg);

	printf("Extraction number %d --> ", extraction_id);
	printf("Winning combination: ");	
	print_combination(w_combination);
}

void the_winner_is(){ //choose the winning clients
	
	struct client * tmp = NULL;
	int n_pot1 = 0, n_pot2 = 0;
	double w1, w2, w_send = 0;
	int ret;
	
	/* check winning clients in the list */
	tmp = clients;
	while(tmp != NULL){

		ret = combcmp(w_combination, tmp->combination);
		if(ret == 5){ //if guess 5 numbers win the pot number 1

			tmp->w_pot1 = 1;
			n_pot1++;
		}
		else if(ret == 4){ //if guess 4 numbers win the pot number 2

			tmp->w_pot2 = 1;
			n_pot2++;
		}

		tmp = tmp->next;
	}

	/* amount of money won by the winners */
	w1 = pot * 0.75 / n_pot1; //pot number 1: 75% of the pot
	w2 = pot * 0.25 / n_pot2; //pot number 2: 25% of the pot

	/* sends to each client the prize */
	tmp = clients;
	while(tmp != NULL){

		if(tmp->w_pot1 == 1){ //client won pot number 1

			w_send = w1;
			printf("%s guessed 5 numbers and he won %.02f €!\n", tmp->name, w1);
		}
		else if(tmp->w_pot2 == 1){ //client won pot number 2

			w_send = w2;
			printf("%s guessed 4 numbers and he won %.02f €!\n", tmp->name, w2);
		}
		else{ //client lose

			w_send = 0;
		}

		/* prepare W4L4: {prize, extraction_id, bc_key, H(prize||extraction_id||bc_key)}session_key */
		msg_len = sizeof(double) + sizeof(int) + KEY_LENGTH;
		msg = (char *)malloc(msg_len);
		memcpy(msg, &w_send, sizeof(double));
		memcpy(msg + sizeof(double), &extraction_id, sizeof(int));
		memcpy(msg + sizeof(double) + sizeof(int), bc_key, KEY_LENGTH);
		w4l4 = symmetric_encrypt(msg, msg_len, &w4l4_len, tmp->session_key, 0);
		free(msg);

		/* S-->C W4L4: {prize, extraction_id, bc_key, H(prize||extraction_id||bc_key)}session_key */
		send_len(tmp->socket, w4l4_len);
		send_msg(tmp->socket, (void *)w4l4, w4l4_len);

		/* delete clients from list */
		clients = tmp;
		tmp = tmp->next;
		EVP_PKEY_free(clients->pub_key);
		free(clients->session_key);
		free(clients);	
	}

	if(n_pot1 == 0 && n_pot2 == 0){ //if nobody won, raise the pot

		pot += RAISE;
		printf("Nobody won!\n");
	}
	else{ //if somebody won, restore the pot to the initial amount of money

		pot = STARTING_POT;
	}

	generate_combination(); //generate a new winning combination

	num_client = 0;
	clients = NULL;
}

int check_usernameandpass(char * name, char * password){ //check the username and the password

	struct client * tmp = NULL;
	char usr[100], pwd[100];
	int res, i;
	char app = '\0';
	FILE * f;

	/* Check if client is already connected */
	tmp = clients;
	while(tmp != NULL){

		if(strcmp(name, tmp->name) == 0){

			return 1; //already connected
		}

		tmp = tmp->next;
	}


	f = fopen("users.txt", "r");
	if(f == NULL) {

		perror("Error opening file");
		exit(EXIT_FAILURE);
	}

	/* Check if client is registered */
	while(!feof(f)){

		i = 0;
		res = fread(&app, 1, 1, f);
		if(res < 1){
			
			exit(EXIT_FAILURE);
		}
		while(app != '\t' && !feof(f)){

			usr[i++] = app;
	    	res = fread(&app, 1, 1, f);
	    }
	    usr[i] = '\0';

	    i = 0;
	    res = fread(&app, 1, 1, f);
	    if(res < 1){
			
			exit(EXIT_FAILURE);
		}
		while(app != '\n' && !feof(f)){

			pwd[i++] = app;
	    	res = fread(&app, 1, 1, f);
	    }
	    pwd[i] = '\0';

	    if(strcmp(usr, name) == 0 && strcmp(pwd, password) == 0){

	    	fclose(f);
	    	return 0; //client is registered
	    }
	}

	fclose(f);
	return 2; //client isn't registered
}

void handle_client(int socket_client){ //manage the client connections

	struct client * new_client = NULL;
	int dim, res;
	unsigned char * en_pass = NULL; //encrypted client password
	unsigned char * sgnt; //signature
	int sgnt_size = 0;
	char * concat;
	int concat_len;

	new_client = (struct client *)malloc(sizeof(struct client));

	res = 1;
	while(res != 0){

		/* receive username */
		dim = recv_len(socket_client);
		recv_msg(socket_client,(void *)(new_client->name), dim + 1);

		/* take client public key */
		new_client->pub_key = load_keys(new_client->name, 1);
		if(new_client->pub_key != NULL){ //if the public key exists
		
		    new_client->session_key = key_establishment_server(socket_client, new_client->pub_key, s_priv_key);

		    /* receive encrypted password */
		    dim = recv_len(socket_client);
			en_pass = (unsigned char *)malloc(dim);
			recv_msg(socket_client, (void *)en_pass, dim);
		
		    /* decrypt password */
		    memset(new_client->password, 0, 100);
		    symmetric_decrypt(en_pass, new_client->password , dim, &msg_len, new_client->session_key, 1);

		    /* send the acknowledgement */
		    res = check_usernameandpass(new_client->name, new_client->password);
		    send_msg(socket_client, (void *)&res, sizeof(int));
		}
	}

	/* S-->C W4L1: {extraction_id, w_combination, H(extraction_id||w_combination)}bc_key */
	send_len(socket_client, w4l1_len);/* invio dimensione combinazione vincente + id estazione cifrati */
	send_msg(socket_client, (void *)w4l1, w4l1_len);/* invio combinazione vincente + ID estrazione cifrati */
	send_msg(socket_client, (void *)&extraction_id, sizeof(int));

	/* C-->S W4L2: {extraction_id, combination, Sc(extraction_id||combination)}session_key */
	w4l2_len = recv_len(socket_client);
	w4l2 = (unsigned char *)malloc(w4l2_len);
	msg = (char *)malloc(w4l2_len);
    recv_msg(socket_client, (void *)w4l2, w4l2_len); 

    /* decrypt W4L2 */
    symmetric_decrypt(w4l2, msg, w4l2_len, &msg_len, new_client->session_key, 1);
    concat_len = 11 * sizeof(int);
    concat = (char *)malloc(concat_len);
    memcpy(concat, msg, concat_len);
    memcpy(new_client->combination, msg + sizeof(int), 10 * sizeof(int));
   	/* verify the client signature */
   	verify_signature((unsigned char *)msg + concat_len, msg_len - concat_len, concat, concat_len, new_client->pub_key);

    /* prepare W4L3: {extraction_id, combination, Ss(extraction_id||combination)}session_key */
    msg_len = 10 * sizeof(int) + sizeof(int);
	msg = (char *)realloc(msg, msg_len);
	memcpy(msg, &extraction_id, sizeof(int));
	memcpy(msg + sizeof(int), new_client->combination, 10 * sizeof(int));
	sgnt = signature(msg, msg_len, &sgnt_size, s_priv_key);
	
	msg_len += sgnt_size;
	msg = (char *)realloc((void *)msg, msg_len);
	memcpy(msg + 11 * sizeof(int), sgnt, sgnt_size);
	w4l3 = symmetric_encrypt(msg, msg_len, &w4l3_len, new_client->session_key, 1);

	/* S-->C W4L3: {extraction_id, combination, Ss(extraction_id||combination)}session_key */
	send_len(socket_client, sgnt_size);
	send_len(socket_client, w4l3_len);
	send_msg(socket_client, w4l3, w4l3_len);
  
    printf("Username: %s - Combination: ", new_client->name);
    print_combination(new_client->combination);

    /* initialize client parameters in the structure */
    new_client->socket = socket_client;
	new_client->w_pot1 = 0;
	new_client->w_pot2 = 0;
	
    num_client++;

    if(num_client == 1){ //if the client is the first, start the timer

    	reset_timer();
    	new_client->next = NULL;
    	clients = new_client;
    }
    else{

    	new_client->next = clients;
    	clients = new_client;
    }

    free(msg);
    free(sgnt);
    free(en_pass);
    free(w4l2);
    free(concat);
}

void create_listening_socket(){

	int ret;

	lst_socket = socket(AF_INET, SOCK_STREAM, 0);    
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(4444);
	inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
	ret = bind(lst_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
	if(ret < 0){ //port opening error

		printf("%s\n", strerror(errno));
        exit(EXIT_FAILURE);
	}
	
	ret = listen(lst_socket, BACKLOG_SIZE);
	if (ret < 0){

   		printf("%s\n", strerror(errno));
       	exit(EXIT_FAILURE);
    }
}

int main(){

	int i, socket_client, max_conn, len_str_client;
	fd_set master,read_fds;
	struct timeval start, end, result;

	/* take server private key */
	s_priv_key = load_keys("server", 0);
	if(s_priv_key == NULL){ //no private key (error)

		printf("Key not found!\n");
		exit(EXIT_FAILURE);
	}
	
	create_listening_socket ();

	/* initialization of select parameters */
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
    FD_SET(lst_socket, &master);	
	max_conn = lst_socket;

	pot = STARTING_POT;
	generate_combination(); //generate the winning combination
	
	num_client = 0;

	/* setting timer */
	reset_timer();

	for(;;){

		/* timer starts when there's an user connected */
		if (num_client == 0){
		
			timer = NULL;
		} 
		else if (num_client == 1){

			timer = &time_out; //set timer to the max value
			gettimeofday(&start, NULL); 
		}
		else{

			gettimeofday(&end, NULL);
			timersub(&end, &start,&result);
			gettimeofday(&start, NULL); 
			timersub(&time_out, &result, &time_out); //subtract time spent 
		}

		read_fds = master;

		switch(select(max_conn + 1, &read_fds, NULL, NULL, timer)){

			case -1: //error in select

				printf("%s\n", strerror(errno));
           		exit(EXIT_FAILURE);

			case 0: //timer expired

				reset_timer();
				the_winner_is();
				break;

			default: //client request
	
				for (i = 0; i <= max_conn + 1; i++){

              		if (FD_ISSET(i, &read_fds)){

                		if (i == lst_socket){

                     		/* waiting for the client */
							len_str_client = sizeof(client_addr);
							socket_client = accept(lst_socket, (struct sockaddr *) &client_addr, (socklen_t *) &len_str_client);
	    					max_conn = socket_client;
	    					handle_client(socket_client);
	    				}
					}
				}
		}
    }

    EVP_PKEY_free(s_priv_key);
	close(lst_socket);

	return 0;
}