#ifndef UTILITY_H_1234
#define UTILITY_H_1234

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

void recv_msg(int sk, void * msg, int len);
int recv_len(int sk);
void send_len(int sk, int len);
void send_msg(int sk, void * msg, int len);
void print_bytes(const unsigned char * buf, int len);
void print_combination(int * combination);
int combcmp(int * combination1, int * combination2);

#endif /* UTILITY_H_1234 */
