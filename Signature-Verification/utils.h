#ifndef _UTILS_H_
#define _UTILS_H_


#include <stdio.h>
#include <string.h>
#include "sha1.h"
#include <stdlib.h>


void sha_fun(char target_string[], char* sha_result);
int htoi(unsigned char a);
void xor_operation(unsigned char a, unsigned char b, char* xor_result);

#endif
