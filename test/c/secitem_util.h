#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "seccomon.h"


SECItem hex2si(const char* hex) {
    int i, len = strlen(hex);
    if ( len % 2) {
        fprintf(stderr,
                "WARNING: %s:%u an odd number of input hex chars may cause unexpected results.\n",
                __FILE__, __LINE__);
    }
    int bytelen = len >> 1;
    char* byte = (char*) malloc(3);
    
    SECItem si;
    si.type = siBuffer;
    si.len = bytelen;
    si.data = (unsigned char*) malloc(bytelen);

    for (i=0; i<bytelen; i++) {
        byte[0] = byte[1] = byte[2] = 0;
        strncpy(byte, hex + (2*i), 2);
        si.data[i] = (unsigned char) strtol( byte, NULL, 16 );     
    }

    free(byte); byte = NULL;

    return si;
}

char* si2hex(SECItem si) {
    int i;
    char *hex = (char*) malloc(2*(si.len) + 1);
    
    for (i=0; i<si.len; ++i) {
        sprintf(hex + (2*i), "%02x", si.data[i]);
    }

    return hex;
}

