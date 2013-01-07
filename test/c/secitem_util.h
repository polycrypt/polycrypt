#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*** copypasta from seccomon.h ***/
/*** #include "seccomon.h" ***/
#ifndef _SECCOMMON_H_
typedef enum {
    siBuffer = 0,
    siClearDataBuffer = 1,
    siCipherDataBuffer = 2,
    siDERCertBuffer = 3,
    siEncodedCertBuffer = 4,
    siDERNameBuffer = 5,
    siEncodedNameBuffer = 6,
    siAsciiNameString = 7,
    siAsciiString = 8,
    siDEROID = 9,
    siUnsignedInteger = 10,
    siUTCTime = 11,
    siGeneralizedTime = 12,
    siVisibleString = 13,
    siUTF8String = 14,
    siBMPString = 15
} SECItemType;

typedef struct SECItemStr SECItem;

struct SECItemStr {
    SECItemType type;
    unsigned char *data;
    unsigned int len;
};
#endif /* _SECCOMMON_H_ */
/*** end copypasta ***/

SECItem hex2si(const char* hex) {
    int i, len = strlen(hex);
    int bytelen = len >> 1;
    char* byte = malloc(3);
    
    SECItem si;
    si.type = siBuffer;
    si.len = bytelen;
    si.data = malloc(bytelen);

    for (i=0; i<bytelen; i++) {
        byte[0] = byte[1] = byte[2] = 0;
        strncpy(byte, hex + (2*i), 2);
        si.data[i] = (unsigned char) strtol( byte, NULL, 16 );     
    }

    return si;
}

char* si2hex(SECItem si) {
    int i;
    char *hex = malloc(2*(si.len) + 1);
    
    for (i=0; i<si.len; ++i) {
        sprintf(hex + (2*i), "%02x", si.data[i]);
    }

    return hex;
}

