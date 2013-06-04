#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "secitem_util.h"
#include "TestVectors.h"
#include "hash.h"

// ----------------------------------------------------------------------------
void bool_test(int number, int passfail) {
    const char *space = (number < 10) ? " " : "";
    if (!passfail) {
        printf("[%s%d] [PASS]\n", space, number);
    } else {
        printf("[%s%d] [FAIL]\n", space, number);
    }
}
// ----------------------------------------------------------------------------
void test(int number, const char *result, const char *myresult) {
    const char *space = (number < 10) ? " " : "";
    int passfail = strncasecmp(result, myresult, strlen(result));
    if (passfail) {
        printf("    expected: %s\n", result);
        printf("         got: %s\n", myresult);
    }
    bool_test(number, passfail);
}
// ----------------------------------------------------------------------------
const char * test_sha256(const char* hex_in) {
    SECItem bytes_in;

    const int SHA256_BYTE_LEN = 32;
    SECItemType sit = siBuffer;
    unsigned char data[SHA256_BYTE_LEN];
    SECItem bytes_out = { sit, data, SHA256_BYTE_LEN };

    char *hex_out;

    int status;
    const char *errmsg = "error";

    bytes_in = hex2si(hex_in);
    status = sha256(bytes_out.data, bytes_out.len, bytes_in.data, bytes_in.len);

    if (status) { return errmsg; }

    hex_out = si2hex(bytes_out);

    return hex_out;
}
// ----------------------------------------------------------------------------
int main() {
    /* TODO */
    printf("===== Few C tests performed =====\n");

    test(
            3,
            t3_result,
            test_sha256(t3_data)
    );

    return 0;
}
