/* Changed from the original:  Demonstration program for hashing and MACs
 * This just does a hash with SHA256.
 */

#include <iostream>

#include "pk11pub.h"
#include "nss.h"

using namespace std;

// ----------------------------------------------------------------------------
static void
printDigest(unsigned char *digest, unsigned int len)
{
  int i;

  cout << "length: " << len << endl;
  for(i = 0;i < len;i++) printf("%02x ", digest[i]);
  cout << endl;
}
// ----------------------------------------------------------------------------
int sha256(unsigned char* bytes_out, int bytes_out_len,
        unsigned char const * bytes_in, int bytes_in_len) {
  int i;
  int status = 0;
  PK11SlotInfo *slot = 0;
  PK11SymKey *key = 0;
  PK11Context *context = 0;
  unsigned char digest[bytes_out_len];
  unsigned int len;
  SECStatus s;

  // Initialize NSS
  // If your application code has already initialized NSS, you can skip this.
  // This code uses the simplest of the Init functions, which does not
  // require a NSS database to exist
  //
  NSS_NoDB_Init(".");

  // Get a slot to use for the crypto operations
  slot = PK11_GetInternalKeySlot();
  if (!slot)
  {
    cout << "GetInternalKeySlot failed" << endl;
    status = 1;
    goto done;
  }

  // Create a context for hashing (digesting)
  context = PK11_CreateDigestContext(SEC_OID_SHA256);
  if (!context) { cout << "CreateDigestContext failed" << endl; goto done; }

  s = PK11_DigestBegin(context);
  if (s != SECSuccess) { cout << "DigestBegin failed" << endl; goto done; }

  s = PK11_DigestOp(context, bytes_in, bytes_in_len);
  if (s != SECSuccess) { cout << "DigestUpdate failed" << endl; goto done; }

  s = PK11_DigestFinal(context, digest, &len, sizeof digest);
  if (s != SECSuccess) { cout << "DigestFinal failed" << endl; goto done; }

  if (len != bytes_out_len) {
      fprintf(stderr, "Error: digest length (%u) != expected length (%u).\n", len, bytes_out_len);
      status = -1;
      goto done;
  }

  for (i = 0; i < len; i++) {
      bytes_out[i] = digest[i];
  }

  // Print digest
  //printDigest(digest, len);

  PK11_DestroyContext(context, PR_TRUE);
  context = 0;

done:
  if (context) PK11_DestroyContext(context, PR_TRUE);  // freeit ??
  if (key) PK11_FreeSymKey(key);
  if (slot) PK11_FreeSlot(slot);

  return status;
}
