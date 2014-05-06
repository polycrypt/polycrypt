SubtleCrypto Demos
==================

The demos in this directory use `window.crypto.subtle.*` (SubtleCrypto) to perform all cryptographic operations.  This allows you to use either the internal software security device, or an external PKCS#11 Module (for example, a CAC card) for the cryptographic support.  Note that most testing has been done using Firefox's internal software security device, NOT external hardware tokens.  Unfortunately, most external hardware tokens are not able to perform many cryptographic operations, often just hashing, and RSA sign/verify.  Note that this demo must be run in our release of Nightly that supports SubtleCrypto. 

./demo/index.html:
------------------
    This demo will test common cryptographic operations first using polycrypt, and then seamlessly switches to using SubtleCrypto to show which operations are currently supported.  You can click on each test, which will toggle showing information about each test.  For example, input plaintext, output ciphertext as well as any initializtaion vectors, etc.  SubtleCrypto supports the following operations:

1.  Encrypt (AES-CBC)
2.  Decrypt (AES-CBC)
3.  Import Key (AES-CBC, RSA PKCS#1v1.5)
4.  Digest (SHA-1, SHA-256, SHA-512)
5.  Sign (RSA PKCS#1v1.5 / SHA-1)
6.  Verify (RSA PKCS#1v1.5 / SHA-1)

./hello-chat.html:
------------------
    This demo simulates an encrypted chat between two parties, Alice and Bob.  The chat uses a static key (for simplicity).  Users simply enter a message and its ciphertext will be displayed on their side.  The message is then "transported" to the other party and its ciphertext is displayed.  It is then decrypted so the other party can read it.  A brand new initialization vector is chosen everytime a new message is encrypted.  This demo shows what a high-level cryptographic API might look like that wraps the Web Crypto API.  It is made up of two parts: a low-level API that directly interacts with SubtleCrypto, and a high-level API that interacts with the low-level API.  The following shows how method calls to the high-level API work:

1.  EncryptDataWrapper(message, callback, callbackParams)
2.  encrypt(message, KEY)
3.  window.crypto.subtle.encrypt(ALGORITHM, KEY, plaintext)

This high-level API is very restrictive and does not allow JS developers to modify the cryptographic parameters.  On one hand, this mitigates risk because as long as the API implementor is well-versed in crypto, the operations should be secure (for example, using the AES block cipher in an appropriate mode of operation with a suitable key size).  On the other hand, this type of API will only work for a subset of problems and will most likely not work with legacy systems.  Overall, this type of API is safer.

Another high-level API could resemble this, but take in an optional dictionary of crypto arguments that would explicitly specify block ciphers, modes of operations, etc.  This would allow developers to have more control over their applications that use the API; however, it would also create room for error.  Such an API would need to check the optional parameters to make sure they foster secure cryptographic operations.  For example, if a library wants to encrypt a message with DES, it should either alert the user or outright fail. It would also be difficult to force users to use cryptographic primitives correctly.  For example, a user might want to use AES-CBC with an HMAC.  While trying to get the HMAC to work, the user becomes bored and abandons it, replacing it with just AES-CBC.  This would open their protocol to a Chosen Ciphertext Attack, and the API would have no control over this. 

./hello-hash.html:
------------------
    This demo lets the user hash a string and displays the output on the screen.  It also displays the source code as an example for users who want to directly use the Web Crypto API

./hello-enc.html:
-----------------
    This demo lets the user encrypt a string, displays the ciphertext on the screen, and then decrypt the ciphertext to display the original message.  It also displays the source code as an example for users who want to directly use the Web Crypto API

./hello-sign.html:
------------------
    This demo lets the user sign a string, displaying the signature as well and whether or not the signature verifies with the public key.  It also displays teh source code as an example for users who want to directly use the Web Crypto API.
