#!/usr/bin/env python

import sys
from CryptoHelper import CryptoHelper
from TestVectors import *

# Preamble
def test(n, x):
    passfail = "FAIL"
    if x:
        passfail = "PASS"
    print "[{0:2d}] [{1}]".format(n, passfail)

### TESTS #############################################################

# 1. AES key wrap
test( 1, t1_result == CryptoHelper.aes_key_wrap(t1_key, t1_data) )

# 2. AES key unwrap
test( 2, t2_result == CryptoHelper.aes_key_unwrap(t2_key, t2_data) )

# 3. SHA-256 digest
test( 3, t3_result == CryptoHelper.sha256(t3_data) )

# 4. HMAC SHA-245
test( 4, t4_result == CryptoHelper.hmac_sha256(t4_key, t4_data) )

# 5. AES-128-CCM encryption
test( 5, t5_result == CryptoHelper.encrypt_AES128CCM(t5_key, t5_nonce, t5_tlen, t5_data, t5_adata) );

# 6. AES-128-CCM decryption
test( 6, t6_result == CryptoHelper.decrypt_AES128CCM(t6_key, t6_nonce, t6_tlen, t6_data, t6_adata) );

# 7. PKCS1_v1.5 encryption
t7_rsa_n_int = long(t7_rsa_n.encode('hex'), 16)
t7_rsa_e_int = long(t7_rsa_e.encode('hex'), 16)
t7_rsa_d_int = long(t7_rsa_d.encode('hex'), 16)
t7_enc = CryptoHelper.rsa_pkcs1_key_wrap(t7_rsa_n_int, t7_rsa_e_int, t7_data)
t7_dec = CryptoHelper.rsa_pkcs1_key_unwrap(t7_rsa_n_int, t7_rsa_e_int, t7_rsa_d_int, t7_enc)
test( 7, t7_data == t7_dec )

# 8. PKCS1_v1.5 decryption
t8_rsa_n_int = long(t8_rsa_n.encode('hex'), 16)
t8_rsa_e_int = long(t8_rsa_e.encode('hex'), 16)
t8_rsa_d_int = long(t8_rsa_d.encode('hex'), 16)
test( 8, t8_result == CryptoHelper.rsa_pkcs1_key_unwrap(t8_rsa_n_int, t8_rsa_e_int, t8_rsa_d_int, t8_data) )

# 9. PKCS1_v1.5 sign (using SHA1)
t9_rsa_n_int = long(t9_rsa_n.encode('hex'), 16)
t9_rsa_e_int = long(t9_rsa_e.encode('hex'), 16)
t9_rsa_d_int = long(t9_rsa_d.encode('hex'), 16)
test( 9, t9_sig == CryptoHelper.sign_pkcs1_sha1(t9_rsa_n_int, t9_rsa_e_int, t9_rsa_d_int, t9_data) )

# 10. PKCS1_v1.5 verify (using SHA1)
t10_rsa_n_int = long(t10_rsa_n.encode('hex'), 16)
t10_rsa_e_int = long(t10_rsa_e.encode('hex'), 16)
test(10, CryptoHelper.verify_pkcs1_sha1(t10_rsa_n_int, t10_rsa_e_int, t10_data, t10_sig) )

# 11. PKCS1_v1.5 sign (using SHA256)
t11_rsa_n_int = long(t11_rsa_n.encode('hex'), 16)
t11_rsa_e_int = long(t11_rsa_e.encode('hex'), 16)
t11_rsa_d_int = long(t11_rsa_d.encode('hex'), 16)
test(11, t11_sig == CryptoHelper.sign_pkcs1_sha256(t11_rsa_n_int, t11_rsa_e_int, t11_rsa_d_int, t11_data) )

# 12. PKCS1_v1.5 verify (using SHA256)
t12_rsa_n_int = long(t12_rsa_n.encode('hex'), 16)
t12_rsa_e_int = long(t12_rsa_e.encode('hex'), 16)
t12_rsa_d_int = long(t12_rsa_d.encode('hex'), 16)
test(12, t12_sig == CryptoHelper.sign_pkcs1_sha256(t12_rsa_n_int, t12_rsa_e_int, t12_rsa_d_int, t12_data) )

