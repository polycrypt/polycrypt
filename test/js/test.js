// Summary:           
// 1.  AES key wrap                         DONE    sjcl+libpolycrypt
// 2.  AES key unwrap                       DONE    sjcl+libpolycrypt
// 3.  SHA-256 digest                       DONE    sjcl
// 4.  HMAC SHA-256                         DONE    sjcl
// 5.  AES-128-CCM encryption               DONE    sjcl
// 6.  AES-128-CCM decryption               DONE    sjcl
// 7.  PKCS1_v1.5 encryption                DONE    jsbn
// 8.  PKCS1_v1.5 decryption                DONE    jsbn
// 9.  PKCS1_v1.5 sign (using SHA1)         DONE    jsrsasign
// 10. PKCS1_v1.5 verify (using SHA1)       DONE    jsrsasign
// 11. PKCS1_v1.5 sign (using SHA256)       DONE    jsrsasign
// 12. PKCS1_v1.5 verify (using SHA256)     DONE    jsrsasign

var navigator,  console;
if (typeof(gc) === "undefined") {
    navigator = window.navigator;
    console = window.console;
    // ... and you really should import the scripts below
} else {
    // Shims for Rhino environment
    var navigator = {};
    var console = { log: function(x) { print (x); } };
    load("./typedarray.js");        
    
    // CryptoJS
    load("./lib/CryptoJS/core-min.js");
    load("./lib/CryptoJS/sha1-min.js");
    load("./lib/CryptoJS/sha256-min.js");
    load("./lib/CryptoJS/hmac-min.js");
    load("./lib/CryptoJS/cipher-core-min.js");
    load("./lib/CryptoJS/aes-min.js");
    load("./lib/CryptoJS/mode-ctr-min.js");
    load("./lib/CryptoJS/pad-nopadding-min.js");
    load("./lib/CryptoJS/pbkdf2-min.js");
    
    // JSBN
    load("./lib/prng4.js");
    load("./lib/rng.js");
    load("./lib/jsbn.js");
    load("./lib/jsbn2.js");
    load("./lib/rsa.js");
    load("./lib/rsa2.js");
    load("./lib/rsasign-1.2.js");
   
    // Our GCM implementation
    load("./lib/gcm.js");      

    // Local utilities
    load("./src/util.js");              
    load("./src/libpolycrypt.js");      
    
    // Test vectors
    load("./TestVectors.js");     
}


function test(number, result, myresult) {
    var space = (number < 10)? " " : "";
    var passfail = util.memcmp( result, myresult );
    if (!passfail) {
        console.log("    expected: " + util.abv2hex(result) );
        console.log("         got: " + util.abv2hex(myresult) );
    }
    bool_test(number, passfail)
}

function bool_test(number, passfail) {
    var space = (number < 10)? " " : "";
    if (passfail) {
        console.log("["+ space + number.toString() +"] [PASS]");
    } else {
        console.log("["+ space + number.toString() +"] [FAIL]");
    }
}

// 1. AES key wrap
test( 
    1, 
    tv.t1_result, 
    libpolycrypt.aes_key_wrap(tv.t1_key, tv.t1_data) 
);



// 2. AES key unwrap
test( 
    2, 
    tv.t2_result, 
    libpolycrypt.aes_key_unwrap(tv.t2_key, tv.t2_data) 
);

// 3. SHA-256 digest
test( 
    3, 
    tv.t3_result, 
    libpolycrypt.sha256(tv.t3_data) 
);

// 4. HMAC SHA-256
test( 
    4, 
    tv.t4_result, 
    libpolycrypt.hmac_sha256(tv.t4_key, tv.t4_data) 
);

// 5. AES-128-CCM encryption
bool_test(5, false); // SKIP
/*
test( 
    5, 
    tv.t5_result, 
    libpolycrypt.encrypt_AES128CCM(tv.t5_key, tv.t5_nonce, tv.t5_tlen, tv.t5_data, tv.t5_adata) 
);
*/

// 6. AES-128-CCM encryption
bool_test(6, false); // SKIP
/*
test( 
    6, 
    tv.t6_result, 
    libpolycrypt.decrypt_AES128CCM(tv.t6_key, tv.t6_nonce, tv.t6_tlen, tv.t6_data, tv.t6_adata) 
);
*/

// 7. PKCS1_v1.5 encryption
var ct = libpolycrypt.rsa_pkcs1_key_wrap(tv.t7_rsa_n, tv.t7_rsa_e, tv.t7_data);
var pt = libpolycrypt.rsa_pkcs1_key_unwrap(tv.t7_rsa_n, tv.t7_rsa_e, tv.t7_rsa_d, ct);
test(
    7,
    tv.t7_data,
    pt
);

// 8. PKCS1_v1.5 decryption
test(
    8,
    tv.t8_result,
    libpolycrypt.rsa_pkcs1_key_unwrap(tv.t8_rsa_n, tv.t8_rsa_e, tv.t8_rsa_d, tv.t8_data)
);

// 9.  PKCS1_v1.5 sign (using SHA1)
test(
    9,
    tv.t9_sig,
    libpolycrypt.sign_pkcs1_sha1(tv.t9_rsa_n, tv.t9_rsa_e, tv.t9_rsa_d, tv.t9_data)
);

// 10. PKCS1_v1.5 verify (using SHA1)
bool_test(
    10,
    libpolycrypt.verify_pkcs1(tv.t10_rsa_n, tv.t10_rsa_e, tv.t10_data, tv.t10_sig)
);

// 11.  PKCS1_v1.5 sign (using SHA256)
test(
    11,
    tv.t11_sig,
    libpolycrypt.sign_pkcs1_sha256(tv.t11_rsa_n, tv.t11_rsa_e, tv.t11_rsa_d, tv.t11_data)
);

// 12. PKCS1_v1.5 verify (using SHA256)
bool_test(
    12,
    libpolycrypt.verify_pkcs1(tv.t12_rsa_n, tv.t12_rsa_e, tv.t12_data, tv.t12_sig)
);

// 13. AES CBC encrypt
test(
    13,
    tv.t13_result,
    libpolycrypt.encrypt_AES_CBC(tv.t13_key, tv.t13_iv, tv.t13_data)
);

// 14. AES CBC decrypt
test(
    14,
    tv.t14_result,
    libpolycrypt.decrypt_AES_CBC(tv.t14_key, tv.t14_iv, tv.t14_data)
);

// 15. AES CTR encrypt
test(
    15,
    tv.t15_result,
    libpolycrypt.encrypt_AES_CTR(tv.t15_key, tv.t15_iv, tv.t15_data)
);

// 16. AES CTR decrypt
test(
    16,
    tv.t16_result,
    libpolycrypt.decrypt_AES_CTR(tv.t16_key, tv.t16_iv, tv.t16_data)
);

// 17. PBKDF2/SHA1 derive
test(
    17,
    tv.t17_result,
    libpolycrypt.pbkdf2_sha1(tv.t17_data, tv.t17_salt, tv.t17_c, tv.t17_dkLen)
);

// 18. AES-GCM encryption
test(
    18,
    tv.t18_result,
    libpolycrypt.encrypt_AES_GCM(tv.t18_key, tv.t18_iv, tv.t18_data, tv.t18_adata).C
);
test(
    18,
    tv.t18_tag,
    libpolycrypt.encrypt_AES_GCM(tv.t18_key, tv.t18_iv, tv.t18_data, tv.t18_adata).T
);

// 19. AES-GCM decryption
test(
    19,
    tv.t19_result,
    libpolycrypt.decrypt_AES_GCM(tv.t19_key, tv.t19_iv, tv.t19_data, tv.t19_adata, tv.t19_tag)
);

