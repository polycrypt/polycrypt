/*global TestArray, util, tv */

// -----------------------------------------------------------------------------
TestArray.addTest(
    "Generate a 192-bit AES key",
    function() {
        var length = 192;
        var op = window.polycrypt.generateKey({
            name: "AES-GCM",
            params: { length: 192 }
        });
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(.1, false );
        };
        op.oncomplete = function(e) {
            console.log("COMPLETE :: " + e.target.result);
            var key = e.target.result;
            that.complete( 
                key.hasOwnProperty('type') &&
                key.hasOwnProperty('extractable') &&
                key.hasOwnProperty('algorithm') &&
                key.hasOwnProperty('keyUsage') &&
                key.hasOwnProperty('key') &&
                key.key.length === 2*((length >> 3) + 8) // length+64 bits
            );
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "Generate a 512-bit RSA key",
    function() {
        var op = window.polycrypt.generateKey({
            name: "RSAES-PKCS1-v1_5",
            params: { 
                modulusLength: 512,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01])
            }
        });
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(.2, false );
        };
        op.oncomplete = function(e) {
            console.log("COMPLETE :: " + e.target.result);
            var key = e.target.result;
            that.complete(  
                key.hasOwnProperty('type') &&
                key.hasOwnProperty('extractable') &&
                key.hasOwnProperty('algorithm') &&
                key.hasOwnProperty('keyUsage') &&
                key.hasOwnProperty('key') &&
                key.key.length > 1024 // >4096 bits
            );
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "Import an AES key",
    function() {
        var op = window.polycrypt.importKey(
            "raw",
            util.hex2abv("f3095c4fe5e299477643c2310b44f0aa"),
            "AES-GCM"
        );
        // Assuming that apiKey = f3095c4fe5e299477643c2310b44f0aa,
        // wrappedKey = 4ee13a70ba1cc4fa2f7a21b17d36cc0a54641e49a4853704
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(.3, false );
        };
        op.oncomplete = function(e) {
            console.log("COMPLETE :: " + e.target.result);
            var key = e.target.result;
            that.complete( 
                key.hasOwnProperty('type') &&
                key.hasOwnProperty('extractable') &&
                key.hasOwnProperty('algorithm') &&
                key.hasOwnProperty('keyUsage') &&
                key.hasOwnProperty('key') &&
                key.key.length === 48 // 128+64 bits
            );
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "SHA-256 digest",
    function() {
        var that = this;
        var op = window.polycrypt.digest("SHA-256", tv.t3_data);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete( false );
        };
        op.oncomplete = function(e) {
            console.log("COMPLETE :: " + e.target.result);
            that.memcmp_complete(tv.t3_result, e.target.result); 
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "HMAC SHA-256",
    function() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t4_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.sign({
                name: "HMAC",
                params: { hash: "SHA-256" }
            }, key, tv.t4_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t4_result, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "RSAES encryption",
    function () {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t7_rsa_n ),
            e: util.b64encode( tv.t7_rsa_e ),
            d: util.b64encode( tv.t7_rsa_d )
        };
        var op = window.polycrypt.importKey("jwk", jwk, "RSAES-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.encrypt("RSAES-PKCS1-v1_5", key, tv.t7_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                var data = e.target.result;
                var op3 = window.polycrypt.decrypt("RSAES-PKCS1-v1_5", key, data);
                op3.onerror = function(e) {
                    console.log("ERROR :: " + e.target.result);
                    that.complete(false );
                };
                op3.oncomplete = function(e) {
                    console.log("COMPLETE :: " + e.target.result);
                    that.memcmp_complete(tv.t7_data, e.target.result );
                };
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "RSAES decryption",
    function () { 
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t8_rsa_n ),
            e: util.b64encode( tv.t8_rsa_e ),
            d: util.b64encode( tv.t8_rsa_d )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSAES-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.decrypt("RSAES-PKCS1-v1_5", key, tv.t8_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t8_result, e.target.result);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "RSASSA/SHA-1 signature",
    function () { 
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t9_rsa_n ),
            e: util.b64encode( tv.t9_rsa_e ),
            d: util.b64encode( tv.t9_rsa_d )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.sign({
                name: "RSASSA-PKCS1-v1_5",
                params: { hash: "SHA-1" }
            }, key, tv.t9_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t9_sig, e.target.result);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "RSASSA verification (SHA-1)",
    function () {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t10_rsa_n ),
            e: util.b64encode( tv.t10_rsa_e )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.verify("RSASSA-PKCS1-v1_5", key, tv.t10_sig, tv.t10_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.complete(e.target.result);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "RSASSA/SHA-256 signature",
    function () { 
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t11_rsa_n ),
            e: util.b64encode( tv.t11_rsa_e ),
            d: util.b64encode( tv.t11_rsa_d )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.sign({
                name: "RSASSA-PKCS1-v1_5",
                params: { hash: "SHA-256" }
            }, key, tv.t11_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t11_sig, e.target.result);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "RSASSA verification (SHA-256)",
    function () {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t12_rsa_n ),
            e: util.b64encode( tv.t12_rsa_e )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.verify("RSASSA-PKCS1-v1_5", key, tv.t12_sig, tv.t12_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.complete(e.target.result);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "AES-CBC encryption",
    function () {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t13_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.encrypt({
                name: "AES-CBC",
                params: { iv: tv.t13_iv }
            }, key, tv.t13_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t13_result, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "AES-CBC decryption",
    function () {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t14_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.decrypt({
                name: "AES-CBC",
                params: { iv: tv.t14_iv }
            }, key, tv.t14_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t14_result, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "AES-CTR encryption",
    function () {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t15_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.encrypt({
                name: "AES-CTR",
                params: { iv: tv.t15_iv }
            }, key, tv.t15_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t15_result, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "AES-CTR decryption",
    function () { 
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t16_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.decrypt({
                name: "AES-CTR",
                params: { iv: tv.t16_iv }
            }, key, tv.t16_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t16_result, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "PBKDF2 key derivation",
    function () {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t17_data);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.deriveKey(
                {
                    name: "PBKDF2",
                    params: { 
                        salt: tv.t17_salt,
                        iterations: tv.t17_c,
                        prf: "SHA-1"
                    }
                }, 
                key,
                { 
                    name: "HMAC",
                    params: { length: tv.t17_dkLen * 8 }
                }
            );
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                // Can't test directly, since we can't see the derived key
                // Check that it's properly formed and has the right length
                var key = e.target.result;
                window.key = key;
                that.complete(
                    key.hasOwnProperty('type') &&
                    key.hasOwnProperty('extractable') &&
                    key.hasOwnProperty('algorithm') &&
                    key.hasOwnProperty('keyUsage') &&
                    key.hasOwnProperty('key') &&
                    key.key.length === 2 * (8 * Math.ceil(tv.t17_dkLen / 8) + 8)
                );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "AES-GCM encryption",
    function () { 
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t18_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.encrypt({
                name: "AES-GCM",
                params: { 
                    iv: tv.t18_iv,
                    additionalData: tv.t18_adata,
                    tagLength: 128
                }
            }, key, tv.t18_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                // Concatenate the result and tag
                var t18_fullresult = util.abvcat(
                    tv.t18_result,
                    tv.t18_tag
                );
                that.memcmp_complete(t18_fullresult, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "AES-GCM decryption",
    function () { 
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t19_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            // Concatenate the result and tag
            var t19_fulldata = util.abvcat(
                tv.t19_data,
                tv.t19_tag
            );
            var op2 = window.polycrypt.decrypt({
                name: "AES-GCM",
                params: { 
                    iv: tv.t19_iv,
                    additionalData: tv.t19_adata,
                    tagLength: 128
                }
            }, key, t19_fulldata);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t19_result, e.target.result );
            };
        };
    }
);


