/*global util, tv */

// Requires TestVectors.js for test vectors
// Requires util for memcmp, abv2hex
// -----------------------------------------------------------------------------
var TestRunner = {
    _log: null,
    _logId: "log",
    log: function TestRunner_log(x) {
        if (!this._log) { this._log = document.getElementById(this._logId); }
        this._log.innerHTML += x + "<br/>";
    },

    test: function TestRunner_test(number, result, myresult) {
        var passfail = util.memcmp(result, myresult);
        if (!passfail) {
            this.log("    expected: " + util.abv2hex(result) );
            this.log("         got: " + util.abv2hex(myresult) );
        }
        this.bool_test(number, passfail);
    },

    bool_test: function  TestRunner_bool_test(number, passfail) {
        var space = (number.toString().length < 2)? " " : "";
        var pfstr = (passfail)? "[PASS]" : "[FAIL]";
        this.log("["+ space + number.toString() +"] "+ pfstr);
    },

    // Individual tests go here

    // 0.1. AES key generation
    test01: function TestRunner_test01() {
        var length = 192;
        var op = window.polycrypt.generateKey({
            name: "AES-GCM",
            params: { length: 192, },
        });
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 0.1, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            that.bool_test( 0.1,
                key.hasOwnProperty('type') &&
                key.hasOwnProperty('extractable') &&
                key.hasOwnProperty('algorithm') &&
                key.hasOwnProperty('keyUsage') &&
                key.hasOwnProperty('key') &&
                key.key.length === 2*((length >> 3) + 8) // length+64 bits
            );
        };
    },

    // 0.2. RSA key generation
    test02: function TestRunner_test02() {
        var op = window.polycrypt.generateKey({
            name: "RSAES-PKCS1-v1_5",
            params: {
                modulusLength: 512,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            },
        });
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 0.2, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            that.bool_test( 0.2,
                key.hasOwnProperty('type') &&
                key.hasOwnProperty('extractable') &&
                key.hasOwnProperty('algorithm') &&
                key.hasOwnProperty('keyUsage') &&
                key.hasOwnProperty('key') &&
                key.key.length > 1024 // >4096 bits
            );
        };
    },
    
    // 0.3. AES key import
    test03: function TestRunner_test01() {
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
            that.bool_test( 0.3, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            that.bool_test( 0.3,
                key.hasOwnProperty('type') &&
                key.hasOwnProperty('extractable') &&
                key.hasOwnProperty('algorithm') &&
                key.hasOwnProperty('keyUsage') &&
                key.hasOwnProperty('key') &&
                key.key.length === 48 // 128+64 bits
            );
        };
    },

    // 1. AES key wrap
    // Don't have this in the API.

    // 2. AES key unwrap
    // Don/t have this in the API.

    // 3.1 SHA-256 digest
    test3: function TestRunner_test3() {
        var that = this;
        var op = window.polycrypt.digest("SHA-256");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 3, false );
        };
        op.oncomplete = function(e) {
            console.log('in test3::e.target.result: ' +e.target.result);
            console.log('in test3::op.result: ' +op.result);
            that.test( 3, tv.t3_result, e.target.result);
        };
        op.process(tv.t3_data);
        op.finish();
    },

    // 4. HMAC SHA-256
    test4: function TestRunner_test4() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t4_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 4, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.sign({
                name: "HMAC",
                params: { hash: "SHA-256" }
            }, key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 4, false );
            };
            op2.oncomplete = function(e) {
                that.test( 4, tv.t4_result, e.target.result );
            };
            op2.process(tv.t4_data);
            op2.finish();
        };
    },

    // 5. AES-128-CCM encryption
    // Don/t have this in the API.

    // 6. AES-128-CCM decryption
    // Don/t have this in the API.

    // 7. PKCS1_v1.5 encryption
    test7: function TestRunner_test7() {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t7_rsa_n ),
            e: util.b64encode( tv.t7_rsa_e ),
            d: util.b64encode( tv.t7_rsa_d ),
        };
        var op = window.polycrypt.importKey("jwk", jwk, "RSAES-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 7, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.encrypt("RSAES-PKCS1-v1_5", key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 7, false );
            };
            op2.oncomplete = function(e) {
                var data = e.target.result;
                var op3 = window.polycrypt.decrypt("RSAES-PKCS1-v1_5", key);
                op3.onerror = function(e) {
                    console.log("ERROR :: " + e.target.result);
                    that.bool_test( 7, false );
                };
                op3.oncomplete = function(e) {
                    that.test( 7, tv.t7_data, e.target.result );
                };
                op3.process(data);
                op3.finish();
            };
            op2.process(tv.t7_data);
            op2.finish();
        };
    },

    // 8. PKCS1_v1.5 decryption
    test8: function TestRunner_test8() {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t8_rsa_n ),
            e: util.b64encode( tv.t8_rsa_e ),
            d: util.b64encode( tv.t8_rsa_d ),
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSAES-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 8, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.decrypt("RSAES-PKCS1-v1_5", key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 8, false );
            };
            op2.oncomplete = function(e) {
                that.test( 8, tv.t8_result, e.target.result);
            };
            op2.process(tv.t8_data);
            op2.finish();
        };
    },

    // 9. PKCS1_v1.5 sign (using SHA1)
    test9: function TestRunner_test9() {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t9_rsa_n ),
            e: util.b64encode( tv.t9_rsa_e ),
            d: util.b64encode( tv.t9_rsa_d ),
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 9, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.sign({
                name: "RSASSA-PKCS1-v1_5",
                params: { hash: "SHA-1", },
            }, key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 9, false );
            };
            op2.oncomplete = function(e) {
                that.test( 9, tv.t9_sig, e.target.result);
            };
            op2.process(tv.t9_data);
            op2.finish();
        };
    },

    // 10. PKCS1_v1.5 verify (using SHA1)
    test10: function TestRunner_test10() {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t10_rsa_n ),
            e: util.b64encode( tv.t10_rsa_e ),
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 10, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.verify("RSASSA-PKCS1-v1_5", key, tv.t10_sig);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 10, false );
            };
            op2.oncomplete = function(e) {
                that.bool_test( 10, e.target.result);
            };
            op2.process(tv.t10_data);
            op2.finish();
        };
    },

    // 11. PKCS1_v1.5 sign (using SHA256)
    test11: function TestRunner_test11() {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t11_rsa_n ),
            e: util.b64encode( tv.t11_rsa_e ),
            d: util.b64encode( tv.t11_rsa_d ),
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 11, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.sign({
                name: "RSASSA-PKCS1-v1_5",
                params: { hash: "SHA-256", },
            }, key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 11, false );
            };
            op2.oncomplete = function(e) {
                that.test( 11, tv.t11_sig, e.target.result);
            };
            op2.process(tv.t11_data);
            op2.finish();
        };
    },

    // 12. PKCS1_v1.5 verify (using SHA256)
    test12: function TestRunner_test12() {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t12_rsa_n ),
            e: util.b64encode( tv.t12_rsa_e ),
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 12, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.verify("RSASSA-PKCS1-v1_5", key, tv.t12_sig);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 12, false );
            };
            op2.oncomplete = function(e) {
                that.bool_test( 12, e.target.result);
            };
            op2.process(tv.t12_data);
            op2.finish();
        };
    },

    // 13. AES CBC encrypt
    test13: function TestRunner_test13() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t13_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 13, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.encrypt({
                name: "AES-CBC",
                params: { iv: tv.t13_iv }
            }, key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 13, false );
            };
            op2.oncomplete = function(e) {
                that.test( 13, tv.t13_result, e.target.result );
            };
            op2.process(tv.t13_data);
            op2.finish();
        };
    },

    // 14. AES CBC decrypt
    test14: function TestRunner_test14() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t14_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 14, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.decrypt({
                name: "AES-CBC",
                params: { iv: tv.t14_iv }
            }, key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 14, false );
            };
            op2.oncomplete = function(e) {
                that.test( 14, tv.t14_result, e.target.result );
            };
            op2.process(tv.t14_data);
            op2.finish();
        };
    },

    // 15. AES CTR encrypt
    test15: function TestRunner_test15() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t15_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 15, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.encrypt({
                name: "AES-CTR",
                params: { iv: tv.t15_iv }
            }, key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 15, false );
            };
            op2.oncomplete = function(e) {
                that.test( 15, tv.t15_result, e.target.result );
            };
            op2.process(tv.t15_data);
            op2.finish();
        };
    },

    // 16. AES CTR decrypt
    test16: function TestRunner_test16() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t16_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 16, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.decrypt({
                name: "AES-CTR",
                params: { iv: tv.t16_iv }
            }, key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 16, false );
            };
            op2.oncomplete = function(e) {
                that.test( 16, tv.t16_result, e.target.result );
            };
            op2.process(tv.t16_data);
            op2.finish();
        };
    },

    // 17. PBKDF2/SHA1 derive
    test17: function TestRunner_test17() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t17_data);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 17, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.deriveKey(
                {
                    name: "PBKDF2",
                    params: {
                        salt: tv.t17_salt,
                        iterations: tv.t17_c,
                        prf: "SHA-1",
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
                that.bool_test( 17, false );
            };
            op2.oncomplete = function(e) {
                // Can't test directly, since we can't see the derived key
                // Check that it's properly formed and has the right length
                var key = e.target.result;
                window.key = key;
                that.bool_test( 17,
                    key.hasOwnProperty('type') &&
                    key.hasOwnProperty('extractable') &&
                    key.hasOwnProperty('algorithm') &&
                    key.hasOwnProperty('keyUsage') &&
                    key.hasOwnProperty('key') &&
                    key.key.length === 2 * (8 * Math.ceil(tv.t17_dkLen / 8) + 8)
                );
            };
        };
    },

    // 18. AES-GCM encryption
    test18: function TestRunner_test18() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t18_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 18, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.encrypt({
                name: "AES-GCM",
                params: {
                    iv: tv.t18_iv,
                    additionalData: tv.t18_adata,
                    tagLength: 128,
                }
            }, key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 18, false );
            };
            op2.oncomplete = function(e) {
                // Concatenate the result and tag
                var t18_fullresult = util.abvcat(
                    tv.t18_result,
                    tv.t18_tag
                );
                that.test( 18, t18_fullresult, e.target.result );
            };
            op2.process(tv.t18_data);
            op2.finish();
        };
    },

    // 19. AES-GCM decryption
    test19: function TestRunner_test19() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t19_key);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.bool_test( 19, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.decrypt({
                name: "AES-GCM",
                params: {
                    iv: tv.t19_iv,
                    additionalData: tv.t19_adata,
                    tagLength: 128,
                }
            }, key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.bool_test( 19, false );
            };
            op2.oncomplete = function(e) {
                that.test( 19, tv.t19_result, e.target.result );
            };
            // Concatenate the result and tag
            var t19_fulldata = util.abvcat(
                tv.t19_data,
                tv.t19_tag
            );
            op2.process(t19_fulldata);
            op2.finish();
        };
    },

    checkTestVectors: function TestRunner_checkTestVectors() {
        var i = '', item = '',
        lines = '',
        re = new RegExp('tv.t([_0-9A-Za-z])+', 'g'),
        vector, vectors;

        // get the source lines of enclosing object
        for (item in this) {
            if (this[item] !== null) {
                lines += this[item].toString();
            }
        }
        
        // find the references to test vector variables
        vectors = lines.match(re);
        
        for (i in vectors) {
            vector = vectors[i].substring(3);
            if (tv[vector] === null) {
                console.log('ERROR :: tv.' +vector+ ' is null');
                return false;
            } else if (tv[vector] === undefined) {
                console.log('ERROR :: tv.' +vector+ ' is undefined');
                return false;
            //} else {
            //    console.log('found vector: tv.' + vector);
            }
        }
        
        return true;
    },
    
    run: function() {
        if (!this.checkTestVectors()) {
            return;
        }
        // Invoke tests here
        this.test01();
        this.test02();
        this.test03();
        //this.test1();
        //this.test2();
        this.test3();
        this.test4();
        //this.test5();
        //this.test6();
        this.test7();
        this.test8();
        this.test9();
        this.test10();
        this.test11();
        this.test12();
        this.test13();
        this.test14();
        this.test15();
        this.test16();
        this.test17();
        this.test18();
        this.test19();
    }
};
//-----------------------------------------------------------------------------
window.polycrypt.onalive = function polycryptApiLoaded() {
    console.log('got backend alive');
    document.getElementById("go").disabled = false;
};
