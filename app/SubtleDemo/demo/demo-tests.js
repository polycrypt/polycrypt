/*global TestArray, util, tv */

// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(1);'>Generate a 192-bit AES Key<div style='background:#C0C0C0'><label id='1' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",    
    function() {
        var length = 192;
        var op = window.polycrypt.generateKey({
            name: "AES-GCM",
            params: { length: 192 },
            extractable: true,
            keyUsage: ["Encrypt", "Decrypt"]
        });
        var that = this;
        op.onerror = function(e) {
            var params = "<font size=2><br>Error: " + e.target.result + "</font>";
            TestArray.addTestData(1, params);

            console.log("ERROR :: " + e.target.result);
            that.complete( false );
        };
        op.oncomplete = function(e) {
            console.log("COMPLETE :: " + e.target.result);
            var key = e.target.result;
            that.complete( 
                key.hasOwnProperty('type') &&
                key.hasOwnProperty('extractable') &&
                key.hasOwnProperty('algorithm') &&
                key.hasOwnProperty('keyUsage') 
            );

            var params = "<font size=2>";
            if (key.hasOwnProperty('type')) {
                params += "Type: " + key.type + "<br>";
            } 
                         
            if (key.hasOwnProperty('algorithm')) {
                params += "Algorithm: " + key.algorithm;
            }

            params += "</font>";
            TestArray.addTestData(1, params);

        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(2);'>Generate a 512-bit RSA Key<div style='background:#C0C0C0'><label id='2' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",  
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
            that.complete( false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(2, params);
        };
        op.oncomplete = function(e) {
            console.log("COMPLETE :: " + e.target.result);
            var key = e.target.result;
            that.complete(  
                key.hasOwnProperty('publicKey') &&
                key.hasOwnProperty('privateKey')
            );

            var params = "<font size=2>";
            if (key.hasOwnProperty('publicKey')) {
                params += "Public Key: " + key.publicKey.key + "<br>";
            }
             
            if (key.hasOwnProperty('privateKey')) {
                params += "Private Key: " + key.privateKey.key;
            }

            params += "</font>";
            TestArray.addTestData(2, params);
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(3);'>Import an AES Key<div style='background:#C0C0C0'><label id='3' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function() {
        var op = window.polycrypt.importKey(
            "raw",
            util.hex2abv("f3095c4fe5e299477643c2310b44f0aa"),
            "AES-GCM"
        );
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete( false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(3, params);
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

            var params = "<font size=2>";
            if (key.hasOwnProperty('type')) {
                params += "Type: " + key.type + "<br>";
            }
            
            if (key.hasOwnProperty('algorithm')) {
                params += "Algorithm: " + key.algorithm + "<br>";
            }
                             
            if (key.hasOwnProperty('key')) {
                params += "Key: " + key.key + "<br>";
            }
            
            if (key.key.length === 48) {
                params += "Key Length: " + 48;
            }

            params += "</font>";
            TestArray.addTestData(3, params);
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
        "<div style='width:750px' onclick='TestArray.toggleTestData(4);'>Export an RSA Key<div style='background:#C0C0C0'><label id='4' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function() {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t7_rsa_n ),
            e: util.b64encode( tv.t7_rsa_e ),
            d: util.b64encode( tv.t7_rsa_d )
        };
        var op = window.polycrypt.importKey("jwk", jwk, "RSAES-PKCS1-v1_5");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false);

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(4, params);
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.exportKey("jwk", key);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false);

                var params = "<font size=2>Error: " + e.target.result + "</font>";
                TestArray.addTestData(4, params);

            };
            op2.oncomplete = function(e) {
                var jwk2 = e.target.result;
                console.log("COMPLETE :: " + e.target.result);
                that.complete(
                    (jwk.n === jwk2.n)
                    && (jwk.e === jwk2.e)
                    && (jwk.d === jwk2.d)
                );

                var params = "<font size=2>";
                if (jwk.n === jwk2.n) {
                    params += "n: " + jwk.n + "<br>";
                }
                  
                if (jwk.e === jwk2.e) {
                    params += "e: " + jwk.e + "<br>";
                }
                
                if (jwk.d === jwk2.d) {
                    params += "d: " + jwk.d + "<br>";
                }

                params += "</font>"
                TestArray.addTestData(4, params);

            };
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
        "<div style='width:750px' onclick='TestArray.toggleTestData(5);'>SHA-256 Digest<div style='background:#C0C0C0'><label id='5' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function() {
        var that = this;
        var op = window.polycrypt.digest("SHA-256", tv.t3_data);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete( false );
            
            var params = "<font size=2>Input: " + util.abv2hex(tv.t3_data);
            params += "<br>Error: " + e.target.result + "</font>";

            TestArray.addTestData(5, params);
        };
        op.oncomplete = function(e) {
            console.log("COMPLETE :: " + e.target.result);
            that.memcmp_complete(tv.t3_result, e.target.result); 
        
            var params = "<font size=2>Input: " + util.abv2hex(tv.t3_data);
            params += "<br>Digest: " + util.abv2hex(tv.t3_result) + "</font>";

            TestArray.addTestData(5, params);
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(6);'>HMAC SHA-256<div style='background:#C0C0C0'><label id='6' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function() {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t4_key, '', false, ['sign']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Input: " + util.abv2hex(tv.t4_data);
            params += "<br>Error: " + e.target.result + "</font>";

            TestArray.addTestData(6, params);

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

                var params = "<font size=2>Input: " + util.abv2hex(tv.t4_data);
                params += "<br>Error: " + e.target.result + "</font>";

                TestArray.addTestData(6, params);

            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t4_result, e.target.result );

                var params = "<font size=2>Input: " + util.abv2hex(tv.t4_data);
                params += "<br>Result: " + util.abv2hex(e.target.result) + "</font>";

                TestArray.addTestData(6, params);

            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(7);'>RSAES Encryption<div style='background:#C0C0C0'><label id='7' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t7_rsa_n ),
            e: util.b64encode( tv.t7_rsa_e ),
            d: util.b64encode( tv.t7_rsa_d )
        };
        var op = window.polycrypt.importKey("jwk", jwk, "RSAES-PKCS1-v1_5", false, ['encrypt', 'decrypt']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(7, params);

        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.encrypt("RSAES-PKCS1-v1_5", key, tv.t7_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );

                var params = "<font size=2>Input: " + util.abv2hex(tv.t7_data);
                params += "<br>Error: " + e.target.result + "</font>";
                TestArray.addTestData(7, params);

            };
            op2.oncomplete = function(e) {
                var data = e.target.result;
                var op3 = window.polycrypt.decrypt("RSAES-PKCS1-v1_5", key, data);
                op3.onerror = function(e) {
                    console.log("ERROR :: " + e.target.result);
                    that.complete(false );

                    var params = "<font size=2>Error: " + e.target.result + "</font>";
                    TestArray.addTestData(7, params);

                };
                op3.oncomplete = function(e) {
                    console.log("COMPLETE :: " + e.target.result);
                    that.memcmp_complete(tv.t7_data, e.target.result );

                    var params = "<font size=2>Original Plaintext: " + util.abv2hex(tv.t7_data);
                    params += "<br>Decrypted Plaintext: " + util.abv2hex(e.target.result) + "</font>";

                    TestArray.addTestData(7, params);

                };
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(8);'>RSAES Decryption<div style='background:#C0C0C0'><label id='8' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () { 
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t8_rsa_n ),
            e: util.b64encode( tv.t8_rsa_e ),
            d: util.b64encode( tv.t8_rsa_d )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSAES-PKCS1-v1_5", false, ['encrypt', 'decrypt']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(8, params);

        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.decrypt("RSAES-PKCS1-v1_5", key, tv.t8_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
                                    
                var params = "<font size=2>Error: " + e.target.result + "</font>";

                TestArray.addTestData(8, params);

            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t8_result, e.target.result);

                var params = "<font size=2>Original Plaintext: " + util.abv2hex(tv.t8_result);
                params += "<br>Decrypted Plaintext: " + util.abv2hex(e.target.result) + "</font>";

                TestArray.addTestData(8, params);

            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(9);'>RSASSA SHA-1 signature<div style='background:#C0C0C0'><label id='9' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () { 
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t9_rsa_n ),
            e: util.b64encode( tv.t9_rsa_e ),
            d: util.b64encode( tv.t9_rsa_d )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5", false, ['sign', 'verify']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";

            TestArray.addTestData(9, params);
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

                var params = "<font size=2>Error: " + e.target.result + "</font>";

                TestArray.addTestData(9, params);                
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t9_sig, e.target.result);

                var params = "<font size=2>Message: " + util.abv2hex(tv.t9_data);
                params += "<br>Signature: " + util.abv2hex(e.target.result);
                params += "</font>";

                TestArray.addTestData(9, params);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(10);'>RSASSA Verification (SHA-1)<div style='background:#C0C0C0'><label id='10' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t10_rsa_n ),
            e: util.b64encode( tv.t10_rsa_e )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5", false, ['sign', 'verify']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(10, params); 
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.verify("RSASSA-PKCS1-v1_5", key, tv.t10_sig, tv.t10_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );

                var params = "<font size=2>Error: " + e.target.result;

                TestArray.addTestData(10, params); 
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.complete(e.target.result);

                var params = "<font size=2>Message: " + util.abv2hex(tv.t10_data);
                params += "<br>Signature: " + util.abv2hex(tv.t10_sig);
                params += "</font>";

                TestArray.addTestData(10, params);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(11);'>RSASSA SHA-256 signature<div style='background:#C0C0C0'><label id='11' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () { 
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t11_rsa_n ),
            e: util.b64encode( tv.t11_rsa_e ),
            d: util.b64encode( tv.t11_rsa_d )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5", false, ['sign', 'verify']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(11, params); 

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

                var params = "<font size=2>Error: " + e.target.result + "</font>";
                TestArray.addTestData(11, params); 
            };

            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t11_sig, e.target.result);

                var params = "<font size=2>Message: " + util.abv2hex(tv.t11_data);
                params += "<br>Signature: " + util.abv2hex(e.target.result);
                params += "</font>";

                TestArray.addTestData(11, params);

            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(12);'>RSASSA Verification (SHA-256)<div style='background:#C0C0C0'><label id='12' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () {
        var that = this;
        var jwk = {
            n: util.b64encode( tv.t12_rsa_n ),
            e: util.b64encode( tv.t12_rsa_e )
        };
        console.log(jwk);
        var op = window.polycrypt.importKey("jwk", jwk, "RSASSA-PKCS1-v1_5", false, ['sign', 'verify']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(12, params); 
        };

        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.polycrypt.verify("RSASSA-PKCS1-v1_5", key, tv.t12_sig, tv.t12_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );

                var params = "<font size=2>Error: " + e.target.result + "</font>";
                TestArray.addTestData(12, params); 
            };

            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.complete(e.target.result);

                var params = "<font size=2>Message: " + util.abv2hex(tv.t12_data);
                params += "<br>Signature: " + util.abv2hex(tv.t12_sig);
                params += "</font>";

                TestArray.addTestData(12, params);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(13);'>AES-CBC Encryption<div style='background:#C0C0C0'><label id='13' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t13_key, "AES-CBC", false, ['encrypt', 'decrypt']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        
            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(13, params); 
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

                var params = "<font size=2>Plaintext: " + util.abv2hex(tv.t13_data);
                params += "<br>IV: " + util.abv2hex(tv.t13_iv); 
                params += "<br>Error: " + e.target.result;
                params += "</font>";
                TestArray.addTestData(20, params);
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t13_result, e.target.result );

                var params = "<font size=2>Plaintext: " + util.abv2hex(tv.t13_data); 
                params += "<br>IV: " + util.abv2hex(tv.t13_iv); 
                params += "<br>Ciphertext: " + util.abv2hex(e.target.result);
                params += "</font>";

                TestArray.addTestData(13, params);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(14);'>AES-CBC Decryption<div style='background:#C0C0C0'><label id='14' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t14_key, "AES-CBC", false, ['encrypt', 'decrypt']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(14, params); 

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

                var params = "<font size=2>Ciphertext: " + util.abv2hex(tv.t14_result);
                params += "<br>IV: " + util.abv2hex(tv.t14_iv);
                params += "<br>Error: " + e.target.result;
                params += "</font>";

                TestArray.addTestData(14, params);
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t14_result, e.target.result );

                var params = "<font size=2>Ciphertext: " + util.abv2hex(tv.t14_result);
                params += "<br>IV: " + util.abv2hex(tv.t14_iv);
                params += "<br>Plaintext: " + util.abv2hex(e.target.result);
                params += "</font>"

                TestArray.addTestData(14, params);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(15);'>AES-CTR Encryption<div style='background:#C0C0C0'><label id='15' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t15_key, '', false, ['encrypt', 'decrypt']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(15, params); 

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

                var params = "<font size=2>Plaintext: " + util.abv2hex(tv.t15_data);
                params += "<br>Counter: " + util.abv2hex(tv.t15_iv);
                params += "<br>Error: " + e.target.result;
                TestArray.addTestData(15, params);
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t15_result, e.target.result );

                var params = "<font size=2>Plaintext: " + util.abv2hex(tv.t15_data);
                params += "<br>Counter: " + util.abv2hex(tv.t15_iv);
                params += "<br>Ciphertext: " + util.abv2hex(e.target.result) + "</font>";
                TestArray.addTestData(15, params); 
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(16);'>AES-CTR Decryption<div style='background:#C0C0C0'><label id='16' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () { 
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t16_key, '', false, ['encrypt', 'decrypt']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(16, params); 

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

                var params = "<font size=2>Plaintext: " + util.abv2hex(tv.t16_data);
                params += "<br>Counter: " + util.abv2hex(tv.t16_iv);
                params += "<br>Error: " + e.target.result;
                TestArray.addTestData(16, params);
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t16_result, e.target.result );

                var params = "<font size=2>Plaintext: " + util.abv2hex(tv.t16_data);
                params += "<br>Counter: " + util.abv2hex(tv.t16_iv);
                params += "<br>Ciphertext: " + util.abv2hex(e.target.result) + "</font>";
                TestArray.addTestData(16, params);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(17);'>PBKDF2 Key Derivation<div style='background:#C0C0C0'><label id='17' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () {
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t17_data);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result + "</font>");
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result;
            TestArray.addTestData(17, params); 
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

                var params = "<font size=2>Error: " + e.target.result + "</font>";
                TestArray.addTestData(17, params); 

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

                var params = "<font size=2>";
                if (key.hasOwnProperty('type')) {
                    params += "Key Type: " + key.type + "<br>";
                }
                    
                if (key.hasOwnProperty('algorithm')) {
                    params += "Algorithm: " + key.algorithm.name + "<br>";
                }
                    
                if (key.hasOwnProperty('key')) {
                    params += "Key: " + key.key + "<br>";
                }
                    
                params += "</font>";
                TestArray.addTestData(17, params);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(18);'>AES-GCM Encryption<div style='background:#C0C0C0'><label id='18' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () { 
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t18_key, '', false, ['encrypt', 'decrypt']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(18, params); 
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

                var params = "<font size=2>Plaintext: " + tv.t18_data;
                params += "<br>IV: " + util.abv2hex(tv.t18_iv);
                params += "<br>Additional Data: " + util.abv2hex(tv.t18_adata);
                params += "<br>Tag Length: 128";
                params += "<br>Error: " + e.target.result;
                TestArray.addTestData(18, params); 
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                // Concatenate the result and tag
                var t18_fullresult = util.abvcat(
                    tv.t18_result,
                    tv.t18_tag
                );
                that.memcmp_complete(t18_fullresult, e.target.result );

                var params = "<font size=2>Plaintext: " + util.abv2hex(tv.t18_data);
                params += "<br>IV: " + util.abv2hex(tv.t18_iv);
                params += "<br>Additional Data: " + util.abv2hex(tv.t18_adata);
                params += "<br>Tag Length: 128";
                params += "<br>Ciphertext: " + util.abv2hex(e.target.result) + "</font>";
                TestArray.addTestData(18, params); 

            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(19);'>AES-GCM Decryption<div style='background:#C0C0C0'><label id='19' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function () { 
        var that = this;
        var op = window.polycrypt.importKey("raw", tv.t19_key, '', false, ['encrypt', 'decrypt']);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );

            var params = "<font size=2>Error: " + e.target.result + "</font>";
            TestArray.addTestData(19, params); 
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

                    var params = "<font size=2>Ciphertext: " + tv.t18_data;
                    params += "<br>IV: " + util.abv2hex(tv.t18_iv);
                    params += "<br>Additional Data: " + util.abv2hex(tv.t18_adata);
                    params += "<br>Tag Length: 128";
                    params += "<br>Error: " + e.target.result + "</font>";
                    TestArray.addTestData(19, params); 
            };
            op2.oncomplete = function(e) {
                console.log("COMPLETE :: " + e.target.result);
                that.memcmp_complete(tv.t19_result, e.target.result );

                var params = "<font size=2>Ciphertext: " + util.abv2hex(tv.t19_data);
                params += "<br>IV: " + util.abv2hex(tv.t19_iv);
                params += "<br>Additional Data: " + util.abv2hex(tv.t19_adata);
                params += "<br>Tag Length: 128";
                params += "<br>Plaintext: " + util.abv2hex(e.target.result) + "</font>";
                TestArray.addTestData(19, params); 
            };
        };
    }
);

//-------------------------------------------------------------------------------
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(20);'><font color='blue'>AES-CBC Encryption</font><div style='background:#C0C0C0'><label id='20' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function() {
        var that = this;        

        var cbcKey = window.crypto.subtle.importKey(["secret"], ["raw"], tv.t13_key, "aes-cbc", "AES-CBC Key 1", false, 2); 

        var encOp = window.crypto.subtle.encrypt({name:"aes-cbc", iv:tv.t13_iv}, cbcKey, tv.t13_data);
        encOp.onerror = function() {
            var params = "<font size=2>Plaintext: " + util.abv2hex(tv.t13_data);
            params += "<br>IV: " + util.abv2hex(tv.t13_iv); 
            params += "<br>Error: " + this.error.name;
            params += "</font>";
            TestArray.addTestData(20, params);
            that.complete(false);
            window.crypto.token.deleteSymKey("AES-CBC Key 1");
        }

        encOp.onsuccess = function() {
            var params = "<font size=2>Plaintext: " + util.abv2hex(tv.t13_data); 
            params += "<br>IV: " + util.abv2hex(tv.t13_iv); 
            params += "<br>Ciphertext: " + this.result;
            params += "</font>";

            TestArray.addTestData(20, params);
            that.memcmp_complete(tv.t13_result, window.crypto.subtle.strTOabv(this.result));   
            window.crypto.token.deleteSymKey("AES-CBC Key 1");
        }
    }
);

TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(21);'><font color='blue'>AES-CBC Decryption</font><div style='background:#C0C0C0'><label id='21' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function() {
        var that = this;       
        var cbcKey = window.crypto.subtle.importKey(["secret"], ["raw"], tv.t13_key, "aes-cbc", "AES-CBC Key 2", false, 2); 

        var decOp = window.crypto.subtle.decrypt({name:"aes-cbc", iv:tv.t13_iv}, cbcKey, tv.t13_result);

        decOp.onerror = function() {
            var params = "<font size=2>Ciphertext: " + util.abv2hex(tv.t13_result);
            params += "<br>IV: " + util.abv2hex(tv.t13_iv);
            params += "<br>Error: " + this.error.name;
            params += "</font>";

            TestArray.addTestData(21, params);
            that.complete(false);
            window.crypto.token.deleteSymKey("AES-CBC Key 2");
        }

        decOp.onsuccess = function() {
            var result = window.crypto.subtle.strTOabv(this.result);

            var params = "<font size=2>Ciphertext: " + util.abv2hex(tv.t13_result);
            params += "<br>IV: " + util.abv2hex(tv.t13_iv);
            params += "<br>Plaintext: " + this.result;
            params += "</font>"

            TestArray.addTestData(21, params);
            that.memcmp_complete(tv.t13_data, window.crypto.subtle.strTOabv(this.result));
            window.crypto.token.deleteSymKey("AES-CBC Key 2");
        }
    }
)

/*
TestArray.addTest(
    "<div style='width:750px' onclick='TestArray.toggleTestData(22);'><font color='blue'>RSA PKCS#1v1.5 Encryption</font><div style='background:#C0C0C0'><label id='22' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",  
    function() {
        var that = this;

        window.message = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        window.publicKeyStr = window.crypto.subtle.B64Decode("MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL3F6TIc3JEYsugo+a2fPU3W+Epv/FeIX21DC86WYnpFtW4srFtz2oNUzyLUzDHZdb+k//8dcT3IAOzUUi3R2eMCAwEAAQ==");
        window.privateKeyStr = window.crypto.subtle.B64Decode("MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAvcXpMhzckRiy6Cj5rZ89Tdb4Sm/8V4hfbUMLzpZiekW1biysW3Pag1TPItTMMdl1v6T//x1xPcgA7NRSLdHZ4wIDAQABAkEAjh8+4qncwcmGivnM6ytbpQT+k/jEOeXG2bQhjojvnXN3FazGCEFXvpuIBcJVfaIJS9YBCMOzzrAtO0+k2hWnOQIhAOC4NVbo8FQhZS4yXM1M86kMl47FA9ui//OUfbhlAdw1AiEA2DBmIXnsboKB+OHver69p0gNeWlvcJc9bjDVfdLVsLcCIQCPtV3vGYJv2vdwxqZQaHC+YB4gIGAqOqBCbmjD3lyFLQIgA+VTYdUNoqwtZWvE4gRf7IzK2V5CCNhg3gR5RGwxN58CIGCcafoRrUKsM66ISg0ITI04G9V/w+wMx91wjEEB+QBz");


        var pubKey = window.crypto.subtle.importKey(["public"], ["spki"], window.publicKeyStr, "rsa", "RSA Encrypt Key", false, 2)

        var encOp = window.crypto.subtle.encrypt({name:"rsaes-pkcs1-v1_5"}, pubKey, window.message); 

        encOp.onerror = function() {
            var params = "<font size=2>Plaintext: " + util.abv2hex(window.message);
            params += "<br>Error: " + this.error.name;
            params += "</font>";

            TestArray.addTestData(22, params);
            that.complete(false);
            window.crypto.token.deletePublicKey("RSA Encrypt Key");
            window.message = null;

        }

        encOp.onsuccess = function() {
            var params = "<font size=2>Ciphertext: " + this.result;
            params += "<br>Plaintext: " + util.abv2hex(window.message);
            params += "</font>"

            TestArray.addTestData(22, params);
            that.complete(true);
            window.crypto.token.deletePublicKey("RSA Encrypt Key");
            window.message = null;
        }
    }
);
*/

/*
TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(23);'><font color='blue'>HMAC - SHA1</font><div style='background:#C0C0C0'><label id='23' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",    
    function() {
        var that = this;

        var hmacKey = window.crypto.subtle.importKey(["secret"], ["raw"], tv.t4_key, "aes-cbc", "HMAC-Key", false, 8);

        var hmacOp = window.crypto.subtle.sign({name:"hmac", mHash:"sha-1"}, hmacKey, tv.t4_data);

        hmacOp.onerror = function() {
            var params = "<font size=2>Message: " + util.abv2hex(tv.t4_data);
            params += "<br>Error: " + this.error.name;
            params += "</font>";

            TestArray.addTestData(23, params);
            that.complete(false);
        }

        hmacOp.onsuccess = function() {
            var params = "<font size=2>Message: " + util.abv2hex(tv.t4_data);
            params += "<br>Digest: " + this.result;
            params += "</font>";

            TestArray.addTestData(23, params);
            that.memcmp_complete(window.crypto.subtle.strTOabv(this.result), tv.tv_result);   
        }
    }
);
*/

TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(22);'><font color='blue'>Generate a 192-bit AES Key</font><div style='background:#C0C0C0'><label id='22' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",    
    function() {
        var that = this;
        
        var aesKey = window.crypto.subtle.generateKey({name:"aes-cbc", length:192}, "Test AES Key", true, 2);

        var params = "<font size=2>Key Type: Secret";
        params += "<br>Algorithm: AES-CBC";
        params += "<br>Key Length: 192";
        params += "<br>Nickname: Test AES Key";
        params += "</font>";
        TestArray.addTestData(22, params);


        if (!aesKey) {
            that.complete(false);
        } else {
            if (window.crypto.subtle.findKey(["secret"], 2, "Test AES Key", "aes-cbc")) {
                that.complete(true);   
            } else {
                that.complete(false);
            }
        }

        window.crypto.token.deleteSymKey("Test AES Key");
    }
);

TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(23);'><font color='blue'>Generate a 512-bit RSA Key</font><div style='background:#C0C0C0'><label id='23' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",    
    function() {
        var that = this;
        
        var rsaKey = window.crypto.subtle.generateKey({name:"rsa", length:512}, "Test RSA Key", true, 2);

        var params = "<font size=2>Key Type: Public";
        params += "<br>Algorithm: RSA";
        params += "<br>Key Length: 512";
        params += "<br>Nickname: Test RSA Key";
        params += "</font>";
        TestArray.addTestData(23, params);


        if (!rsaKey) {
            that.complete(false);
        } else {
            if (window.crypto.subtle.findKey(["public"], 2, "Test RSA Key", "rsa")) {
                that.complete(true);   
            } else {
                that.complete(false);
            }
        }

        window.crypto.token.deletePublicKey("Test RSA Key");
        window.crypto.token.deletePrivateKey("Test RSA Key");
    }
);


TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(24);'><font color='blue'>Import an AES Key</font><div style='background:#C0C0C0'><label id='24' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",
    function() {
        var that = this;       
        var cbcKey = window.crypto.subtle.importKey(["secret"], ["raw"], tv.t13_key, "aes-cbc", "Test AES Key", false, 2); 

        var params = "<font size=2>Key Type: Secret";
        params += "<br>Algorithm: AES-CBC";
        params += "<br>Key Length: 192";
        params += "<br>Nickname: Test AES Key";
        params += "<br>Key Data: " + util.abv2hex(tv.t13_key);
        params += "</font>";

        TestArray.addTestData(24, params);

        if (!cbcKey) {
            that.complete(false);
        } else {
            if (window.crypto.subtle.findKey(["secret"], 2, "Test AES Key", "aes-cbc")) {
                that.complete(true);
            } else {
                that.complete(false);
            }
        }

        window.crypto.token.deleteSymKey("Test AES Key");
    }
)

TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(25);'><font color='blue'>SHA-1 Digest</font><div style='background:#C0C0C0'><label id='25' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",    
   function() {
        var that = this;

        var digestOp = window.crypto.subtle.digest({name:"sha-1"}, tv.t20_sha1_input);

        digestOp.onerror = function() {
            var params = "<font size=2>Message: " + util.abv2hex(tv.t20_sha1_input);
            params += "<br>Error: " + this.error.name;
            params += "</font>";

            TestArray.addTestData(25, params);
            that.complete(false);
        }

        digestOp.onsuccess = function() {
            var params = "<font size=2>Message: " + util.abv2hex(tv.t20_sha1_input);
            params += "<br>Digest: " + this.result;
            params += "</font>";

            TestArray.addTestData(25, params);
            that.memcmp_complete(tv.t20_sha1_result, window.crypto.subtle.strTOabv(this.result));   
        }
    }
);

TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(26);'><font color='blue'>SHA-256 Digest</font><div style='background:#C0C0C0'><label id='26' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",    
    function() {
        var that = this;

        var digestOp = window.crypto.subtle.digest({name:"sha-256"}, tv.t3_data);

        digestOp.onerror = function() {
            var params = "<font size=2>Message: " + util.abv2hex(tv.t3_data);
            params += "<br>Error: " + this.error.name;
            params += "</font>";

            TestArray.addTestData(26, params);
            that.complete(false);
        }

        digestOp.onsuccess = function() {
            var params = "<font size=2>Message: " + util.abv2hex(tv.t3_data);
            params += "<br>Digest: " + this.result;
            params += "</font>";

            TestArray.addTestData(26, params);
            that.memcmp_complete(tv.t3_result, window.crypto.subtle.strTOabv(this.result));  
        }
    }
);

TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(27);'><font color='blue'>SHA-512 Digest</font><div style='background:#C0C0C0'><label id='27' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",    
    function() {
        var that = this;

        var digestOp = window.crypto.subtle.digest({name:"sha-512"}, tv.t21_sha512_input);

        digestOp.onerror = function() {
            var params = "<font size=2>Message: " + util.abv2hex(tv.t21_sha512_input);
            params += "<br>Error: " + this.error.name;
            params += "<br></font>";

            TestArray.addTestData(27, params);
            that.complete(false);
        }

        digestOp.onsuccess = function() {
            var params = "<font size=2>Message: " + util.abv2hex(tv.t21_sha512_input);
            params += "<br>Digest: " + this.result;
            params += "<br></font>";

            TestArray.addTestData(27, params);
            that.memcmp_complete(tv.t21_sha512_result, window.crypto.subtle.strTOabv(this.result));  
        }
    }
);

TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(28);'><font color='blue'>RSA PKCS#1v1.5 (SHA-1) Signature Generation</font><div style='background:#C0C0C0'><label id='28' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",    
   function() {
        var that = this;

        window.message = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        window.publicKeyStr = window.crypto.subtle.B64Decode("MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL3F6TIc3JEYsugo+a2fPU3W+Epv/FeIX21DC86WYnpFtW4srFtz2oNUzyLUzDHZdb+k//8dcT3IAOzUUi3R2eMCAwEAAQ==");
        window.privateKeyStr = window.crypto.subtle.B64Decode("MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAvcXpMhzckRiy6Cj5rZ89Tdb4Sm/8V4hfbUMLzpZiekW1biysW3Pag1TPItTMMdl1v6T//x1xPcgA7NRSLdHZ4wIDAQABAkEAjh8+4qncwcmGivnM6ytbpQT+k/jEOeXG2bQhjojvnXN3FazGCEFXvpuIBcJVfaIJS9YBCMOzzrAtO0+k2hWnOQIhAOC4NVbo8FQhZS4yXM1M86kMl47FA9ui//OUfbhlAdw1AiEA2DBmIXnsboKB+OHver69p0gNeWlvcJc9bjDVfdLVsLcCIQCPtV3vGYJv2vdwxqZQaHC+YB4gIGAqOqBCbmjD3lyFLQIgA+VTYdUNoqwtZWvE4gRf7IzK2V5CCNhg3gR5RGwxN58CIGCcafoRrUKsM66ISg0ITI04G9V/w+wMx91wjEEB+QBz");
        
        var privateKey = window.crypto.subtle.importKey(["private"], ["pkcs8"], window.privateKeyStr, "rsa", "Test RSA Private Key", false, 4);

        var signOp = window.crypto.subtle.sign({name:"rsassa-pkcs1-v1_5", hash:"sha-1"}, privateKey, window.message);

        signOp.onerror = function() {
            var params = "<font size=2>Message: " + util.abv2hex(window.message);
            params += "<br>Error: " + this.error.name;
            params += "</font>";

            TestArray.addTestData(28, params);
            that.complete(false);   

            window.crypto.token.deletePrivateKey("Test RSA Private Key");
        }

        signOp.onsuccess = function() {
            var params = "<font size=2>Message: " + util.abv2hex(window.message);
            params += "<br>Signature: " + this.result;
            params += "</font>";

            TestArray.addTestData(28, params);

            window.signature = window.crypto.subtle.strTOabv(this.result);
            if (this.result != null) {
                that.complete(true);
            } else {
                that.complete(false);
            }

            window.crypto.token.deletePrivateKey("Test RSA Private Key");
        }
    }
)

TestArray.addTest(
   "<div style='width:750px' onclick='TestArray.toggleTestData(29);'><font color='blue'>RSA PKCS#1v1.5 (SHA-1) Signature Verification</font><div style='background:#C0C0C0'><label id='29' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",   
    function() {
        var that = this;
        var publicKey = window.crypto.subtle.importKey(["public"], ["spki"], window.publicKeyStr, "rsa", "Test RSA Public Key", false, 8)

        var signature = util.hex2abv("5d4c5c448eeee992e9df02e7fb66ba16b1eab8e0baa4665beb69bce79025191c183ea5e5da251bd4834cf59e851e7b7061d6965034467906cf89386d59ce7df2");

        var verifyOp = window.crypto.subtle.verify({name:"rsassa-pkcs1-v1_5", hash:"sha-1"}, publicKey, signature, window.message);
        
        verifyOp.onerror = function() {
            var params = "<font size=2>Message: " + util.abv2hex(window.message);
            params += "<br>Error: " + this.error.name;
            params += "</font>";

            TestArray.addTestData(29, params);
            window.message = null;
            window.signature = null;
            window.publicKeyStr = null;
            window.privateKeyStr = null;
            
            that.complete(false);
            window.crypto.token.deletePublicKey("Test RSA Public Key");

        }

        verifyOp.onsuccess = function() {
            var params = "<font size=2>Message: " + util.abv2hex(window.message);
            params += "<br>Signature: " + util.abv2hex(signature);
            params += "</font>";

            TestArray.addTestData(29, params);
            
            if (this.result === "01") {
                that.complete(true);
            } else {
                that.complete(false);
            }

            window.message = null;
            window.signature = null;
            window.publicKeyStr = null;
            window.privateKeyStr = null;
            window.crypto.token.deletePublicKey("Test RSA Public Key");

        }
    }
//)
//    
//TestArray.addTest(
//   "<div style='width:750px' onclick='TestArray.toggleTestData(30);'><font color='blue'>Generate 192-bit AES Key</font><div style='background:#C0C0C0'><label id='30' style='visibility:hidden;display:none;width:750px;overflow:auto'></label></div></div>",    
//    function() {
//        var that = this;
//
//        var op = window.crypto.subtle.generateKey({name:"aes-cbc", length:24}, "test1234", false, 3);
//        var params = "<font size=2>Message: " + util.abv2hex(tv.t21_sha512_input);
//        params += "<br>Digest: " + this.result;
//        params += "<br></font>";
//
//        TestArray.addTestData(30, params);
//
//        //digestOp.onerror = function() {
//        //   var params = "<font size=2>Message: " + util.abv2hex(tv.t21_sha512_input);
//        //    params += "<br>Error: " + this.error.name;
//        //    params += "<br></font>";
//
//        //    TestArray.addTestData(27, params);
//        //    that.complete(false);
//        //}
//
//        //digestOp.onsuccess = function() {
//        //    var params = "<font size=2>Message: " + util.abv2hex(tv.t21_sha512_input);
//        //    params += "<br>Digest: " + this.result;
//        //    params += "<br></font>";
//
//        //    TestArray.addTestData(27, params);
//        //    that.memcmp_complete(tv.t21_sha512_result, window.crypto.subtle.strTOabv(this.result));  
//        //}
//    }
);
