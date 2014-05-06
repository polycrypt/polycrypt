var userRSAKey = null,        
userPublicKeyJWK = null,       
userNonceHex = null,
userNonceHashed = null,        
otherRSAPublicKey = null,    
otherNonceEncrypted = null,   
otherNonceHashed = null,
password = null,        
derivedKey = null;        

function startCrypto(callback) {

    if (window.polycrypt == undefined) {
        $("#working").text("Unable to start " + window.document.title + ", see the console for error messages");
        return;
    }

    window.polycrypt.onalive = function() {
        console.log("Creating Operation");

        var mL = 1024;

        /* Generate an RSA public/private key pair */
        var userPublicKeyOp = window.polycrypt.generateKey({
            name: "RSAES-PKCS1-v1_5",
            params: {
                modulusLength: mL,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01])
            }
        }, true, ["encrypt", "decrypt"]);

        /* Now export the key to jwk */
         userPublicKeyOp.oncomplete = function(e) {
            userRSAKey = e.target.result; 
            console.log("Finished User RSA :: " + userRSAKey.publicKey["key"].toString());
            
            var userPublicKeyExport = window.polycrypt.exportKey("jwk", userRSAKey.publicKey);

            userPublicKeyExport.onerror = function(e) {
                console.log("Failed to export the user key to JWK: " + e.target.result);
            }

            userPublicKeyExport.oncomplete = function(e) {
                userPublicKeyJWK = e.target.result;  
                document.getElementById("upkb").value = JSON.stringify(userPublicKeyJWK);                            
                callback();
                console.log("Exported RSA Key to JWK --> e:" + userPublicKeyJWK.e + ", n: " + userPublicKeyJWK.n);
            }
        }
            
        /* Generate and Hash a random nonce using SHA-256 */
        var userNonce = new Uint32Array(1);
        window.crypto.getRandomValues(userNonce);
        userNonceHex = window.util.hex2abv("" + userNonce[0]);
        var userNonceHashOp = window.polycrypt.digest("SHA-256", userNonceHex);
        
        userNonceHashOp.onerror = function(e) {
            console.log("Failed to hash the user's nonce: " + e.target.result);
        }

        userNonceHashOp.oncomplete = function(e) {
            console.log("Hashing is complete");
            var temp = e.target.result;
            userNonceHashed = window.util.abv2hex(temp);
            console.log("Finished SHA :: " + userNonceHashed);
        }
    }   
};   

/*
 *  This will encrypt the random hashed nonce with the other user's
 *  public RSA key
 */
var encryptNonce = function(successCallback, failureCallback, element) {
    /* Update the GUI */
    /*
    document.getElementById("deriveKey").disabled = false;
    document.getElementById("onb").disabled = false;
    document.getElementById("unb").disabled = false;

    document.getElementById("upkb").disabled = true;
    document.getElementById("opkb").disabled = true;

    document.getElementById("encryptNonce").disabled = true;
    */

    /* Get the other user's RSA public key from the GUI */
    var otherPublicKeyJWK = document.getElementById("opkb").value;
    console.log("Other Public Key: " + JSON.stringify(otherPublicKeyJWK));
    console.log("Nonce to encrypt: " + util.abv2hex(userNonceHex));

    /* Import the other user's public key */
    var importOp;
    try {
        importOp = window.polycrypt.importKey("jwk", JSON.parse(otherPublicKeyJWK), "RSAES-PKCS1-v1_5", true, ["encrypt", "decrypt"]);
    } catch (e) {
        failureCallback(element, "Unable to Extract Other Public Key");
        return;
    }
    importOp.onerror = function(e) {
        console.log("Failed to extract the other RSA Key: " + e.target.result);
        failureCallback(element);
    }

    importOp.oncomplete = function(e) {
        otherRSAPublicKey = e.target.result;
        console.log("Imported Other Public Key :" + otherRSAPublicKey);
        
        /* Encrypt the user's hashed nonce with the other user's public key */
        var encryptOp = window.polycrypt.encrypt("RSAES-PKCS1-v1_5", otherRSAPublicKey, userNonceHex);

        encryptOp.onerror = function(e) {
            console.log("ERROR with encrypt Operation");
            console.log(e.target.result);
            failureCallback(element, "Unable to encrypt your nonce");
        };

        encryptOp.oncomplete = function(e) {
            var encryptedData = e.target.result;
            console.log("Encrypted Nonce!");
            document.getElementById("unb").value = util.abv2hex(encryptedData);
            successCallback();
        };
    };
}

/*
 *  This will perform the key derivation procedure
 *  The other user's public RSA key is required
 *  The other user's Hashed Nonce encrypted with your public key is required
 *
 *  First it will decrypt the other's encrypted Hashed Nonce using your private key
 *  The derived key K will have the form: K = PBKDF2(password, H(N_user) XOR H(N_other),2048)
 */
var go = function(successCallback, failureCallback, element) {
    console.log("STARTED :: go");

    console.log("STARTED :: Decrypting Other Nonce with User RSA Key");
    console.log("Other Encrypted Nonce: " + document.getElementById("onb").value);

    if (document.getElementById("onb").value == "") {
        failureCallback(element, "Please enter the other user's encrypted nonce");
        return;
    }

    /* Decrypt the other user's nonce using our public key */
    var decryptNonceOp = window.polycrypt.decrypt("RSAES-PKCS1-v1_5", userRSAKey.privateKey, util.hex2abv(document.getElementById("onb").value));

    decryptNonceOp.onerror = function(e) {
        console.log("error decrypting other nonce: " + e.target.result);
        failureCallback(element, "Error decrypting the other nonce.  Please try again");
        return;
    }

    decryptNonceOp.oncomplete = function(e) {
        console.log("other nonce: " + util.abv2hex(e.target.result));

        /* Hash the other nonce using the other user's public key */
        var hashOtherNonceOp = polycrypt.digest("SHA-256", e.target.result);
        
        hashOtherNonceOp.onerror = function(e) {
            console.log("ERROR!  Unable to hash other nonce: " + e.target.result);
            failureCallback(element, "Unable to hash the other user's nonce.  Please try again");
            return;
        }

        hashOtherNonceOp.oncomplete = function(e) {
            console.log("Hashed other nonce: " + util.abv2hex(e.target.result));
            console.log("Our hashed nonce: " + userNonceHashed);

            /* Get the shared password from the user.  If none exists,
             * use the word "password"
             */
            password = document.getElementById("pwb").value;
            if (!password) {
                password = "password";
            }

            /* Generate the salt which is: salt = H(N_user) XOR H(N_other) */
            var generatedSalt = xor(e.target.result, util.hex2abv(userNonceHashed));
            
            /* Import the shared secret (password) as a RAW symmetric key for use with PBKDF2 */
            var importPasswordOp = window.polycrypt.importKey("raw", util.hex2abv(password));
            
            importPasswordOp.onerror = function(e) {
                console.log("Error importing password: " + e.target.result);
                failureCallback(element, "Unable to import your password.  Please try again");
                return;
            }

            importPasswordOp.oncomplete = function(e) {
                var key = e.target.result;

                /* Derive a shared key using PBKDF2 and SHA-1 */
                var deriveKeyOp = window.polycrypt.deriveKey(
                    {
                        name: "PBKDF2",
                        params: {
                            salt: generatedSalt,
                            iterations: 2048,
                            prf: "SHA-1"
                        }
                    },
                    key,
                    {
                        name: "AES-GCM",
                        params: {length: 128}
                    },
                    true,
                    ["encrypt", "decrypt"]
                );

                deriveKeyOp.onerror = function(e) {
                    console.log("Unable to derive key: " + e.target.result);
                    failureCallback(element, "Unable to derive a shared key.  Please try again");
                    return;
                }

                deriveKeyOp.oncomplete = function(e) {
                    derivedKey = e.target.result;
                    successCallback();
                    console.log("Derived the key!: " + JSON.stringify(derivedKey)); 
                }
            }
        }


    }

    /*
    document.getElementById("plaintext").disabled = false;
    document.getElementById("ciphertext").disabled = false;

    document.getElementById("encrypt").disabled = false;
    document.getElementById("decrypt").disabled = false;

    document.getElementById("upkb").disabled = true;
    document.getElementById("opkb").disabled = true;
    
    document.getElementById("unb").disabled = true;
    document.getElementById("onb").disabled = true;
    
    document.getElementById("pwb").disabled = true;

    document.getElementById("deriveKey").disabled = true;
    document.getElementById("encryptNonce").disabled = true;
    */
}

/*
 *  Computes the XOR of two byte arrays
 *  Assumes the two byte arrays have the same length
 */
var xor = function(first, second) {
    var len = first.length;
    var result = new Uint8Array(len);

    for (var i = 0; i < len; i++) {
        result[i] = first[i] ^ second[i];
    }

    return result;
}

/*
 *  Encrypt the text in "plaintext" and export it to "ciphertext"
 *  Encrypted form: IV:Encrypted Data:Additional Data
 */
var encrypt = function() {
    var myIv = new Uint8Array(16);
    window.crypto.getRandomValues(myIv);

    var data = util.str2abv(document.getElementById("userPlaintext").value);
    console.log("data: " + util.abv2hex(data));

    var additional = new Uint8Array(16);
    window.crypto.getRandomValues(additional);

    var encryptOp = window.polycrypt.encrypt({
        name: "AES-GCM",
        params: {
            iv: myIv,
            additionalData: additional,
            tagLength: 128
        }
    }, derivedKey, data);
            
    encryptOp.onerror = function(e) {
        console.log("Failed to encrypt plaintext: " + e.target.result);
    }

    encryptOp.oncomplete = function(e) {
        console.log("Encrypted plaintext: " + e.target.result);

        var all = util.abv2hex(myIv) + ":" + util.abv2hex(e.target.result) + ":" + util.abv2hex(additional);
        document.getElementById("userCiphertext").value = all;
        
        all = all.split(":");
        console.log("Encrypt IV: " + all[0]);
        console.log("Encrypted Payload: " + all[1]);
        console.log("Encrypt Additional Data: " + all[2]);
        console.log("Additional Data Length: " + util.hex2abv(all[2]).length * 8);
    }
}

/*
 *  Decrypt the text in "ciphertext" and export it to "plaintext"
 */
var decrypt = function() {
    var all = document.getElementById("otherCiphertext").value;
    
    /*
     * vals[0] = iv
     * vals[1] = output of block cipher
     * vals[2] = additionalData
     */
    var vals = all.split(":");

    console.log("Decrypt IV: " + vals[0]);
    console.log("Encrypted Payload: " + vals[1]);
    console.log("Decrypt Additional Data: " + vals[2]);
    console.log("Additional Data Length: " + util.hex2abv(vals[2]).length * 8);

    var decryptOp = window.polycrypt.decrypt({
        name: "AES-GCM",
        params: {
            iv: util.hex2abv(vals[0]),
            additionalData: util.hex2abv(vals[2]),
            tagLength: 128
        }
    }, derivedKey, util.hex2abv(vals[1]));
    
    decryptOp.onerror = function(e) {
        console.log("Error decrypting plaintext: " + e.target.result);
    }

    decryptOp.oncomplete = function(e) {
        console.log("Decrypted ciphertext is: " + util.abv2str(e.target.result)); 
        document.getElementById("otherPlaintext").value = util.abv2str(e.target.result);
    }
}

/*
 * Reset the entire page
 */
var reset = function() {
    document.location.reload(true);
}
