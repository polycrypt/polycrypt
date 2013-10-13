/*global self, Uint32Array */

// CryptoJS requirements
importScripts('./lib/CryptoJS/core-min.js');
importScripts('./lib/CryptoJS/cipher-core-min.js');
importScripts('./lib/CryptoJS/aes-min.js');
// jsbn requirements
importScripts('./lib/jsbn.js');
importScripts('./lib/jsbn2.js');
importScripts('./lib/rsa.js');
importScripts('./lib/rsa2.js');
importScripts('./lib/prng4.js');
importScripts('./lib/rng.js');
// Crypto glue
importScripts('./libpolycrypt.js');

Impl.extend({

    generate: function generate(args) {
        'use strict';

        var algorithm = args['algorithm'] || null;
        var keyUsages = args['keyUsages'] || [];
        var extractable = args['extractable'];
        if (!('extractable' in args)) {
            extractable = true;
        }

        if (!algorithm) {
            this.die('Algorithm must be provided');
        }
        
        var bareKey, type;
        var algoName = this.algoName(algorithm);
        switch (algoName) {
            case "AES-CTR":
            case "AES-CBC":
            case "AES-GCM":
                if (!algorithm.params || !algorithm.params.hasOwnProperty('length')) {
                    this.die('Key length must be provided');
                    return;
                }
                var length = algorithm.params.length;
                if ((length != 128) && (length != 192) && (length != 256)) {
                    this.die('Invalid AES key length ' + length);
                    return;
                }
                type = "secret";
                bareKey = libpolycrypt.random(algorithm.params.length >> 3);
                var key = {
                    type: type,
                    extractable: extractable,
                    algorithm: algoName,
                    keyUsage: keyUsages,
                    key: bareKey,
                };
                key = libpolycrypt.wrap_key(this.apiKey, key);
                this.complete(key);
                break;

            case "RSAES-PKCS1-v1_5":
            case "RSASSA-PKCS1-v1_5":
            case "RSA-OAEP":
            case "RSA-PSS":
                if (!algorithm.params || !algorithm.params.hasOwnProperty('modulusLength') ||
                    !algorithm.params.hasOwnProperty('publicExponent')) {
                    this.die('Modulus length and public exponent must be provided');
                    return;
                }
                var length = algorithm.params.modulusLength;
                var e = util.abv2hex(algorithm.params.publicExponent);
                var rsa = libpolycrypt.rsa_generate(length, e);
                // Store key values as hex strings
                bareKey = {};
                for (var ix in rsa) {
                    if ((rsa[ix].constructor == BigInteger)||(rsa[ix].constructor === Number)) {
                        bareKey[ix] = rsa[ix].toString(16);
                    }
                }
                var keyPair = {};
                keyPair.publicKey = {
                    type: 'public',
                    extractable: true,
                    algorithm: algoName,
                    keyUsage: keyUsages,
                    key: {
                        n: bareKey.n,
                        e: bareKey.e
                    }
                };
                keyPair.privateKey = {
                    type: 'private',
                    extractable: extractable,
                    algorithm: algoName,
                    keyUsage: keyUsages,
                    key: bareKey
                };
                keyPair.publicKey = libpolycrypt.wrap_key(this.apiKey, keyPair.publicKey);
                keyPair.privateKey = libpolycrypt.wrap_key(this.apiKey, keyPair.privateKey);
                this.complete(keyPair);
                break;

            case "HMAC":
                if (!algorithm.params || !algorithm.params.hasOwnProperty('length')) {
                    this.die('Key length must be provided');
                    return;
                }
                var length = algorithm.params.length;
                type = "secret";
                bareKey = libpolycrypt.random(length >> 3);
                var key = {
                    type: type,
                    extractable: extractable,
                    algorithm: algoName,
                    keyUsage: keyUsages,
                    key: bareKey,
                };
                key = libpolycrypt.wrap_key(this.apiKey, key);
                this.complete(key);
                break;

            default:
                this.die("Unknkown algorithm: " + algorithm);
        }
       
        // XXX-SPEC: The spec is inconsistent between keyUsage[s]
        // XXX-SPEC: Algorithm comes in with KeyGenParams; what should go out?
    },

});
