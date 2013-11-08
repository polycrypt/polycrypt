/*global self, Uint32Array */

// CryptoJS requirements
importScripts('./lib/CryptoJS/core-min.js');
importScripts('./lib/CryptoJS/cipher-core-min.js');
importScripts('./lib/CryptoJS/aes-min.js');
importScripts('./lib/CryptoJS/sha1-min.js');
importScripts('./lib/CryptoJS/sha256-min.js');
importScripts('./lib/CryptoJS/hmac-min.js');
importScripts('./lib/CryptoJS/pbkdf2-min.js');
// Crypto glue
importScripts('./libpolycrypt.js');

Impl.extend({

    derive: function derive(args) {
        'use strict';

        var algorithm = args['algorithm'] || null;
        var baseKey = args['baseKey'] || null;
        var derivedKeyType = args['derivedKeyType'] || null;
        var extractable = args['extractable'];
        var keyUsages = args['keyUsages'] || [];
        
        if (!args.hasOwnProperty('extractable') || 
            (typeof(args.extractable) != 'boolean')) {
            extractable = false;
        }
       
        if (!algorithm) {
            this.die("Algorithm must be provided");
            return;
        }
        if (!baseKey) {
            this.die("Base Key must be provided");
            return
        }
        // XXX-SPEC: We have overloading here.  No way to specify length wihtout setting algorithm
        // XXX-SPEC: Just put in Pbkdf2Params
        if (!derivedKeyType) {
            this.die("Algorithm for derived key must be provided");
        }

        if (baseKey.type !== 'secret') {
            this.die('Base key must be secret');
            return;
        }

        // Unwrap the base key
        var rawKey = libpolycrypt.unwrap_key(this.apiKey, baseKey);

        // Figure out how long a key we need to make
        var keyLength = 0;
        var derivedAlgoName = this.algoName(derivedKeyType);
        switch (derivedAlgoName) {
            case "AES-CBC":
            case "AES-CTR":
            case "AES-GCM":
            case "HMAC":
                if (!derivedKeyType.length) {
                    this.die('Derived algorithm name must provide key length');
                    return;
                }
                keyLength = derivedKeyType.length;
                break;

            default:
                this.die("Unable to derive key for derived algorithm " + derivedAlgoName);
                return;
        }


        var keyData;
        var algoName = this.algoName(algorithm);
        switch (algoName) {
            case "PBKDF2":
                // Check required fields
                if (!algorithm.hasOwnProperty('salt') ||
                    !algorithm.hasOwnProperty('iterations') ||
                    !algorithm.hasOwnProperty('prf')) {
                    this.die("PBKDF2 parameters must be provided");
                    return;
                }
                var prf = this.algoName(algorithm.prf);
                // Do the computation
                if (prf === "SHA-1") {
                    keyData = libpolycrypt.pbkdf2_sha1(
                        rawKey.key,
                        algorithm.salt,
                        algorithm.iterations,
                        keyLength >> 3
                    );
                } else if (prf === "SHA-256") {
                    keyData = libpolycrypt.pbkdf2_sha256(
                        rawKey.key,
                        algorithm.salt,
                        algorithm.iterations,
                        keyLength >> 3
                    );
                } else {
                    this.die("Unsupported PRF: " + prf);
                }
                break;

            default:
                this.die("Unsupported algorithm: " + algorithm);
                return;
        }
       
        // XXX-SPEC: The spec is inconsistent between keyUsage[s]
        // XXX-SPEC: Should the policy fields be optional? (extractable / keyUsage / algorithm)
        var key = { 
            type: "secret", 
            key: keyData,
            algorithm: derivedKeyType,
            extractable: extractable,
            keyUsage: keyUsages,
        };
        key = libpolycrypt.wrap_key(this.apiKey, key);
        this.complete(key);
    },

});
