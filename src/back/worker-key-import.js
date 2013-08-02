/*global self, Uint32Array */

// CryptoJS requirements
importScripts('./lib/CryptoJS/core-min.js');
importScripts('./lib/CryptoJS/cipher-core-min.js');
importScripts('./lib/CryptoJS/aes-min.js');
// Crypto glue
importScripts('./libpolycrypt.js');

Impl.extend({

    import: function worker_import(args) {
        'use strict';

        var format = args['format'] || null;
        var keyData = args['keyData'] || null;
        var algorithm = args['algorithm'] || null;
        var keyUsages = args['keyUsages'] || [];
        var extractable = args['extractable'];
        if (!args.hasOwnProperty('extractable') || 
            (typeof(args.extractable) != 'boolean')) {
            extractable = false;
        }
        
        if ((format !== 'raw')&&(format !== 'jwk')) {
            this.die('Only raw key and jwk import supported');
            return;
        }

        var type;
        var algoName = this.algoName(algorithm);
        switch (algoName) {
            // Raw symmetric key
            case null:
                // XXX-SPEC: Assuming that this is symmetric?
            case "AES-CTR":
            case "AES-CBC":
            case "AES-GCM":
            case "AES-KW":
            case "HMAC":
                if (format !== 'raw') {
                    this.die('Only raw key supported for algorithm ' + algoName);
                    return;
                }
                type = "secret";
                break;

            case "RSASSA-PKCS1-v1_5":
            case "RSAES-PKCS1-v1_5":
                if (format !== 'jwk') {
                    this.die('Only jwk key supported for algorithm ' + algoName);
                    return;
                }
                if ((typeof(keyData) !== 'object') ||
                    (!keyData.hasOwnProperty('n')) ||
                    (!keyData.hasOwnProperty('e'))) {
                    this.die('Malformed JWK');
                    return;
                }
                var rsa = {
                    n: util.abv2hex(util.b64decode(keyData['n'])),
                    e: util.abv2hex(util.b64decode(keyData['e'])),
                };
                if (keyData.hasOwnProperty('d')) {
                    rsa.d = util.abv2hex(util.b64decode(keyData['d']));
                }
                keyData = rsa;
                type = (keyData.hasOwnProperty('d'))? 'private' : 'public'; 
                break;

            default:
                this.die("Unsupported algorithm: " + algoName);
                return;
        }
       
        // XXX-SPEC: The spec is inconsistent between keyUsage[s]
        // XXX-SPEC: Should the policy fields be optional? (extractable / keyUsage / algorithm)
        var key = { 
            type: type, 
            key: keyData,
            algorithm: algorithm,
            extractable: extractable,
            keyUsage: keyUsages,
        };
        key = libpolycrypt.wrap_key(this.apiKey, key);
        this.complete(key);
    },

});
