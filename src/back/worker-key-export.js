/*global self, Uint32Array */

// CryptoJS requirements
importScripts('./lib/CryptoJS/core-min.js');
importScripts('./lib/CryptoJS/cipher-core-min.js');
importScripts('./lib/CryptoJS/aes-min.js');
// Crypto glue
importScripts('./libpolycrypt.js');

Impl.extend({

    export: function worker_export(args) {
        console.log("Entered worker_export");
        'use strict';

        var format = args['format'] || null;
        var key = args['key'] || null;
      
        console.log(JSON.stringify(args));

        if (!key) {
            this.die('You must provide a key to export');
            return;
        }

        if ((format !== 'raw')&&(format !== 'jwk')) {
            this.die('Only raw key and jwk export supported');
            return;
        }

        if (('exportable' in key)&&(key.exportable === false)) {
            this.die('Attempt to export a non-exportable key');
            return;
        }

        // Unwrap the key
        var rawKey = libpolycrypt.unwrap_key(this.apiKey, key);

        var algoName = this.algoName(key.algorithm);
        switch (algoName) {
            // Raw symmetric key
            case null:
                // XXX-SPEC: Assuming that this is symmetric?
            case "AES-CTR":
            case "AES-CBC":
            case "AES-GCM":
            case "HMAC":
                if (format === 'raw') {
                    this.complete(rawKey.key);
                } else {
                    this.die('Only raw key supported for algorithm ' + algoName);
                    return;
                }
                
                break;

            case "RSASSA-PKCS1-v1_5":
            case "RSAES-PKCS1-v1_5":
                if (format !== 'jwk') {
                    this.die('Only jwk key supported for algorithm ' + algoName);
                    return;
                }
                var jwk = {};
                for (var ix in rawKey.key) {
                    jwk[ix] = util.b64encode(util.hex2abv(rawKey.key[ix]));
                }
                this.complete(jwk);
                break;

            default:
                this.die("Unsupported algorithm: " + algoName);
                return;
        }
    },

});
