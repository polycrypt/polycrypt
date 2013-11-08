/*global self, Uint32Array */

// CryptoJS requirements
importScripts('./lib/CryptoJS/core-min.js');
importScripts('./lib/CryptoJS/cipher-core-min.js');
importScripts('./lib/CryptoJS/aes-min.js');
importScripts('./lib/CryptoJS/sha1-min.js');
importScripts('./lib/CryptoJS/sha256-min.js');
importScripts('./lib/CryptoJS/hmac-min.js');
// jsbn requirements
importScripts('./lib/jsbn.js');
importScripts('./lib/jsbn2.js');
importScripts('./lib/prng4.js');
importScripts('./lib/rng.js');
importScripts('./lib/rsa.js');
importScripts('./lib/rsa2.js');
importScripts('./lib/rsasign-1.2.js');
// Crypto glue
importScripts('./libpolycrypt.js');

Impl.extend({
    key: null,
    algorithm: null,
    buffer: null,

    create: function worker_verify_create(args) {
        console.log("entered worker_verify_create");
        'use strict';
        
        // Verify and cache parameters
        this.key = args['key'];
        this.algorithm = args['algorithm'];
        this.signature = args['signature'];
        var algoName = this.algoName(this.algorithm);
        
        if (!this.key) { 
            this.die('Key must be provided');
            return;
        } else if (!this.algorithm) {
            this.die('Algorithm must be provided');
            return;
        } else if (!this.signature) {
            this.die('Signature must be provided');
            return;
        }
        
        // Check that we have permission to use this key with this algorithm
        if (this.key.hasOwnProperty('algorithm') &&
           (this.key.algorithm !== null) && 
           (this.key.algorithm !== algoName)) {
            // XXX: Should do full algorithm comparison?
            this.die('Algorithm not supported for this key');
            return;
        }

        // Check that we have permission to use this key for this purpose
        if (this.key.hasOwnProperty('keyUsage') &&
           (this.key.keyUsage.length > 0) &&
           (this.key.keyUsage.indexOf("verify") === -1)) {
            // XXX: Should do full algorithm comparison?
            this.die('Verify usage not supported for this key');
            return;
        }

        // Unwrap the key
        this.key = libpolycrypt.unwrap_key(this.apiKey, this.key);

        // Algorithm-specific checks
        switch (algoName) {
            case 'HMAC':
                // Key type
                if (this.key.type !== 'secret') {
                    this.die('Key must be a secret / symmetric key');
                }
                // Need to use a supported hash algorithm
                if (!this.algorithm.hasOwnProperty('hash')) {
                    this.die('HMAC algorithm parameters must specify a hash function');
                    return;
                }
                switch (this.algorithm.hash) {
                    case 'SHA-1':
                    case 'SHA-256':
                        break;
                    default:
                        this.die('Unsupported hash algorithm ' + this.algorithm.hash);
                }
                break;

            case 'RSASSA-PKCS1-v1_5':
                // Need to have public key fields 
                if (!this.key.key.hasOwnProperty('n') || !this.key.key.hasOwnProperty('e')) {
                    this.die('Key must have RSA public fields (n, e)');
                    return
                }
                // No other parameters needed; hash is under the signature (in DER)

                break;
            
            default:
                this.die('Unsupported algorithm: '+algoName);
                return;
        }

        // We made it this far; we're alive
        this.alive = true;

        // If there is data, process it and finish
        this.buffer = "";
        if (('buffer' in args) && util.isABV(args['buffer']) 
             && (args['buffer'].byteLength > 0)) {
            this.process(args);
            this.finish();
        }
    },

    process: function process(args) {
        if (!this.alive) { return; }
        if ('buffer' in args) {
            this.buffer += util.abv2hex(args['buffer']);
        }
    },

    finish: function finish(args) {
        if (!this.alive) { return; }

        // Takes no arguments
        var data = util.hex2abv(this.buffer);
        var ver = false;

        var algoName = this.algoName(this.algorithm);
        switch (algoName) {
            case 'HMAC':
                var hash;
                switch (this.algorithm.hash) {
                    case 'SHA-1':
                        hash = libpolycrypt.hmac_sha1(this.key.key, data);
                        break;

                    case 'SHA-256':
                        hash = libpolycrypt.hmac_sha256(this.key.key, data);
                        break;
                }
                ver = (hash == this.signature);
                break;

            case 'RSASSA-PKCS1-v1_5':
                ver = libpolycrypt.verify_pkcs1(
                    util.hex2abv(this.key.key.n),
                    util.hex2abv(this.key.key.e),
                    data,
                    this.signature
                );
                break;
        }

        this.complete(ver);
    },

    abort: function abort(args) {
        // TODO
    },

});
