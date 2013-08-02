/*global self, Uint32Array */

// CryptoJS requirements
importScripts('./lib/CryptoJS/core-min.js');
importScripts('./lib/CryptoJS/cipher-core-min.js');
importScripts('./lib/CryptoJS/aes-min.js');
importScripts('./lib/CryptoJS/pad-nopadding-min.js');
importScripts('./lib/CryptoJS/mode-ctr-min.js');
importScripts('./lib/gcm.js');
// jsbn requirements
importScripts('./lib/jsbn.js');
importScripts('./lib/jsbn2.js');
importScripts('./lib/prng4.js');
importScripts('./lib/rng.js');
importScripts('./lib/rsa.js');
importScripts('./lib/rsa2.js');
// Crypto glue
importScripts('./libpolycrypt.js');

Impl.extend({
    key: null,
    algorithm: null,
    buffer: null,

    create: function worker_encrypt_create(args) {
        console.log("Entered worker_encrypt_create");
        'use strict';
        
        // Verify and cache parameters
        this.key = args['key'];
        this.algorithm = args['algorithm'];
        
        if (!this.key) { 
            this.die('Key must be provided');
            // TODO: Die
            return;
        } else if (!this.algorithm) {
            this.die('Algorithm must be provided');
            // TODO: Die
            return;
        } 

        var algoName = this.algoName(this.algorithm);
        
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
           (this.key.keyUsage.indexOf("encrypt") === -1)) {
            // XXX: Should do full algorithm comparison?
            this.die('Encryption usage not supported for this key');
            return;
        }

        // Unwrap the key
        this.key = libpolycrypt.unwrap_key(this.apiKey, this.key);

        // Algorithm-specific checks
        switch (algoName) {
            case 'AES-CBC':
            case 'AES-CTR':
                // Key type
                if (this.key.type !== 'secret') {
                    this.die('Key must be a secret / symmetric key');
                }
                // Required fields
                if (!this.algorithm.hasOwnProperty('params')) {
                    this.die('Algorithm parameters missing');
                    return;
                }
                if (!this.algorithm.params.hasOwnProperty('iv')) {
                    this.die('IV must be provided');
                    return;
                }
                break;
                

            case 'AES-GCM':
                // Key type
                if (this.key.type !== 'secret') {
                    this.die('Key must be a secret / symmetric key');
                }
                // Required fields
                if (!this.algorithm.hasOwnProperty('params')) {
                    this.die('Algorithm parameters missing');
                    return;
                }
                if (!this.algorithm.params.hasOwnProperty('iv')) {
                    this.die('IV must be provided');
                    return;
                }
                // Default values
                if (!this.algorithm.params.hasOwnProperty('additionalData')) {
                    this.algorithm['additionalData'] = new Uint8Array(0);
                }
                if (!this.algorithm.params.hasOwnProperty('tagLength')) {
                    // XXX-SPEC: This should be 128, per RFC 5116
                    this.algorithm['tagLength'] = 0;
                }
                break;

            case 'AES-KW':
                if (this.key.type !== 'secret') {
                    this.die('Key must be a secret / symmetric key');
                }
                break;

            case 'RSAES-PKCS1-v1_5':
                // Need to have public key fields
                if (!this.key.key.hasOwnProperty('n') || !this.key.key.hasOwnProperty('e')) {
                    this.die('Key must be have RSA public key fields (n, e)');
                    return;
                }
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
        var ct;

        var algoName = this.algoName(this.algorithm);
        switch (algoName) {
            case 'AES-CBC':
                ct = libpolycrypt.encrypt_AES_CBC(
                    this.key.key, 
                    this.algorithm.params.iv, 
                    data);
                break;

            case 'AES-CTR':
                ct = libpolycrypt.encrypt_AES_CTR(
                    this.key.key,
                    this.algorithm.params.iv,
                    data);
                break

            case 'AES-GCM':
                var CT = libpolycrypt.encrypt_AES_GCM(
                    this.key.key,
                    this.algorithm.params.iv,
                    data,
                    this.algorithm.params.additionalData,
                    this.algorithm.params.tagLength
                );
                ct = util.abvcat(CT.C, CT.T);
                break;

            case 'AES-KW':
                ct = libpolycrypt.aes_key_wrap(
                    this.key.key,
                    data);
                break;

            case 'RSAES-PKCS1-v1_5':
                ct = libpolycrypt.rsa_pkcs1_key_wrap(
                    util.hex2abv(this.key.key.n),
                    util.hex2abv(this.key.key.e),
                    data
                );
                break;
        }

        this.complete(ct);
    },

    abort: function abort(args) {
        // TODO
    },

});
