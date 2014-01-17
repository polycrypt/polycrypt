/*global self, Uint32Array */

// CryptoJS requirements
importScripts('./lib/CryptoJS/core-min.js');
importScripts('./lib/CryptoJS/sha1-min.js');
importScripts('./lib/CryptoJS/sha256-min.js');
importScripts('./lib/CryptoJS/sha384-min.js');
importScripts('./lib/CryptoJS/sha512-min.js');
// Crypto glue
importScripts('./libpolycrypt.js');

Impl.extend({
    algorithm: null,
    buffer: null,

    create: function worker_digest_create(args) {
        console.log("Entered worker_digest_create");
        'use strict';
        
        // Verify and cache parameters
        this.algorithm = args['algorithm'];
        var algoName = this.algoName(this.algorithm);
        
        if (!this.algorithm) {
            this.die('Algorithm must be provided');
            // TODO: Die
            return;
        } 

        // Algorithm-specific checks
        switch (algoName) {
            case 'SHA-1':
            case 'SHA-256':
                // No checks needed; just checking that the algo is supported
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
        var digest;

        var algoName = this.algoName(this.algorithm);
        switch (algoName) {
            case 'SHA-1':
                digest = libpolycrypt.sha1(data);
                break;
            case 'SHA-256':
                digest = libpolycrypt.sha256(data);
            case 'SHA-384':
                digest = libpolycrypt.sha384(data);
            case 'SHA-512':
                digest = libpolycrypt.sha512(data);
        }

        this.complete(digest);
    },

    abort: function abort(args) {
        // TODO
    },

});
