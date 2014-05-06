/*global util:false, CryptoJS:false, sjcl:false RSAKey:false, AESGCM:false */
/*
 * PolyCrypt Crypto Library
 *
 * This library provides an abstraction layer over many crypto primitives
 * that are implemented in different ways in different libraries.  All of
 * the primitives use ArrayBufferViews as a common interface.
 *
 * See 'src/util.js' for functions to convert to and from ArrayBufferViews
 */

var libpolycrypt = {

    random: function libpolycrypt_random(bytes) {
        return util.wa2abv( CryptoJS.lib.WordArray.random(bytes) );
    },

    aes: function libpolycrypt_aes(key) {
        // CryptoJS implementation
        return {
            _impl: CryptoJS.algo.AES.createEncryptor(util.abv2wa(key)),
            encrypt: function aes_encrypt(x) {
                var xw = util.abv2wa(x);
                this._impl.encryptBlock(xw.words, 0);
                return util.wa2abv(xw);
            },
            decrypt: function aes_decrypt(x) {
                var xw = util.abv2wa(x);
                this._impl.decryptBlock(xw.words, 0);
                return util.wa2abv(xw);
            },
        };
    },

    rsa_generate: function libpolycrypt_rsa_generate(bits, e) {
        var rsa = new RSAKey();
        rsa.generate(bits, e);
        return rsa;
    },

    aes_key_wrap: function libpolycrypt_aes_key_wrap(key, p_in) {
        var b, dv;
        var p = new Uint8Array(8* Math.ceil( p_in.byteLength * 1.0 / 8 ));
        p.set(new Uint8Array(p_in.buffer), 0);
        var a = new Uint32Array([0xA6A6A6A6, 0xA6A6A6A6]);
        if (p_in.byteLength % 8 !== 0) {
            a = new Uint32Array([0xA65959A6, 0x00000000]);
            dv = new DataView(a.buffer);
            dv.setUint32( 4, p_in.byteLength, false );
        }

        var n = p.byteLength / 8;
        var r = new Uint32Array(2 * (n+1));
        r.set( [0x00000000, 0x00000000], 0 );
        r.set( new Uint32Array(p.buffer), 2 );

        var aes = this.aes(key);
        for (var j=0; j<6; ++j) {
            for (var i=1; i<n+1; i++) {
                var ar = new Uint32Array(4);
                ar.set(a, 0);
                ar.set(r.subarray(2*i, 2*i + 2), 2);
                b = aes.encrypt(ar);
                b = new Uint32Array(b.buffer);
                a.set(b.subarray(0,2));
                r.set(b.subarray(2,4), 2*i);
                // Use a DataView to explicitly control endianness
                dv = new DataView(a.buffer);
                var a1 = dv.getUint32(4, false);
                dv.setUint32(4, a1 ^ ((n*j) + i), false);
            }
        }

        r.set( a, 0 );
        return r;
    },

    aes_key_unwrap: function libpolycrypt_aes_key_unwrap(key, c) {
        util.assert( c.byteLength % 8 === 0 );

        var a, r8;
        var cv = new Uint32Array(c.buffer);
        var n = c.byteLength / 8 - 1;
        var r = new Uint32Array(2 * (n+1));
        r.set( cv );
        r.set( [0, 0], 0 );
        a = new Uint32Array(2);
        a.set( cv.subarray(0,2) );

        var aes = this.aes(key);
        for (var j=5; j>-1; j--) {
            for (var i=n; i>0; i--) {
                // Use a DataView to explicitly control endianness
                var dv = new DataView(a.buffer);
                var a1 = dv.getUint32(4, false);
                dv.setUint32(4, a1 ^ ((n*j) + i), false);
                var ar = new Uint32Array(4);
                ar.set(a, 0);
                ar.set(r.subarray(2*i, 2*i + 2), 2);
                b = aes.decrypt(ar);
                b = new Uint32Array(b.buffer);
                a.set(b.subarray(0,2));
                r.set(b.subarray(2,4), 2*i);
            }
        }

        if ((a[0] === 0xa6a6a6a6) && (a[1] === 0xa6a6a6a6)) {
            return new Uint32Array(r.subarray(2));
        } else if (a[0] === 0xa65959a6) {
            var mli = (new DataView(a.buffer)).getUint32(4, false);
            var b = 8*n - mli;
            r8 = new Uint8Array(r.buffer, r.byteOffset, r.byteLength);
            var allzero = true;
            for (var i=r8.byteLength - b; i<r8.byteLength-1; ++i) {
                allzero = (r8[i] === 0x00);
            }
            if ((b >= 0) && (b < 8) && allzero) {
                return new Uint8Array(r8.subarray(8,r8.length-b));
            } else {
                throw "Key unwrap padding check failed";
            }
        } else {
            throw "Key unwrap integrity check failed";
        }
    },

    // Key format is as specified, plus 'key' field
    // For symmetric, key is an ArrayBufferView, with the value of the key
    // For asymmetric, key is object with appropriate fields
    wrap_key: function libpolycrypt_wrap_key(kek, key) {
        var wrap = key;
        if (!key.hasOwnProperty("key")) {
            return key;
        }

        var bareKey = key.key;
        if ((key.type !== "secret") && (typeof(key.key) === "object")) {
            // JSON.stringify -> str2abv -> key wrap
            bareKey = util.str2abv(JSON.stringify(key.key));
        }
        var wrappedKey = this.aes_key_wrap(kek, bareKey);
        wrap.key = util.abv2hex(wrappedKey);

        return wrap;
    },

    unwrap_key: function libpolycrypt_wrap_key(kek, key) {
        var unwrap = key;
        if (!key.hasOwnProperty("key")) {
            return key;
        }

        var wrappedKey = util.hex2abv(key.key);
        var bareKey = this.aes_key_unwrap(kek, wrappedKey);
        if (key.type !== "secret") {
            bareKey = JSON.parse(util.abv2str(bareKey));
        }
        unwrap.key = bareKey;

        return unwrap;
    },

    sha1: function libpolycrypt_sha1(data) {
        // CryptoJS implementation
        var sha1 = CryptoJS.algo.SHA1.create();
        sha1.update(util.abv2wa(data));
        var hash = sha1.finalize();
        return util.wa2abv(hash);
    },

    sha256: function libpolycrypt_sha256(data) {
        // CryptoJS implementation
        var sha256 = CryptoJS.algo.SHA256.create();
        sha256.update(util.abv2wa(data));
        var hash = sha256.finalize();
        return util.wa2abv(hash);
    },

    hmac_sha1: function libpolycrypt_hmac_sha1(key, data) {
        // CryptJS implementation
        var hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA1, util.abv2wa(key));
        hmac.update(util.abv2wa(data));
        var hash = hmac.finalize();
        return util.wa2abv(hash);
    },

    hmac_sha256: function libpolycrypt_hmac_sha256(key, data) {
        // CryptJS implementation
        var hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, util.abv2wa(key));
        hmac.update(util.abv2wa(data));
        var hash = hmac.finalize();
        return util.wa2abv(hash);
    },

    encrypt_AES_GCM: function libpolycrypt_encrypt_AES_GCM(key, iv, data, adata, tlen) {
        tlen = tlen || 128;
        var ct = AESGCM.encrypt_AES_GCM(key, iv, data, adata, tlen);
        return {
            C: ct[0],
            T: ct[1]
        };
    },

    decrypt_AES_GCM: function libpolycrypt_decrypt_AES_GCM(key, iv, data, adata, tag) {
        return AESGCM.decrypt_AES_GCM(key, iv, data, adata, tag);
    },

    encrypt_AES128CCM: function libpolycrypt_encrypt_AES128CCM(key, nonce, tlen, data, adata) {
        // Convert everything to bitArrays
        var key_ba   = util.abv2ba(key);
        var nonce_ba = util.abv2ba(nonce);
        var data_ba  = util.abv2ba(data);
        var adata_ba = util.abv2ba(adata);
        // SJCL counts tag length in bits; we count in octets, as the RFC does
        var tlen_bits = 8*tlen;
        
        var prf = new sjcl.cipher.aes(key_ba);
        var ct = sjcl.mode.ccm.encrypt(prf, data_ba, nonce_ba, adata_ba, tlen_bits);
        return util.ba2abv(ct);
    },

    decrypt_AES128CCM: function libpolycrypt_encrypt_AES128CCM(key, nonce, tlen, data, adata) {
        // Convert everything to bitArrays
        var key_ba   = util.abv2ba(key);
        var nonce_ba = util.abv2ba(nonce);
        var data_ba  = util.abv2ba(data);
        var adata_ba = util.abv2ba(adata);
        // SJCL counts tag length in bits; we count in octets, as the RFC does
        var tlen_bits = 8*tlen;
        
        var prf = new sjcl.cipher.aes(key_ba);
        var ct = sjcl.mode.ccm.decrypt(prf, data_ba, nonce_ba, adata_ba, tlen_bits);
        return util.ba2abv(ct);
    },

    encrypt_AES_CBC: function libpolycrypt_encrypt_AES_CBC(key, iv, data) {
        // Convert everything to word arrays
        var key_wa  = util.abv2wa(key);
        var iv_wa   = util.abv2wa(iv);
        var data_wa = util.abv2wa(data);

        var ct_enc = CryptoJS.AES.encrypt(data_wa, key_wa,
            { iv: iv_wa, mode: CryptoJS.mode.CBC });
        return util.wa2abv(ct_enc.ciphertext);
    },
    
    decrypt_AES_CBC: function libpolycrypt_decrypt_AES_CBC(key, iv, data) {
        // Convert everything to word arrays
        var key_wa  = util.abv2wa(key);
        var iv_wa   = util.abv2wa(iv);
        // CryptoJS insists on this wrapping
        var ct_enc = { ciphertext: util.abv2wa(data) };

        var pt = CryptoJS.AES.decrypt(ct_enc, key_wa,
            { iv: iv_wa, mode: CryptoJS.mode.CBC });
        return util.wa2abv(pt);
    },
    
    encrypt_AES_CTR: function libpolycrypt_encrypt_AES_CTR(key, iv, data) {
        // Convert everything to word arrays
        var key_wa  = util.abv2wa(key);
        var iv_wa   = util.abv2wa(iv);
        var data_wa = util.abv2wa(data);

        var ct_enc = CryptoJS.AES.encrypt(data_wa, key_wa,
            { iv: iv_wa, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding });
        return util.wa2abv(ct_enc.ciphertext);
    },
    
    decrypt_AES_CTR: function libpolycrypt_decrypt_AES_CTR(key, iv, data) {
        // Convert everything to word arrays
        var key_wa  = util.abv2wa(key);
        var iv_wa   = util.abv2wa(iv);
        // CryptoJS insists on this wrapping
        var ct_enc = { ciphertext: util.abv2wa(data) };

        var pt = CryptoJS.AES.decrypt(ct_enc, key_wa,
            { iv: iv_wa, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding });
        return util.wa2abv(pt);
    },

    rsa_pkcs1_key_wrap: function libpolycrypt_rsa_pkcs1_key_wrap(n, e, p) {
        // Convert everything to hex strings
        var n_s = util.abv2hex(n);
        var e_s = util.abv2hex(e);
        var p_s = util.abv2hex(p);

        var k = new RSAKey();
        k.setPublic(n_s, e_s);
        var c_s = k.encrypt(p_s);
        return util.hex2abv(c_s);
    },
    
    rsa_pkcs1_key_unwrap: function libpolycrypt_rsa_pkcs1_key_unwrap(n, e, d, c) {
        // Convert everything to hex strings
        var n_s = util.abv2hex(n);
        var e_s = util.abv2hex(e);
        var d_s = util.abv2hex(d);
        var c_s = util.abv2hex(c);

        var k = new RSAKey();
        k.setPrivate(n_s, e_s, d_s);
        var p_s = k.decrypt(c_s);
        return util.hex2abv(p_s);
    },

    sign_pkcs1_sha1: function libpolycrypt_sign_pkcs1_sha1(n, e, d, content) {
        // Convert everything to hex strings
        var n_s = util.abv2hex(n);
        var e_s = util.abv2hex(e);
        var d_s = util.abv2hex(d);
        var content_w = util.abv2wa(content);
        
        var k = new RSAKey();
        k.setPrivate(n_s, e_s, d_s);
        var sig_s = k.sign(content_w, 'sha1');
        return util.hex2abv(sig_s);
    },

    sign_pkcs1_sha256: function libpolycrypt_sign_pkcs1_sha256(n, e, d, content) {
        // Convert everything to hex strings
        var n_s = util.abv2hex(n);
        var e_s = util.abv2hex(e);
        var d_s = util.abv2hex(d);
        var content_w = util.abv2wa(content);
        
        var k = new RSAKey();
        k.setPrivate(n_s, e_s, d_s);
        var sig_s = k.sign(content_w, 'sha256');
        return util.hex2abv(sig_s);
    },

    verify_pkcs1: function libpolycrypt_sign_pkcs1_sha1(n, e, content, sig) {
        // Convert everything to hex strings
        var n_s = util.abv2hex(n);
        var e_s = util.abv2hex(e);
        var sig_s = util.abv2hex(sig);
        var content_w = util.abv2wa(content);
        
        var k = new RSAKey();
        k.setPublic(n_s, e_s);
        return k.verify(content_w, sig_s);
    },

    pbkdf2_sha1: function libpolycrypt_pbkdf2_sha1(password, salt, iter, bytes) {
        // Convert everything to word arrays
        var password_wa = util.abv2wa(password);
        var salt_wa = util.abv2wa(salt);

        var key = CryptoJS.PBKDF2(password_wa, salt_wa,
            {
                keySize: bytes/4,
                iterations: iter,
                hasher: CryptoJS.algo.SHA1,
            });
        return util.wa2abv(key);
    },

    pbkdf2_sha256: function libpolycrypt_pbkdf2_sha256(password, salt, iter, bytes) {
        // Convert everything to word arrays
        var password_wa = util.abv2wa(password);
        var salt_wa = util.abv2wa(salt);

        var key = CryptoJS.PBKDF2(password_wa, salt_wa,
            {
                keySize: bytes/4,
                iterations: iter,
                hasher: CryptoJS.algo.SHA256,
            });
        return util.wa2abv(key);
    },
};
