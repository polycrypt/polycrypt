// Ad-hoc implementation of AES-GCM
// Requires CryptoJS for AES primitive (also typed arrays)

var AESGCM = {
    _gf128_mult: function AESGCM_gf128_mult(X, Y) {
        var R = new Uint8Array([0xe1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
        var Z = new Uint8Array(16);
        var V = new Uint8Array(Y);
    
        for (var i=0; i<128; ++i) {
            if ((X[(i>>3)] & (1 << (7-i%8))) > 0) {
                for (var j=0; j<16; ++j) { Z[j] ^= V[j]; } 
            }
    
            var lsbV = V[15] % 2;
            for (var j=15; j>0; --j) { V[j] = (V[j] >> 1) + ((V[j-1] % 2) << 7); }
            V[0] >>= 1;
            if (lsbV == 1) {
                for (var j=0; j<16; ++j) { V[j] ^= R[j]; } 
            }
        }
    
        return Z;
    },

    _GHASH: function AESGCM_GHASH(H, A, C) {
        // Concatenate the two strings with their lengths
        var la = A.byteLength, lc = C.byteLength;
        var ab = Math.ceil(la/16), cb = Math.ceil(lc/16);
        var lab = 16*ab, lcb = 16*cb;
        var X = new Uint8Array(lab + lcb + 16);
        X.set(A, 0);
        X.set(C, lab);
        var dv = new DataView(X.buffer);
        dv.setUint32( X.byteLength - 12, 8*la, false );
        dv.setUint32( X.byteLength -  4, 8*lc, false );
    
        // Compute the hash over the whole string
        var m = X.byteLength / 16;
        var Y = new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
        for (var i=0; i<m; ++i) {
            for (var j=0; j<16; ++j) { Y[j] ^= X[16*i + j]; } 
            Y = this._gf128_mult(Y, H);
        }
        return Y;
    },

    _inc32: function AESGCM_inc32(x) {
        var i = x.byteLength - 1;
        while (x[i] == 0xff && i >= 12) { 
            x[i--] = 0x00; 
        }
        if (i >= 12) { x[i] += 1; }
        return x;
    },
    
    _aes_encryptor: function AESGCM_aes_encryptor(key) {
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
    
    _GCM_params: function AESGCM_GCM_params(K, IV) {
        var aes = this._aes_encryptor(K);
        // 1. H = AES(K, 0)
        var zero = new Uint8Array(16);
        var H = aes.encrypt(zero);
    
        // 2. Compute Y0 from IV
        var Y0;
        if (IV.byteLength == 12) {
            // Y0 == IV || 1
            var Y0 = new Uint8Array(16);
            Y0.set(IV, 0);
            Y0[15] = 1;
        } else {
            Y0 = this._GHASH(H, new Uint8Array(0), IV);
        }
        var EY0 = aes.encrypt(Y0);
    
        return {
            H: H,
            Y0: Y0,
            EY0: EY0
        };
    },
    
    _GCTR: function AESGCM_GCTR(K, Y0, P) {
        var aes = this._aes_encryptor(K);
        var C = new Uint8Array(P.byteLength);
        var Y = Y0, EY_wa, EY = new Uint8Array(16);
        for (var i=0; i<P.byteLength; i++) {
            if (i % 16 == 0) {
                Y = this._inc32(Y);
                EY = aes.encrypt(Y);
            }
            C[i] = P[i] ^ EY[i % 16];
        }
        return C;
    },
    
    encrypt_AES_GCM: function AESGCM_encrypt_AES_GCM(K, IV, P, A, tlen) {
        /***** PHASE 1: Parameter generation *****/
        var p = this._GCM_params(K, IV);
    
        /***** PHASE 2: Encryption *****/
        // Could also update the hash along the way here
        var C = this._GCTR(K, p.Y0, P);
    
        /***** PHASE 3: Compute authentication tag *****/
        var S = this._GHASH(p.H, A, C);
        for (var i=0; i<16; ++i) { S[i] ^= p.EY0[i]; }
        var T = new Uint8Array(S.subarray(0, tlen>>3));
    
        return [C, T];
    },
    
    decrypt_AES_GCM: function AESGCM_decrypt_AES_GCM(K, IV, C, A, T) {
        /***** PHASE 1: Parameter generation *****/
        var p = this._GCM_params(K, IV);
        
        /***** PHASE 2: Compute authentication tag *****/
        var Tp = this._GHASH(p.H, A, C);
        for (var i=0; i<16; ++i) { Tp[i] ^= p.EY0[i]; }
        var memcmp = true;
        for (var i=0; i<T.byteLength && memcmp; ++i) { memcmp = (T[i] == Tp[i]); }
        if (!memcmp) { throw "AES-GCM integrity check failed"; }
    
        /***** PHASE 3: Decryption *****/
        return this._GCTR(K, p.Y0, C);
    },
};

